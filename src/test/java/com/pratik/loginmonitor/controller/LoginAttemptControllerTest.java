package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.dto.LoginRequest;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.LoginRateLimiter;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAttemptControllerTest {

    @Mock
    private LoginService loginService;

    @Mock
    private LoginRateLimiter loginRateLimiter;

    @Mock
    private CaptchaService captchaService;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @InjectMocks
    private LoginAttemptController loginAttemptController;

    @Test
    @DisplayName("Should return 200 OK and list of login attempts from service")
    void testGetLoginAttempts_returnsList() {
        LoginAttempt a1 = new LoginAttempt(1L, "john", "192.168.1.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS))
                .thenReturn(List.of(a1));

        ResponseEntity<List<LoginAttempt>> response = loginAttemptController.getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        verify(loginService).getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS);
        verifyNoInteractions(loginRateLimiter, captchaService, clientIpAddressExtractor);
    }

    @Test
    @DisplayName("Should return 429 Too Many Requests and not call LoginService when the IP is blocked")
    void testPostLoginAttempt_returnsTooManyRequestsWithoutSaving() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.1");
        when(loginRateLimiter.isAllowed("10.0.0.1")).thenReturn(false);

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user1", LoginStatus.SUCCESS), httpRequest);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        verify(loginRateLimiter).isAllowed("10.0.0.1");
        verify(loginService, never()).recordLoginAttempt("user1", "10.0.0.1", LoginStatus.SUCCESS);
        verifyNoInteractions(loginService, captchaService);
    }

    @Test
    @DisplayName("Should return 201 Created and save the attempt when the IP is allowed")
    void testPostLoginAttempt_allowedReturnsCreated() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.2");
        when(loginRateLimiter.isAllowed("10.0.0.2")).thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.2")).thenReturn(false);
        LoginAttempt savedAttempt = new LoginAttempt(
                1L, "user2", "10.0.0.2", LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.recordLoginAttempt("user2", "10.0.0.2", LoginStatus.SUCCESS))
                .thenReturn(savedAttempt);

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user2", LoginStatus.SUCCESS), httpRequest);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(savedAttempt, response.getBody());
        verify(loginService).recordLoginAttempt("user2", "10.0.0.2", LoginStatus.SUCCESS);
    }

    @Test
    @DisplayName("Should save the fifth failure and return CAPTCHA-required response")
    void testPostLoginAttempt_fifthFailureSavedAndRequiresCaptcha() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.3");
        when(loginRateLimiter.isAllowed("10.0.0.3")).thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.3")).thenReturn(false, true);
        LoginAttempt savedAttempt = new LoginAttempt(
                5L, "user3", "10.0.0.3", LocalDateTime.now(), LoginStatus.FAILURE);
        when(loginService.recordLoginAttempt("user3", "10.0.0.3", LoginStatus.FAILURE))
                .thenReturn(savedAttempt);

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user3", LoginStatus.FAILURE), httpRequest);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals(true, ((Map<String, Object>) response.getBody()).get("captchaRequired"));
        verify(loginService).recordLoginAttempt("user3", "10.0.0.3", LoginStatus.FAILURE);
    }

    @Test
    @DisplayName("Should block a subsequent login attempt without verification")
    void testPostLoginAttempt_subsequentAttemptWithoutVerificationIsBlocked() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.4");
        when(loginRateLimiter.isAllowed("10.0.0.4")).thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.4")).thenReturn(true);
        when(captchaService.consumePermission("10.0.0.4")).thenReturn(false);

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user4", LoginStatus.FAILURE), httpRequest);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        verify(loginService, never()).recordLoginAttempt(any(String.class), any(String.class), any(LoginStatus.class));
    }

    @Test
    @DisplayName("Should consume a successful verification permission exactly once before login")
    void testPostLoginAttempt_verificationPermissionPermitsOneAttempt() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.5");
        when(loginRateLimiter.isAllowed("10.0.0.5")).thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.5")).thenReturn(true);
        when(captchaService.consumePermission("10.0.0.5")).thenReturn(true, false);
        LoginAttempt savedAttempt = new LoginAttempt(
                6L, "user5", "10.0.0.5", LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.recordLoginAttempt("user5", "10.0.0.5", LoginStatus.SUCCESS))
                .thenReturn(savedAttempt);

        ResponseEntity<?> firstResponse = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user5", LoginStatus.SUCCESS), httpRequest);
        ResponseEntity<?> secondResponse = loginAttemptController.recordLoginAttempt(
                new LoginRequest("user5", LoginStatus.SUCCESS), httpRequest);

        assertEquals(HttpStatus.CREATED, firstResponse.getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, secondResponse.getStatusCode());
        verify(captchaService, org.mockito.Mockito.times(2)).consumePermission("10.0.0.5");
        verify(loginService, org.mockito.Mockito.times(1))
                .recordLoginAttempt("user5", "10.0.0.5", LoginStatus.SUCCESS);
    }

    @Test
    @DisplayName("Should return 400 Bad Request when status parameter is invalid")
    void testHandleTypeMismatch_returnsBadRequest() {
        MethodArgumentTypeMismatchException ex = new MethodArgumentTypeMismatchException(
                "INVALID_STATUS",
                LoginStatus.class,
                "status",
                (MethodParameter) null,
                null
        );

        ResponseEntity<Map<String, Object>> response = loginAttemptController.handleTypeMismatch(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(400, response.getBody().get("status"));
        assertEquals("Bad Request", response.getBody().get("error"));
        assertNotNull(response.getBody().get("message"));
    }
}

