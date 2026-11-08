
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.dto.PublicLoginFailureRequest;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.LoginRateLimiter;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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

    // 1. GET login attempts
    @Test
    @DisplayName("Should return 200 OK and list of login attempts")
    void testGetLoginAttempts_returnsList() {

        LoginAttempt a1 = new LoginAttempt(
                1L,
                "john",
                "192.168.1.1",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        when(loginService.getLoginAttempts(
                "john", "192.168.1.1", LoginStatus.SUCCESS
        )).thenReturn(List.of(a1));

        Authentication authentication = new TestingAuthenticationToken(
                "john", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        "john", "192.168.1.1", LoginStatus.SUCCESS, authentication
                );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, ((List<?>) response.getBody()).size());

        verify(loginService).getLoginAttempts(
                "john", "192.168.1.1", LoginStatus.SUCCESS
        );

        verifyNoInteractions(
                loginRateLimiter,
                captchaService,
                clientIpAddressExtractor
        );
    }

    @Test
    @DisplayName("USER should be able to retrieve only their own login history")
    void testGetLoginAttempts_userOwnHistory() {
        Authentication authentication = new TestingAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        LoginAttempt attempt = new LoginAttempt(
                1L, "alice", "192.168.1.10",
                LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.getLoginAttempts(
                "alice", null, null)).thenReturn(List.of(attempt));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        null, null, null, authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(loginService).getLoginAttempts("alice", null, null);
    }

    @Test
    @DisplayName("USER should not retrieve another user's login history")
    void testGetLoginAttempts_userCannotViewAnotherUser() {
        Authentication authentication = new TestingAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        "bob", null, null, authentication);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        verify(loginService, never()).getLoginAttempts(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    // 2. Rate limiter blocks request
    @Test
    @DisplayName("Should return 429 when IP is blocked")
    void testPostLoginAttempt_returnsTooManyRequestsWithoutSaving() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.1");

        when(loginRateLimiter.isAllowed("10.0.0.1"))
                .thenReturn(false);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user1"),
                        httpRequest
                );

        assertEquals(
                HttpStatus.TOO_MANY_REQUESTS,
                response.getStatusCode()
        );

        verify(loginRateLimiter).isAllowed("10.0.0.1");

        verify(loginService, never()).recordLoginAttempt(
                anyString(), anyString(), any(LoginStatus.class)
        );

        verifyNoInteractions(loginService, captchaService);
    }

    // 3. Successful login creates a session
    @Test
    @DisplayName("Should record a public failure without treating it as an authenticated success")
    void testPostLoginAttempt_publicFailureReturnsCreated() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.2");

        when(loginRateLimiter.isAllowed("10.0.0.2"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.2"))
                .thenReturn(false);

        LoginAttempt savedAttempt = new LoginAttempt(
                1L,
                "user2",
                "10.0.0.2",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(loginService.recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE
        )).thenReturn(savedAttempt);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user2"),
                        httpRequest
                );

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(savedAttempt, response.getBody());

        verify(loginService).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE
        );
    }

    @Test
    @DisplayName("Should never create a public SUCCESS record or authenticated session")
    void testPostLoginAttempt_failureOnlyPayloadNeverUsesSuccessStatus() {
        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.2");
        when(loginRateLimiter.isAllowed("10.0.0.2"))
                .thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.2"))
                .thenReturn(false);

        LoginAttempt savedFailure = new LoginAttempt(
                2L,
                "user2",
                "10.0.0.2",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );
        when(loginService.recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE))
                .thenReturn(savedFailure);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user2"),
                        httpRequest);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        verify(loginService, org.mockito.Mockito.never()).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.SUCCESS);
        verify(loginService, org.mockito.Mockito.times(1)).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE);
    }

    // 4. Fifth failure requires CAPTCHA
    @Test
    @DisplayName("Should save fifth failure and require CAPTCHA")
    void testPostLoginAttempt_fifthFailureSavedAndRequiresCaptcha() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.3");

        when(loginRateLimiter.isAllowed("10.0.0.3"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.3"))
                .thenReturn(false, true);

        LoginAttempt savedAttempt = new LoginAttempt(
                5L,
                "user3",
                "10.0.0.3",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(loginService.recordLoginAttempt(
                "user3", "10.0.0.3", LoginStatus.FAILURE
        )).thenReturn(savedAttempt);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user3"),
                        httpRequest
                );

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        Map<String, Object> responseBody =
                (Map<String, Object>) response.getBody();

        assertEquals(true, responseBody.get("captchaRequired"));

        verify(loginService).recordLoginAttempt(
                "user3", "10.0.0.3", LoginStatus.FAILURE
        );

    }

    // 5. Block attempt when CAPTCHA permission is missing
    @Test
    @DisplayName("Should block login without CAPTCHA verification")
    void testPostLoginAttempt_subsequentAttemptWithoutVerificationIsBlocked() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.4");

        when(loginRateLimiter.isAllowed("10.0.0.4"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.4"))
                .thenReturn(true);

        when(captchaService.consumePermission("10.0.0.4"))
                .thenReturn(false);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user4"),
                        httpRequest
                );

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        verify(loginService, never()).recordLoginAttempt(
                any(String.class),
                any(String.class),
                any(LoginStatus.class)
        );

    }

    // 6. Successful CAPTCHA permission allows one login attempt
    @Test
    @DisplayName("Should consume CAPTCHA permission exactly once for failure monitoring")
    void testPostLoginAttempt_verificationPermissionPermitsOneAttempt() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.5");

        when(loginRateLimiter.isAllowed("10.0.0.5"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.5"))
                .thenReturn(true, false, true);

        when(captchaService.consumePermission("10.0.0.5"))
                .thenReturn(true, false);

        LoginAttempt savedAttempt = new LoginAttempt(
                6L,
                "user5",
                "10.0.0.5",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(loginService.recordLoginAttempt(
                "user5", "10.0.0.5", LoginStatus.FAILURE
        )).thenReturn(savedAttempt);

        ResponseEntity<?> firstResponse =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user5"),
                        httpRequest
                );

        ResponseEntity<?> secondResponse =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest("user5"),
                        httpRequest
                );

        assertEquals(
                HttpStatus.CREATED,
                firstResponse.getStatusCode()
        );

        assertEquals(
                HttpStatus.FORBIDDEN,
                secondResponse.getStatusCode()
        );

        verify(captchaService, org.mockito.Mockito.times(2))
                .consumePermission("10.0.0.5");

        verify(loginService, org.mockito.Mockito.times(1))
                .recordLoginAttempt(
                        "user5", "10.0.0.5", LoginStatus.FAILURE
                );

    }

    // 7. Invalid status query parameter
    @Test
    @DisplayName("Should return 400 when status parameter is invalid")
    void testHandleTypeMismatch_returnsBadRequest() {

        MethodArgumentTypeMismatchException ex =
                new MethodArgumentTypeMismatchException(
                        "INVALID_STATUS",
                        LoginStatus.class,
                        "status",
                        (MethodParameter) null,
                        null
                );

        ResponseEntity<Map<String, Object>> response =
                loginAttemptController.handleTypeMismatch(ex);

        assertEquals(
                HttpStatus.BAD_REQUEST,
                response.getStatusCode()
        );

        assertNotNull(response.getBody());

        assertEquals(400, response.getBody().get("status"));
        assertEquals("Bad Request", response.getBody().get("error"));
        assertNotNull(response.getBody().get("message"));
    }
}
