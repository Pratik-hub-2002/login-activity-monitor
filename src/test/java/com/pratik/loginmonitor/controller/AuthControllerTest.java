package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.pratik.loginmonitor.dto.OtpVerificationRequest;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;
import com.pratik.loginmonitor.service.OneTimePasswordService;
import com.pratik.loginmonitor.service.SessionService;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private LoginService loginService;

    @Mock
    private SessionService sessionService;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @Mock
    private OneTimePasswordService oneTimePasswordService;

    @InjectMocks
    private AuthController authController;

    @Test
    void validCredentialsSendOtpWithoutCreatingSessionOrSuccessRecord() {
        HttpServletRequest request = org.mockito.Mockito.mock(HttpServletRequest.class);
        Authentication authentication = authentication();
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.10");

        ResponseEntity<?> response = authController.login(authentication, request);

        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
        Map<?, ?> body = (Map<?, ?>) response.getBody();
        assertTrue((Boolean) body.get("otpRequired"));
        assertFalse(body.containsKey("otp"));
        verify(oneTimePasswordService).sendOtp(
                "alice", "192.168.1.10");
        verify(loginService, never()).recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS);
        verify(sessionService, never()).createSession("alice", "192.168.1.10");
    }

    @Test
    void validOtpRecordsSuccessAndCreatesSession() {
        HttpServletRequest request = org.mockito.Mockito.mock(HttpServletRequest.class);
        Authentication authentication = authentication();
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.10");
        when(oneTimePasswordService.verifyOtp(
                "alice", "192.168.1.10", "123456")).thenReturn(true);

        LoginAttempt attempt = new LoginAttempt(
                1L, "alice", "192.168.1.10",
                LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS)).thenReturn(attempt);

        LoginSession session = new LoginSession();
        session.setSessionId("secure-session-id");
        session.setUsername("alice");
        session.setIpAddress("192.168.1.10");
        session.setCreatedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusMinutes(15));
        session.setActive(true);
        when(sessionService.createSession("alice", "192.168.1.10"))
                .thenReturn(session);

        ResponseEntity<?> response = authController.verifyOtp(
                authentication, new OtpVerificationRequest("123456"), request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals("USER", ((Map<?, ?>) response.getBody()).get("role"));
        verify(loginService).recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS);
        verify(sessionService).createSession("alice", "192.168.1.10");
    }

    @Test
    void invalidOtpDoesNotRecordSuccessOrCreateSession() {
        HttpServletRequest request = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.10");
        when(oneTimePasswordService.verifyOtp(
                "alice", "192.168.1.10", "000000")).thenReturn(false);

        ResponseEntity<?> response = authController.verifyOtp(
                authentication(), new OtpVerificationRequest("000000"), request);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(loginService, never()).recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS);
        verify(sessionService, never()).createSession("alice", "192.168.1.10");
    }

    @Test
    void logoutInvalidatesTheCurrentSession() {
        Authentication authentication = authentication();
        when(sessionService.logout("alice-session")).thenReturn(true);

        ResponseEntity<?> response =
                authController.logout("alice-session", authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionService).logout("alice-session");
    }

    @Test
    void logoutReturnsUnauthorizedForMissingOrInactiveSession() {
        Authentication authentication = authentication();
        when(sessionService.logout("missing-session")).thenReturn(false);

        ResponseEntity<?> response =
                authController.logout("missing-session", authentication);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(sessionService).logout("missing-session");
    }

    @Test
    void otpDeliveryFailureReturns503ServiceUnavailable() {
        OneTimePasswordService.OtpDeliveryException deliveryException =
                new OneTimePasswordService.OtpDeliveryException("Unable to deliver the login verification code.");

        ResponseEntity<Map<String, String>> response =
                authController.otpDeliveryFailed(deliveryException);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals("Unable to deliver the login verification code.", response.getBody().get("message"));
    }

    private Authentication authentication() {
        return new TestingAuthenticationToken(
                "alice",
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }
}
