package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;

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

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;
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

    @InjectMocks
    private AuthController authController;

    @Test
    void verifiedBasicAuthenticationCreatesSession() {
        HttpServletRequest request =
                org.mockito.Mockito.mock(HttpServletRequest.class);
        Authentication authentication =
                new TestingAuthenticationToken("alice", null);
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.10");

        LoginAttempt attempt = new LoginAttempt(
                1L, "alice", "192.168.1.10",
                LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS))
                .thenReturn(attempt);

        LoginSession session = new LoginSession();
        session.setSessionId("secure-session-id");
        session.setUsername("alice");
        session.setIpAddress("192.168.1.10");
        session.setCreatedAt(LocalDateTime.now());
        session.setExpiresAt(LocalDateTime.now().plusMinutes(15));
        session.setActive(true);
        when(sessionService.createSession("alice", "192.168.1.10"))
                .thenReturn(session);

        ResponseEntity<?> response =
                authController.login(authentication, request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        verify(loginService, org.mockito.Mockito.times(1)).recordLoginAttempt(
                "alice", "192.168.1.10", LoginStatus.SUCCESS);
        verify(sessionService, org.mockito.Mockito.times(1))
                .createSession("alice", "192.168.1.10");
    }

    @Test
    void logoutInvalidatesTheCurrentSession() {
        Authentication authentication =
                new TestingAuthenticationToken(
                        "alice", null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(sessionService.logout("alice-session")).thenReturn(true);

        ResponseEntity<?> response =
                authController.logout("alice-session", authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionService).logout("alice-session");
    }

    @Test
    void logoutReturnsUnauthorizedForMissingOrInactiveSession() {
        Authentication authentication =
                new TestingAuthenticationToken(
                        "alice", null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER")));
        when(sessionService.logout("missing-session")).thenReturn(false);

        ResponseEntity<?> response =
                authController.logout("missing-session", authentication);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(sessionService).logout("missing-session");
    }
}
