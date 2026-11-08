package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
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

import com.pratik.loginmonitor.dto.ActiveSessionResponse;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.service.SessionService;

@ExtendWith(MockitoExtension.class)
class SessionControllerTest {

    @Mock
    private SessionService sessionService;

    @InjectMocks
    private SessionController sessionController;

    @Test
    void adminCanRetrieveActiveSessions() {
        Authentication auth = authentication("admin", "ROLE_ADMIN");
        LoginSession session = activeSession("alice");
        when(sessionService.getActiveSessions()).thenReturn(List.of(session));

        ResponseEntity<?> response = sessionController.getActiveSessions(auth);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        List<ActiveSessionResponse> body = body(response);
        assertEquals(1, body.size());
        assertEquals("alice", body.get(0).getUsername());
    }

    @Test
    void superAdminCanRetrieveActiveSessions() {
        Authentication auth = authentication("owner", "ROLE_SUPERADMIN");
        when(sessionService.getActiveSessions()).thenReturn(List.of());

        ResponseEntity<?> response = sessionController.getActiveSessions(auth);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(body(response).isEmpty());
    }

    @Test
    void userCannotRetrieveAllActiveSessions() {
        Authentication auth = authentication("alice", "ROLE_USER");

        ResponseEntity<?> response = sessionController.getActiveSessions(auth);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        verify(sessionService, never()).getActiveSessions();
    }

    @Test
    void adminCanRetrieveSessionsForSpecificUser() {
        Authentication auth = authentication("admin", "ROLE_ADMIN");
        when(sessionService.getActiveSessionsByUsername("alice"))
                .thenReturn(List.of(activeSession("alice")));

        ResponseEntity<?> response =
                sessionController.getSessionsForUser("alice", auth);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("alice", body(response).get(0).getUsername());
    }

    @Test
    void userCanRetrieveOnlyOwnSessions() {
        Authentication auth = authentication("alice", "ROLE_USER");
        when(sessionService.getActiveSessionsByUsername("alice"))
                .thenReturn(List.of(activeSession("alice")));

        ResponseEntity<?> response =
                sessionController.getSessionsForUser("alice", auth);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("alice", body(response).get(0).getUsername());
    }

    @Test
    void userCannotRetrieveAnotherUsersSessions() {
        Authentication auth = authentication("alice", "ROLE_USER");

        ResponseEntity<?> response =
                sessionController.getSessionsForUser("bob", auth);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        verify(sessionService, never()).getActiveSessionsByUsername("bob");
    }

    @Test
    void unauthenticatedRequestIsUnauthorized() {
        ResponseEntity<?> activeResponse =
                sessionController.getActiveSessions(null);
        ResponseEntity<?> userResponse =
                sessionController.getSessionsForUser("alice", null);

        assertEquals(HttpStatus.UNAUTHORIZED, activeResponse.getStatusCode());
        assertEquals(HttpStatus.UNAUTHORIZED, userResponse.getStatusCode());
    }

    @Test
    void expiredSessionsAreExcludedByServiceResults() {
        Authentication auth = authentication("admin", "ROLE_ADMIN");
        when(sessionService.getActiveSessions()).thenReturn(List.of());

        ResponseEntity<?> response = sessionController.getActiveSessions(auth);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(body(response).isEmpty());
    }

    private Authentication authentication(String username, String role) {
        return new TestingAuthenticationToken(
                username,
                null,
                List.of(new SimpleGrantedAuthority(role)));
    }

    private LoginSession activeSession(String username) {
        LocalDateTime now = LocalDateTime.now();
        LoginSession session = new LoginSession();
        session.setUsername(username);
        session.setIpAddress("192.168.1.10");
        session.setCreatedAt(now.minusMinutes(5));
        session.setLastActivityAt(now);
        session.setExpiresAt(now.plusMinutes(15));
        session.setActive(true);
        return session;
    }

    @SuppressWarnings("unchecked")
    private List<ActiveSessionResponse> body(ResponseEntity<?> response) {
        return (List<ActiveSessionResponse>) response.getBody();
    }
}
