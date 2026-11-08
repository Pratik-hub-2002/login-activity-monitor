package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.repository.LoginSessionRepository;

@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-01-01T00:00:00Z");

    @Mock
    private LoginSessionRepository loginSessionRepository;

    private MutableClock clock;
    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(FIXED_INSTANT);
        sessionService = new SessionService(loginSessionRepository, clock);
    }

    @Test
    @DisplayName("Should create, save, and configure a 15-minute inactivity session")
    void createSessionCreatesValidSession() {
        when(loginSessionRepository.save(any(LoginSession.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        LoginSession session = sessionService.createSession("alice", "192.168.1.10");

        assertEquals("alice", session.getUsername());
        assertEquals("192.168.1.10", session.getIpAddress());
        assertTrue(session.isActive());
        assertNotNull(session.getSessionId());
        assertFalse(session.getSessionId().isBlank());

        LocalDateTime createdAt = LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC);
        assertEquals(createdAt, session.getCreatedAt());
        assertEquals(createdAt, session.getLastActivityAt());
        assertEquals(createdAt.plusMinutes(15), session.getExpiresAt());
        verify(loginSessionRepository).save(session);
    }

    @Test
    @DisplayName("Should validate an active unexpired session")
    void validateActiveUnexpiredSession() {
        LoginSession session = activeSession();
        when(loginSessionRepository.findBySessionId("session-1"))
                .thenReturn(Optional.of(session));

        assertTrue(sessionService.validateSession("session-1"));
    }

    @Test
    @DisplayName("Should return false for a missing session")
    void validateMissingSession() {
        when(loginSessionRepository.findBySessionId("missing-session"))
                .thenReturn(Optional.empty());

        assertFalse(sessionService.validateSession("missing-session"));
    }

    @Test
    @DisplayName("Should return false for an inactive session")
    void validateInactiveSession() {
        LoginSession session = activeSession();
        session.setActive(false);
        when(loginSessionRepository.findBySessionId("inactive-session"))
                .thenReturn(Optional.of(session));

        assertFalse(sessionService.validateSession("inactive-session"));
        verify(loginSessionRepository, never()).save(any(LoginSession.class));
    }

    @Test
    @DisplayName("Should deactivate and save an expired session")
    void validateExpiredSessionDeactivatesIt() {
        LoginSession session = activeSession();
        session.setExpiresAt(LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC).minusSeconds(1));
        when(loginSessionRepository.findBySessionId("expired-session"))
                .thenReturn(Optional.of(session));

        assertFalse(sessionService.validateSession("expired-session"));
        assertFalse(session.isActive());
        verify(loginSessionRepository).save(session);
    }

    @Test
    @DisplayName("Should expire an active session after exactly 15 minutes without refresh")
    void validateSessionExpiresAtInactivityDeadline() {
        LoginSession session = activeSession();
        session.setExpiresAt(LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC).plusMinutes(15));
        when(loginSessionRepository.findBySessionId("expired-session"))
                .thenReturn(Optional.of(session));

        clock.advance(Duration.ofMinutes(15));

        assertFalse(sessionService.validateSession("expired-session"));
        assertFalse(session.isActive());
        verify(loginSessionRepository).save(session);
    }

    @Test
    @DisplayName("Should deactivate and set logout time for an active session")
    void logoutActiveSession() {
        LoginSession session = activeSession();
        when(loginSessionRepository.findBySessionId("session-1"))
                .thenReturn(Optional.of(session));

        assertTrue(sessionService.logout("session-1"));
        assertFalse(session.isActive());
        assertEquals(LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC), session.getLoggedOutAt());
        verify(loginSessionRepository).save(session);
    }

    @Test
    @DisplayName("Should return false when logging out a missing session")
    void logoutMissingSession() {
        when(loginSessionRepository.findBySessionId("missing-session"))
                .thenReturn(Optional.empty());

        assertFalse(sessionService.logout("missing-session"));
        verify(loginSessionRepository, never()).save(any(LoginSession.class));
    }

    @Test
    @DisplayName("Should return false when logging out an inactive session")
    void logoutInactiveSession() {
        LoginSession session = activeSession();
        session.setActive(false);
        when(loginSessionRepository.findBySessionId("inactive-session"))
                .thenReturn(Optional.of(session));

        assertFalse(sessionService.logout("inactive-session"));
        verify(loginSessionRepository, never()).save(any(LoginSession.class));
    }

    @Test
    @DisplayName("Should refresh activity and expiry by 15 minutes")
    void refreshValidSession() {
        LoginSession session = activeSession();
        when(loginSessionRepository.findBySessionId("session-1"))
                .thenReturn(Optional.of(session));
        when(loginSessionRepository.save(any(LoginSession.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        clock.advance(Duration.ofMinutes(10));
        Optional<LoginSession> result = sessionService.refreshSession("session-1");

        assertTrue(result.isPresent());
        LocalDateTime now = LocalDateTime.ofInstant(FIXED_INSTANT.plus(Duration.ofMinutes(10)), ZoneOffset.UTC);
        assertEquals(now, result.get().getLastActivityAt());
        assertEquals(now.plusMinutes(15), result.get().getExpiresAt());
        verify(loginSessionRepository).save(session);
    }

    @Test
    @DisplayName("Should return empty when refreshing a missing session")
    void refreshMissingSession() {
        when(loginSessionRepository.findBySessionId("missing-session"))
                .thenReturn(Optional.empty());

        assertTrue(sessionService.refreshSession("missing-session").isEmpty());
        verify(loginSessionRepository, never()).save(any(LoginSession.class));
    }

    @Test
    @DisplayName("Should return empty when refreshing an inactive session")
    void refreshInactiveSession() {
        LoginSession session = activeSession();
        session.setActive(false);
        when(loginSessionRepository.findBySessionId("inactive-session"))
                .thenReturn(Optional.of(session));

        assertTrue(sessionService.refreshSession("inactive-session").isEmpty());
        verify(loginSessionRepository, never()).save(any(LoginSession.class));
    }

    @Test
    @DisplayName("Should return empty and deactivate when refreshing an expired session")
    void refreshExpiredSession() {
        LoginSession session = activeSession();
        session.setExpiresAt(LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC).minusSeconds(1));
        when(loginSessionRepository.findBySessionId("expired-session"))
                .thenReturn(Optional.of(session));

        assertTrue(sessionService.refreshSession("expired-session").isEmpty());
        assertFalse(session.isActive());
        verify(loginSessionRepository).save(session);
    }

    private LoginSession activeSession() {
        LocalDateTime createdAt = LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC);
        return new LoginSession(
                1L,
                "session-1",
                "alice",
                "192.168.1.10",
                createdAt,
                createdAt.plusMinutes(15),
                createdAt,
                null,
                true
        );
    }

    private static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
