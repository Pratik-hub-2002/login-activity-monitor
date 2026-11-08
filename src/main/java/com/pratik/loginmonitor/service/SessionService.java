
package com.pratik.loginmonitor.service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.repository.LoginSessionRepository;

@Service
public class SessionService {

    private static final long SESSION_INACTIVITY_MINUTES = 15;

    private final LoginSessionRepository loginSessionRepository;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    public SessionService(LoginSessionRepository loginSessionRepository, Clock clock) {
        this.loginSessionRepository = loginSessionRepository;
        this.clock = clock;
    }

    // Create a new session after successful login
    @Transactional
    public LoginSession createSession(String username, String ipAddress) {

        LocalDateTime createdAt = LocalDateTime.now(clock);

        LoginSession session = new LoginSession();

        session.setSessionId(generateSessionId());
        session.setUsername(username);
        session.setIpAddress(ipAddress);
        session.setCreatedAt(createdAt);
        session.setLastActivityAt(createdAt);
        session.setExpiresAt(
                createdAt.plusMinutes(SESSION_INACTIVITY_MINUTES));
        session.setLoggedOutAt(null);
        session.setActive(true);

        return loginSessionRepository.save(session);
    }

    // Validate a session
    @Transactional
    public boolean validateSession(String sessionId) {

        Optional<LoginSession> optionalSession =
                loginSessionRepository.findBySessionId(sessionId);

        if (optionalSession.isEmpty()) {
            return false;
        }

        LoginSession session = optionalSession.get();

        if (!session.isActive()) {
            return false;
        }

        LocalDateTime now = LocalDateTime.now(clock);

        if (!now.isBefore(session.getExpiresAt())) {
            session.setActive(false);
            loginSessionRepository.save(session);
            return false;
        }

        return true;
    }

    // Logout a session
    @Transactional
    public boolean logout(String sessionId) {

        Optional<LoginSession> optionalSession =
                loginSessionRepository.findBySessionId(sessionId);

        if (optionalSession.isEmpty()) {
            return false;
        }

        LoginSession session = optionalSession.get();

        if (!session.isActive()) {
            return false;
        }

        session.setActive(false);
        session.setLoggedOutAt(LocalDateTime.now(clock));

        loginSessionRepository.save(session);

        return true;
    }

    // Refresh session after user activity
    @Transactional
    public Optional<LoginSession> refreshSession(String sessionId) {
        return refreshSession(sessionId, null, null);
    }

    @Transactional
    public Optional<LoginSession> refreshSession(
            String sessionId, String clientIp, String expectedUsername) {
        Optional<LoginSession> optionalSession =
                loginSessionRepository.findBySessionId(sessionId);
        if (optionalSession.isEmpty()) {
            return Optional.empty();
        }

        LoginSession session = optionalSession.get();
        if (!session.isActive()) {
            return Optional.empty();
        }

        LocalDateTime now = LocalDateTime.now(clock);
        if (!now.isBefore(session.getExpiresAt())) {
            session.setActive(false);
            loginSessionRepository.save(session);
            return Optional.empty();
        }

        if (clientIp != null
                && !clientIp.isBlank()
                && session.getIpAddress() != null
                && !clientIp.equals(session.getIpAddress())) {
            return Optional.empty();
        }

        if (expectedUsername != null
                && !expectedUsername.isBlank()
                && !expectedUsername.equals(session.getUsername())) {
            return Optional.empty();
        }

        session.setLastActivityAt(now);
        session.setExpiresAt(
                now.plusMinutes(SESSION_INACTIVITY_MINUTES));

        return Optional.of(loginSessionRepository.save(session));
    }

    @Transactional
    public Optional<LoginSession> getValidatedSession(String sessionId) {
        Optional<LoginSession> optionalSession =
                loginSessionRepository.findBySessionId(sessionId);
        if (optionalSession.isEmpty()) {
            return Optional.empty();
        }

        LoginSession session = optionalSession.get();
        if (!session.isActive()) {
            return Optional.empty();
        }

        if (!LocalDateTime.now(clock).isBefore(session.getExpiresAt())) {
            session.setActive(false);
            loginSessionRepository.save(session);
            return Optional.empty();
        }

        return Optional.of(session);
    }

    // Retrieve all active and unexpired sessions (Admin functionality)
    public List<LoginSession> getActiveSessions() {

        LocalDateTime now = LocalDateTime.now(clock);

        return loginSessionRepository
                .findByActiveTrueAndExpiresAtAfterOrderByCreatedAtDesc(now);
    }

    public List<LoginSession> getActiveSessionsByUsername(String username) {

        LocalDateTime now = LocalDateTime.now(clock);

        return loginSessionRepository
                .findByUsernameAndActiveTrueAndExpiresAtAfterOrderByCreatedAtDesc(
                        username, now);
    }

    // Generate a secure random session ID
    private String generateSessionId() {

        byte[] randomBytes = new byte[32];

        secureRandom.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }
}
