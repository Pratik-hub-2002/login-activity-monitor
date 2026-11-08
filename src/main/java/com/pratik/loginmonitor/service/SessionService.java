package com.pratik.loginmonitor.service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

import org.springframework.stereotype.Service;

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

    public LoginSession createSession(String username, String ipAddress) {
        LocalDateTime createdAt = LocalDateTime.now(clock);
        LoginSession session = new LoginSession();
        session.setSessionId(generateSessionId());
        session.setUsername(username);
        session.setIpAddress(ipAddress);
        session.setCreatedAt(createdAt);
        session.setLastActivityAt(createdAt);
        session.setExpiresAt(createdAt.plusMinutes(SESSION_INACTIVITY_MINUTES));
        session.setLoggedOutAt(null);
        session.setActive(true);
        return loginSessionRepository.save(session);
    }

    public boolean validateSession(String sessionId) {
        Optional<LoginSession> optionalSession = loginSessionRepository.findBySessionId(sessionId);
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

    public boolean logout(String sessionId) {
        Optional<LoginSession> optionalSession = loginSessionRepository.findBySessionId(sessionId);
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

    public Optional<LoginSession> refreshSession(String sessionId) {
        if (!validateSession(sessionId)) {
            return Optional.empty();
        }

        Optional<LoginSession> optionalSession = loginSessionRepository.findBySessionId(sessionId);
        if (optionalSession.isEmpty()) {
            return Optional.empty();
        }

        LoginSession session = optionalSession.get();
        LocalDateTime now = LocalDateTime.now(clock);
        session.setLastActivityAt(now);
        session.setExpiresAt(now.plusMinutes(SESSION_INACTIVITY_MINUTES));
        return Optional.of(loginSessionRepository.save(session));
    }

    private String generateSessionId() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
