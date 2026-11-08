package com.pratik.loginmonitor.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;
import com.pratik.loginmonitor.service.SessionService;

import jakarta.servlet.http.HttpServletRequest;
import com.pratik.loginmonitor.config.SessionAuthenticationFilter;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final LoginService loginService;
    private final SessionService sessionService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public AuthController(
            LoginService loginService,
            SessionService sessionService,
            ClientIpAddressExtractor clientIpAddressExtractor) {
        this.loginService = loginService;
        this.sessionService = sessionService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            Authentication authentication,
            HttpServletRequest request) {

        String username = authentication.getName();
        String clientIp = clientIpAddressExtractor.extract(request);

        LoginAttempt attempt = loginService.recordLoginAttempt(
                username, clientIp, LoginStatus.SUCCESS);
        LoginSession session = sessionService.createSession(username, clientIp);

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "loginAttempt", attempt,
                "session", Map.of(
                        "sessionId", session.getSessionId(),
                        "createdAt", session.getCreatedAt(),
                        "expiresAt", session.getExpiresAt())));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(SessionAuthenticationFilter.SESSION_HEADER)
            String sessionId,
            Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!sessionService.logout(sessionId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok(Map.of(
                "message", "Session logged out successfully"));
    }
}
