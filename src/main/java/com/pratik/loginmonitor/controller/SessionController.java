package com.pratik.loginmonitor.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pratik.loginmonitor.dto.ActiveSessionResponse;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.service.SessionService;

@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping("/active")
    public ResponseEntity<?> getActiveSessions(Authentication authentication) {
        if (!isAuthenticated(authentication)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!isAdmin(authentication)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(toResponse(sessionService.getActiveSessions()));
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<?> getSessionsForUser(
            @PathVariable String username,
            Authentication authentication) {

        if (!isAuthenticated(authentication)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        boolean admin = isAdmin(authentication);
        if (!admin && !authentication.getName().equals(username)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok(
                toResponse(sessionService.getActiveSessionsByUsername(username)));
    }

    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null
                && authentication.isAuthenticated()
                && authentication.getName() != null;
    }

    private boolean isAdmin(Authentication authentication) {
        if (authentication.getAuthorities() == null) {
            return false;
        }

        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String role = authority.getAuthority();
            if ("ROLE_ADMIN".equals(role)
                    || "ADMIN".equals(role)
                    || "ROLE_SUPERADMIN".equals(role)
                    || "SUPERADMIN".equals(role)) {
                return true;
            }
        }

        return false;
    }

    private List<ActiveSessionResponse> toResponse(List<LoginSession> sessions) {
        return sessions.stream()
                .map(session -> new ActiveSessionResponse(
                        session.getUsername(),
                        session.getIpAddress(),
                        session.getCreatedAt(),
                        session.getLastActivityAt(),
                        session.getExpiresAt()))
                .toList();
    }
}
