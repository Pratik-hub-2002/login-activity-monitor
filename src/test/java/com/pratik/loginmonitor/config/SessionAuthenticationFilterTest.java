
package com.pratik.loginmonitor.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.UserRepository;
import com.pratik.loginmonitor.service.SessionService;
import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
class SessionAuthenticationFilterTest {

    @Mock
    private SessionService sessionService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private FilterChain filterChain;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validSessionGrantsDatabaseUserAndRole() throws Exception {
        LoginSession session = session("alice", true);
        User user = databaseUser("alice", UserRole.ADMIN, true);

        when(sessionService.getValidatedSession("valid-session"))
                .thenReturn(Optional.of(session));

        when(clientIpAddressExtractor.extract(any(HttpServletRequest.class)))
                .thenReturn("192.168.1.10");

        when(sessionService.refreshSession(
                "valid-session", "192.168.1.10", "alice"))
                .thenReturn(Optional.of(session));

        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user));

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest("valid-session");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(sessionService).refreshSession(
                "valid-session", "192.168.1.10", "alice");

        verify(filterChain).doFilter(
                any(HttpServletRequest.class), eq(response));

        assertEquals("alice",
                SecurityContextHolder.getContext().getAuthentication().getName());

        assertTrue(SecurityContextHolder.getContext().getAuthentication()
                .getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void invalidUnknownSessionReturns401() throws Exception {
        when(sessionService.getValidatedSession("unknown-session"))
                .thenReturn(Optional.empty());

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest("unknown-session");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verifyNoInteractions(filterChain);

        assertFalse(SecurityContextHolder.getContext().getAuthentication() != null);
    }

    @Test
    void missingSessionHeaderReturns401WithoutPersistenceLookup() throws Exception {
        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/sessions/active");

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verifyNoInteractions(sessionService, userRepository, filterChain);
    }

    @Test
    void expiredSessionReturns401() throws Exception {
        assertInvalidRefreshedSession(Optional.empty(), "expired-session");
    }

    @Test
    void inactiveSessionReturns401() throws Exception {
        assertInvalidRefreshedSession(Optional.empty(), "inactive-session");
    }

    @Test
    void basicCredentialsCannotChangeOrBypassSessionOwner() throws Exception {
        LoginSession session = session("alice", true);

        when(sessionService.getValidatedSession("alice-session"))
                .thenReturn(Optional.of(session));

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest("alice-session");

        request.addHeader("Authorization",
                basicAuthorization("bob", "password"));

        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());

        verify(sessionService, never()).refreshSession(
                eq("alice-session"), any(), any());

        verifyNoInteractions(userRepository, filterChain);
    }

    @Test
    void invalidClientIpDoesNotRefreshSession() throws Exception {
        LoginSession session = session("alice", true);

        when(sessionService.getValidatedSession("alice-session"))
                .thenReturn(Optional.of(session));

        when(clientIpAddressExtractor.extract(any(HttpServletRequest.class)))
                .thenReturn("203.0.113.50");

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest("alice-session");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());

        verify(sessionService, never()).refreshSession(
                eq("alice-session"), any(), any());

        verifyNoInteractions(userRepository, filterChain);
    }

    @Test
    void disabledSessionUserReturns401() throws Exception {
        LoginSession session = session("alice", true);
        User user = databaseUser("alice", UserRole.ADMIN, false);

        when(sessionService.getValidatedSession("valid-session"))
                .thenReturn(Optional.of(session));

        when(clientIpAddressExtractor.extract(any(HttpServletRequest.class)))
                .thenReturn("192.168.1.10");

        when(userRepository.findByUsername("alice"))
                .thenReturn(Optional.of(user));

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest("valid-session");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verifyNoInteractions(filterChain);
    }

    @Test
    void publicLoginAndMonitoringPostAreNotFiltered() {
        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest loginRequest = new MockHttpServletRequest(
                "POST", "/api/auth/login");

        loginRequest.setServletPath("/api/auth/login");

        MockHttpServletRequest monitoringRequest = new MockHttpServletRequest(
                "POST", "/api/login-attempts");

        monitoringRequest.setServletPath("/api/login-attempts");

        assertTrue(filter.shouldNotFilter(loginRequest));
        assertTrue(filter.shouldNotFilter(monitoringRequest));
    }

    private void assertInvalidRefreshedSession(
            Optional<LoginSession> result, String sessionId) throws Exception {

        when(sessionService.getValidatedSession(sessionId))
                .thenReturn(result);

        SessionAuthenticationFilter filter =
                new SessionAuthenticationFilter(
                        sessionService, userRepository, clientIpAddressExtractor);

        MockHttpServletRequest request = protectedRequest(sessionId);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verifyNoInteractions(userRepository, filterChain);
    }

    private MockHttpServletRequest protectedRequest(String sessionId) {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/api/sessions/active");

        request.setServletPath("/api/sessions/active");
        request.setRemoteAddr("192.168.1.10");

        request.addHeader(SessionAuthenticationFilter.SESSION_HEADER, sessionId);

        return request;
    }

    private LoginSession session(String username, boolean active) {
        LoginSession session = new LoginSession();

        LocalDateTime now = LocalDateTime.now();

        session.setSessionId("valid-session");
        session.setUsername(username);
        session.setIpAddress("192.168.1.10");
        session.setCreatedAt(now.minusMinutes(5));
        session.setLastActivityAt(now);
        session.setExpiresAt(now.plusMinutes(15));
        session.setActive(active);

        return session;
    }

    private User databaseUser(String username, UserRole role, boolean enabled) {
        User user = new User();

        user.setUsername(username);
        user.setPassword("encoded-password");
        user.setRole(role);
        user.setEnabled(enabled);

        return user;
    }

    private String basicAuthorization(String username, String password) {
        String value = username + ":" + password;

        return "Basic " + Base64.getEncoder().encodeToString(
                value.getBytes(StandardCharsets.UTF_8));
    }
}
