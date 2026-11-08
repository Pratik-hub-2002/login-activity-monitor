package com.pratik.loginmonitor.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.repository.UserRepository;
import com.pratik.loginmonitor.service.SessionService;
import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequestWrapper;

@Component
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    public static final String SESSION_HEADER = "X-Session-Id";

    private final SessionService sessionService;
    private final UserRepository userRepository;
    private final ClientIpAddressExtractor clientIpAddressExtractor;
    private final WebAuthenticationDetailsSource authenticationDetailsSource =
            new WebAuthenticationDetailsSource();

    public SessionAuthenticationFilter(
            SessionService sessionService,
            UserRepository userRepository) {
        this(sessionService, userRepository, new ClientIpAddressExtractor());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SessionAuthenticationFilter(
            SessionService sessionService,
            UserRepository userRepository,
            ClientIpAddressExtractor clientIpAddressExtractor) {
        this.sessionService = sessionService;
        this.userRepository = userRepository;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (HttpMethod.POST.matches(request.getMethod())
                && "/api/auth/login".equals(path)) {
            return true;
        }
        if (HttpMethod.POST.matches(request.getMethod())
                && "/api/login-attempts".equals(path)) {
            return true;
        }
        return path.startsWith("/api/captcha/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String sessionId = request.getHeader(SESSION_HEADER);
        if (sessionId == null || sessionId.isBlank()) {
            reject(response, "Missing or invalid session");
            return;
        }

        Optional<LoginSession> validatedSession =
                sessionService.getValidatedSession(sessionId.trim());
        if (validatedSession.isEmpty()) {
            reject(response, "Missing or invalid session");
            return;
        }

        LoginSession session = validatedSession.get();
        String basicUsername = extractBasicUsername(request);
        if (basicUsername != null
                && !basicUsername.equals(session.getUsername())) {
            reject(response, "Session does not belong to the authenticated user");
            return;
        }

        String requestIp = clientIpAddressExtractor.extract(request);
        if (requestIp != null
                && !requestIp.isBlank()
                && session.getIpAddress() != null
                && !requestIp.equals(session.getIpAddress())) {
            reject(response, "Session does not belong to this client IP");
            return;
        }

        Optional<com.pratik.loginmonitor.entity.User> user =
                userRepository.findByUsername(session.getUsername());
        if (user.isEmpty() || !user.get().isEnabled()) {
            reject(response, "Invalid session user");
            return;
        }

        Optional<LoginSession> refreshedSession =
                sessionService.refreshSession(
                        sessionId.trim(), requestIp, session.getUsername());
        if (refreshedSession.isEmpty()) {
            reject(response, "Missing or invalid session");
            return;
        }

        UserDetails details = org.springframework.security.core.userdetails.User.builder()
                .username(user.get().getUsername())
                .password(user.get().getPassword())
                .authorities(new SimpleGrantedAuthority(
                        "ROLE_" + user.get().getRole().name()))
                .disabled(false)
                .build();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        details, null, details.getAuthorities());
        authentication.setDetails(
                authenticationDetailsSource.buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(
                new AuthorizationHeaderSuppressingRequest(request),
                response);
    }

    private void reject(HttpServletResponse response, String message) throws IOException {
        SecurityContextHolder.clearContext();
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"message\":\"" + message + "\"}");
    }

    private String extractBasicUsername(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null
                || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }

        try {
            String credentials = new String(
                    Base64.getDecoder().decode(
                            authorization.substring(6).trim()),
                    StandardCharsets.UTF_8);
            int separator = credentials.indexOf(':');
            return separator < 0
                    ? null
                    : credentials.substring(0, separator);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static class AuthorizationHeaderSuppressingRequest
            extends HttpServletRequestWrapper {

        private AuthorizationHeaderSuppressingRequest(
                HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return null;
            }
            return super.getHeader(name);
        }

        @Override
        public java.util.Enumeration<String> getHeaders(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return java.util.Collections.emptyEnumeration();
            }
            return super.getHeaders(name);
        }

        @Override
        public java.util.Enumeration<String> getHeaderNames() {
            return super.getHeaderNames();
        }
    }
}
