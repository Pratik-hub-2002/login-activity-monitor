
package com.pratik.loginmonitor.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.repository.UserRepository;
import com.pratik.loginmonitor.service.SessionService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

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
            UserRepository userRepository,
            ClientIpAddressExtractor clientIpAddressExtractor) {

        this.sessionService = sessionService;
        this.userRepository = userRepository;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = getRequestPath(request);

        if (HttpMethod.POST.matches(request.getMethod())) {
            return path.equals("/api/auth/login")
                    || path.equals("/api/auth/otp/verify")
                    || path.equals("/api/login-attempts")
                    || path.equals("/login")
                    || path.equals("/api/login");
        }

        return path.startsWith("/api/captcha/");
    }

    private String getRequestPath(HttpServletRequest request) {

        String path = request.getServletPath();

        if (path == null || path.isBlank()) {
            path = request.getRequestURI();

            String contextPath = request.getContextPath();

            if (contextPath != null
                    && !contextPath.isEmpty()
                    && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }
        }

        return path;
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

        sessionId = sessionId.trim();

        Optional<LoginSession> validatedSession =
                sessionService.getValidatedSession(sessionId);

        if (validatedSession.isEmpty()) {
            reject(response, "Missing or invalid session");
            return;
        }

        LoginSession session = validatedSession.get();

        // Optional Basic username check.
        // The session ID remains the actual authentication mechanism.
        String basicUsername = extractBasicUsername(request);

        if (basicUsername != null
                && !basicUsername.equals(session.getUsername())) {
            reject(response,
                    "Session does not belong to the authenticated user");
            return;
        }

        String requestIp = clientIpAddressExtractor.extract(request);

        // Validate the IP associated with the session.
        if (requestIp != null
                && !requestIp.isBlank()
                && session.getIpAddress() != null
                && !session.getIpAddress().isBlank()
                && !requestIp.equals(session.getIpAddress())) {

            reject(response,
                    "Session does not belong to this client IP");
            return;
        }

        Optional<User> optionalUser =
                userRepository.findByUsername(session.getUsername());

        if (optionalUser.isEmpty() || !optionalUser.get().isEnabled()) {
            reject(response, "Invalid session user");
            return;
        }

        User user = optionalUser.get();

        // Refresh the session after successful validation.
        Optional<LoginSession> refreshedSession =
                sessionService.refreshSession(
                        sessionId,
                        requestIp,
                        session.getUsername());

        if (refreshedSession.isEmpty()) {
            reject(response, "Missing or invalid session");
            return;
        }

        UserDetails details =
                org.springframework.security.core.userdetails.User
                        .builder()
                        .username(user.getUsername())
                        .password(user.getPassword())
                        .authorities(
                                new SimpleGrantedAuthority(
                                        "ROLE_" + user.getRole().name()))
                        .disabled(false)
                        .build();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        details,
                        null,
                        details.getAuthorities());

        authentication.setDetails(
                authenticationDetailsSource.buildDetails(request));

        SecurityContextHolder.getContext()
                .setAuthentication(authentication);

        // Prevent downstream BasicAuthenticationFilter from attempting
        // a second authentication using the Authorization header.
        HttpServletRequest wrappedRequest =
                new AuthorizationHeaderSuppressingRequest(request);

        filterChain.doFilter(wrappedRequest, response);
    }

    private void reject(
            HttpServletResponse response,
            String message) throws IOException {

        SecurityContextHolder.clearContext();

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        response.getWriter().write(
                "{\"message\":\"" + message + "\"}");
    }

    private String extractBasicUsername(HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization == null
                || !authorization.regionMatches(
                        true, 0, "Basic ", 0, 6)) {
            return null;
        }

        try {
            String encodedCredentials =
                    authorization.substring(6).trim();

            String credentials = new String(
                    Base64.getDecoder().decode(encodedCredentials),
                    StandardCharsets.UTF_8);

            int separator = credentials.indexOf(':');

            if (separator <= 0) {
                return null;
            }

            return credentials.substring(0, separator);

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
        public Enumeration<String> getHeaders(String name) {

            if ("Authorization".equalsIgnoreCase(name)) {
                return Collections.emptyEnumeration();
            }

            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {

            return Collections.enumeration(
                    Collections.list(super.getHeaderNames())
                            .stream()
                            .filter(name ->
                                    !"Authorization".equalsIgnoreCase(name))
                            .collect(Collectors.toList()));
        }
    }
}
