package com.pratik.loginmonitor.config;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class DatabaseAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String RECORDING_ATTRIBUTE =
            DatabaseAuthenticationEntryPoint.class.getName() + ".failureRecorded";

    private final LoginService loginService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public DatabaseAuthenticationEntryPoint(
            LoginService loginService,
            ClientIpAddressExtractor clientIpAddressExtractor) {
        this.loginService = loginService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) {

        if (request.getAttribute(RECORDING_ATTRIBUTE) == null) {
            request.setAttribute(RECORDING_ATTRIBUTE, true);
            String username = extractBasicUsername(request);

            if (username != null && !username.isBlank()) {
                String clientIp = clientIpAddressExtractor.extract(request);
                try {
                    loginService.recordLoginAttempt(
                            username, clientIp, LoginStatus.FAILURE);
                } catch (RuntimeException ignored) {
                    // Authentication still returns the same generic 401 response.
                }
            }
        }

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try {
            response.getWriter().write("{\"message\":\"Authentication required\"}");
        } catch (Exception ignored) {
            // The status is already set and must not leak credential details.
        }
    }

    private String extractBasicUsername(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null
                || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }

        String encoded = authorization.substring(6).trim();
        if (encoded.isEmpty()) {
            return null;
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            String credentials = new String(decoded, StandardCharsets.UTF_8);
            int separator = credentials.indexOf(':');
            if (separator < 0) {
                return null;
            }

            String username = credentials.substring(0, separator);
            return username.isBlank() ? null : username;
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }
}
