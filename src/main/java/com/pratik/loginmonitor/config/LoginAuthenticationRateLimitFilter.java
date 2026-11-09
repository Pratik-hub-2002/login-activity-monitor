package com.pratik.loginmonitor.config;

import java.io.IOException;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.service.LoginRateLimiter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoginAuthenticationRateLimitFilter extends OncePerRequestFilter {

    private final LoginRateLimiter loginRateLimiter;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public LoginAuthenticationRateLimitFilter(
            LoginRateLimiter loginRateLimiter,
            ClientIpAddressExtractor clientIpAddressExtractor) {
        this.loginRateLimiter = loginRateLimiter;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!HttpMethod.POST.matches(request.getMethod())) {
            return true;
        }
        String path = getRequestPath(request);
        return !"/api/auth/login".equals(path)
                && !"/api/auth/otp/verify".equals(path);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String ipAddress = clientIpAddressExtractor.extract(request);
        if (!loginRateLimiter.isAllowed(ipAddress)) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"message\":\"Too many login requests. Please try again later.\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private String getRequestPath(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path == null || path.isBlank()) {
            path = request.getRequestURI();
            String contextPath = request.getContextPath();
            if (contextPath != null && !contextPath.isEmpty()
                    && path.startsWith(contextPath)) {
                path = path.substring(contextPath.length());
            }
        }
        return path;
    }
}
