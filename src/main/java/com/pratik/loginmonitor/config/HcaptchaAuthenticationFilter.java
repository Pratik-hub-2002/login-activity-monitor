package com.pratik.loginmonitor.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.HcaptchaVerifier.HcaptchaVerificationException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class HcaptchaAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(HcaptchaAuthenticationFilter.class);

    private final CaptchaService captchaService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public HcaptchaAuthenticationFilter(
            CaptchaService captchaService,
            ClientIpAddressExtractor clientIpAddressExtractor) {
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!HttpMethod.POST.matches(request.getMethod())) {
            return true;
        }
        String path = getRequestPath(request);
        return !"/api/auth/login".equals(path)
                && !"/login".equals(path)
                && !"/api/login".equals(path)
                && !"/api/login-attempts".equals(path);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String ipAddress = clientIpAddressExtractor.extract(request);
        if (!captchaService.isCaptchaRequired(ipAddress)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader("X-Captcha-Token");
        try {
            if (captchaService.verifyCaptcha(ipAddress, token)) {
                filterChain.doFilter(request, response);
                return;
            }
        } catch (HcaptchaVerificationException exception) {
            LOGGER.error("The hCaptcha provider could not verify the submitted challenge.",
                    exception);
            reject(response, HttpStatus.SERVICE_UNAVAILABLE,
                    "CAPTCHA verification is temporarily unavailable.");
            return;
        }
        reject(response, HttpStatus.FORBIDDEN,
                "A valid CAPTCHA challenge is required.");
    }

    private void reject(
            HttpServletResponse response, HttpStatus status, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"message\":\"" + message + "\"}");
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
