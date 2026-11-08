
package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.dto.PublicLoginFailureRequest;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.LoginRateLimiter;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/login-attempts")
public class LoginAttemptController {

    private final LoginService loginService;
    private final LoginRateLimiter loginRateLimiter;
    private final CaptchaService captchaService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public LoginAttemptController(
            LoginService loginService,
            LoginRateLimiter loginRateLimiter,
            CaptchaService captchaService,
            ClientIpAddressExtractor clientIpAddressExtractor) {

        this.loginService = loginService;
        this.loginRateLimiter = loginRateLimiter;
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @PostMapping
    public ResponseEntity<?> recordLoginAttempt(
            @Valid @RequestBody PublicLoginFailureRequest request,
            HttpServletRequest httpRequest) {

        // 1. Extract client IP address
        String clientIp = clientIpAddressExtractor.extract(httpRequest);

        // 2. Check rate limiting
        if (!loginRateLimiter.isAllowed(clientIp)) {
            return ResponseEntity
                    .status(HttpStatus.TOO_MANY_REQUESTS)
                    .build();
        }

        // 3. Check CAPTCHA requirement
        if (captchaService.isCaptchaRequired(clientIp)) {

            if (!captchaService.consumePermission(clientIp)) {

                Map<String, Object> error = new HashMap<>();

                error.put("captchaRequired", true);
                error.put("message",
                        "CAPTCHA verification is required before another login attempt");

                return ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(error);
            }
        }

        // 4. Save login attempt
        LoginAttempt savedAttempt = loginService.recordLoginAttempt(
                request.getUsername(),
                clientIp,
                LoginStatus.FAILURE
        );

        // 5. Check CAPTCHA requirement after failed login
        if (savedAttempt.getStatus() == LoginStatus.FAILURE
                && captchaService.isCaptchaRequired(clientIp)) {

            Map<String, Object> response = new HashMap<>();

            response.put("captchaRequired", true);
            response.put("message",
                    "CAPTCHA verification is now required after 5 failed login attempts");
            response.put("loginAttempt", savedAttempt);

            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body(response);
        }

        // 6. Return the normal failure-monitoring response
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(savedAttempt);
    }

    // GET login attempts with optional filters
    @GetMapping
    public ResponseEntity<?> getLoginAttempts(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) LoginStatus status,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        boolean admin = hasAnyRole(authentication, "ROLE_ADMIN", "ROLE_SUPERADMIN");
        if (!admin) {
            if (username != null && !authentication.getName().equals(username)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            username = authentication.getName();
        }

        List<LoginAttempt> attempts = loginService.getLoginAttempts(
                username,
                ipAddress,
                status
        );

        return ResponseEntity.ok(attempts);
    }

    private boolean hasAnyRole(Authentication authentication, String... roles) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }
        for (var authority : authentication.getAuthorities()) {
            for (String role : roles) {
                if (role.equals(authority.getAuthority())) {
                    return true;
                }
            }
        }
        return false;
    }

    // Handle invalid query parameter values
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleTypeMismatch(
            MethodArgumentTypeMismatchException ex) {

        Map<String, Object> error = new HashMap<>();

        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");

        error.put("message", String.format(
                "Invalid value '%s' for parameter '%s'. Allowed values for status are: SUCCESS, FAILURE",
                ex.getValue(),
                ex.getName()
        ));

        return ResponseEntity.badRequest().body(error);
    }
}
