
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
import com.pratik.loginmonitor.dto.LoginAttemptResponse;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.DetectionService;
import com.pratik.loginmonitor.service.LoginRateLimiter;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping
public class LoginAttemptController {

    private final LoginService loginService;
    private final LoginRateLimiter loginRateLimiter;
    private final CaptchaService captchaService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;
    private final DetectionService detectionService;

    public LoginAttemptController(
            LoginService loginService,
            LoginRateLimiter loginRateLimiter,
            CaptchaService captchaService,
            ClientIpAddressExtractor clientIpAddressExtractor,
            DetectionService detectionService) {

        this.loginService = loginService;
        this.loginRateLimiter = loginRateLimiter;
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
        this.detectionService = detectionService;
    }

    @PostMapping({"/login", "/api/login", "/api/login-attempts"})
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

        // 3. Save login attempt after the CAPTCHA filter has validated any required challenge.
        LoginAttempt savedAttempt = loginService.recordLoginAttempt(
                request.getUsername(),
                clientIp,
                request.getStatus()
        );
        LoginAttemptResponse responseAttempt = toResponse(savedAttempt);

        // 4. Run suspicious-activity detection (handles both SUCCESS and FAILURE branches).
        detectionService.checkSuspiciousActivity(savedAttempt);

        // Check whether the next login submission will require CAPTCHA.
        if (savedAttempt.getStatus() == LoginStatus.FAILURE
                && captchaService.isCaptchaRequired(clientIp)) {

            Map<String, Object> response = new HashMap<>();

            response.put("captchaRequired", true);
            response.put("message",
                    "CAPTCHA verification is now required after 5 failed login attempts");
            response.put("loginAttempt", responseAttempt);

            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body(response);
        }

        // 6. Return the normal failure-monitoring response
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(responseAttempt);
    }

    // GET login attempts with optional filters
    @GetMapping({"/login", "/api/login", "/api/login-attempts"})
    public ResponseEntity<?> getLoginAttempts(
            @RequestParam(required = false) String username,
            @RequestParam(name = "ip_address", required = false) String ipAddressSnake,
            @RequestParam(name = "ipAddress", required = false) String ipAddressCamel,
            @RequestParam(required = false) LoginStatus status,
            Authentication authentication) {

        String ipAddress = (ipAddressSnake != null && !ipAddressSnake.isBlank())
                ? ipAddressSnake
                : ipAddressCamel;

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

        List<LoginAttemptResponse> responses =
                attempts.stream().map(this::toResponse).toList();

        return ResponseEntity.ok(responses);
    }

    public ResponseEntity<?> getLoginAttempts(
            String username,
            String ipAddress,
            LoginStatus status,
            Authentication authentication) {
        return getLoginAttempts(username, ipAddress, null, status, authentication);
    }

    private LoginAttemptResponse toResponse(LoginAttempt attempt) {
        return new LoginAttemptResponse(
                attempt.getId(),
                attempt.getUsername(),
                attempt.getIpAddress(),
                attempt.getAttemptTime(),
                attempt.getStatus());
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
