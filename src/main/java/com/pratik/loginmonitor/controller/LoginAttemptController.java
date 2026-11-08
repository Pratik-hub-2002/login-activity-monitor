package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.dto.LoginRequest;
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

    public LoginAttemptController(LoginService loginService, LoginRateLimiter loginRateLimiter,
                                  CaptchaService captchaService,
                                  ClientIpAddressExtractor clientIpAddressExtractor) {
        this.loginService = loginService;
        this.loginRateLimiter = loginRateLimiter;
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @PostMapping
    public ResponseEntity<?> recordLoginAttempt(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = clientIpAddressExtractor.extract(httpRequest);

        if (!loginRateLimiter.isAllowed(clientIp)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
        }

        if (captchaService.isCaptchaRequired(clientIp)) {
            if (!captchaService.consumePermission(clientIp)) {
                Map<String, Object> error = new HashMap<>();
                error.put("captchaRequired", true);
                error.put("message", "CAPTCHA verification is required before another login attempt");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
            }
        }

        LoginAttempt savedAttempt = loginService.recordLoginAttempt(
                request.getUsername(),
                clientIp,
                request.getStatus()
        );

        if (request.getStatus() == LoginStatus.FAILURE
                && captchaService.isCaptchaRequired(clientIp)) {
            Map<String, Object> response = new HashMap<>();
            response.put("captchaRequired", true);
            response.put("message", "CAPTCHA verification is now required after 5 failed login attempts");
            response.put("loginAttempt", savedAttempt);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(savedAttempt);
    }

    @GetMapping
    public ResponseEntity<List<LoginAttempt>> getLoginAttempts(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) LoginStatus status) {

        List<LoginAttempt> attempts = loginService.getLoginAttempts(username, ipAddress, status);
        return ResponseEntity.ok(attempts);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");
        error.put("message", String.format(
                "Invalid value '%s' for parameter '%s'. Allowed values for status are: SUCCESS, FAILURE",
                ex.getValue(), ex.getName()
        ));
        return ResponseEntity.badRequest().body(error);
    }

}
