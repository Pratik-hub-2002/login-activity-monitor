package com.pratik.loginmonitor.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.pratik.loginmonitor.dto.OtpVerificationRequest;
import com.pratik.loginmonitor.dto.LoginAttemptResponse;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.LoginSession;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;
import com.pratik.loginmonitor.service.OneTimePasswordService;
import com.pratik.loginmonitor.service.OneTimePasswordService.OtpDeliveryException;
import com.pratik.loginmonitor.service.SessionService;

import jakarta.servlet.http.HttpServletRequest;
import com.pratik.loginmonitor.config.SessionAuthenticationFilter;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final LoginService loginService;
    private final SessionService sessionService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;
    private final OneTimePasswordService oneTimePasswordService;

    public AuthController(
            LoginService loginService,
            SessionService sessionService,
            ClientIpAddressExtractor clientIpAddressExtractor,
            OneTimePasswordService oneTimePasswordService) {
        this.loginService = loginService;
        this.sessionService = sessionService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
        this.oneTimePasswordService = oneTimePasswordService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            Authentication authentication,
            HttpServletRequest request) {

        String username = authentication.getName();
        String clientIp = clientIpAddressExtractor.extract(request);
        oneTimePasswordService.sendOtp(username, clientIp);
        return ResponseEntity.accepted().body(Map.of(
                "otpRequired", true,
                "message", "A verification code has been sent to your configured email address."));
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<?> verifyOtp(
            Authentication authentication,
            @Valid @RequestBody OtpVerificationRequest verification,
            HttpServletRequest request) {
        String username = authentication.getName();
        String clientIp = clientIpAddressExtractor.extract(request);
        if (!oneTimePasswordService.verifyOtp(
                username, clientIp, verification.getOtp())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "The verification code is invalid or expired."));
        }

        LoginAttempt attempt = loginService.recordLoginAttempt(
                username, clientIp, LoginStatus.SUCCESS);
        LoginSession session = sessionService.createSession(username, clientIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "loginAttempt", new LoginAttemptResponse(
                        attempt.getId(),
                        attempt.getUsername(),
                        attempt.getIpAddress(),
                        attempt.getAttemptTime(),
                        attempt.getStatus()),
                "session", Map.of(
                        "sessionId", session.getSessionId(),
                        "createdAt", session.getCreatedAt(),
                        "expiresAt", session.getExpiresAt()),
                "role", getRole(authentication)));
    }

    @ExceptionHandler(OtpDeliveryException.class)
    public ResponseEntity<Map<String, String>> otpDeliveryFailed(
            OtpDeliveryException exception) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("message", exception.getMessage()));
    }

    private String getRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Authenticated user has no assigned role."));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(SessionAuthenticationFilter.SESSION_HEADER)
            String sessionId,
            Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if (!sessionService.logout(sessionId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return ResponseEntity.ok(Map.of(
                "message", "Session logged out successfully"));
    }
}
