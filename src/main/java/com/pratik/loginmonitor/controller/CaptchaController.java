package com.pratik.loginmonitor.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pratik.loginmonitor.dto.CaptchaChallengeResponse;
import com.pratik.loginmonitor.dto.CaptchaVerificationRequest;
import com.pratik.loginmonitor.service.CaptchaService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/captcha")
public class CaptchaController {

    private final CaptchaService captchaService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;

    public CaptchaController(CaptchaService captchaService,
                             ClientIpAddressExtractor clientIpAddressExtractor) {
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
    }

    @PostMapping("/challenge")
    public ResponseEntity<CaptchaChallengeResponse> generateChallenge(HttpServletRequest httpRequest) {
        String clientIp = clientIpAddressExtractor.extract(httpRequest);
        CaptchaChallengeResponse response = captchaService.generateChallenge(clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyChallenge(
            @Valid @RequestBody CaptchaVerificationRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = clientIpAddressExtractor.extract(httpRequest);
        boolean verified = captchaService.verifyChallenge(
                clientIp,
                request.getCaptchaToken(),
                request.getAnswer()
        );

        Map<String, Object> response = new HashMap<>();
        response.put("verified", verified);
        response.put("message", verified
                ? "CAPTCHA verified. One subsequent login attempt is allowed."
                : "CAPTCHA verification failed or the challenge has expired.");

        if (verified) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
