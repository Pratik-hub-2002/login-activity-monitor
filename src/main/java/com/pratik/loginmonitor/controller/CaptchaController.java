package com.pratik.loginmonitor.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pratik.loginmonitor.service.CaptchaService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/captcha")
public class CaptchaController {

    private final CaptchaService captchaService;
    private final ClientIpAddressExtractor clientIpAddressExtractor;
    private final String siteKey;

    public CaptchaController(
            CaptchaService captchaService,
            ClientIpAddressExtractor clientIpAddressExtractor,
            @Value("${app.captcha.hcaptcha.site-key:}") String siteKey) {
        this.captchaService = captchaService;
        this.clientIpAddressExtractor = clientIpAddressExtractor;
        this.siteKey = siteKey;
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getCaptchaConfig(
            HttpServletRequest request) {
        String ipAddress = clientIpAddressExtractor.extract(request);
        return ResponseEntity.ok(Map.of(
                "required", captchaService.isCaptchaRequired(ipAddress),
                "siteKey", siteKey));
    }
}
