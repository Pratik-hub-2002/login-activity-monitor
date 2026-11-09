package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import com.pratik.loginmonitor.service.CaptchaService;

import jakarta.servlet.http.HttpServletRequest;

class CaptchaControllerTest {

    @Test
    void captchaConfigReturnsRequiredStatusAndPublicSiteKey() {
        CaptchaService captchaService = mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor = mock(ClientIpAddressExtractor.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(ipExtractor.extract(request)).thenReturn("192.0.2.10");
        when(captchaService.isCaptchaRequired("192.0.2.10")).thenReturn(true);

        CaptchaController controller =
                new CaptchaController(captchaService, ipExtractor, "site-key");
        ResponseEntity<Map<String, Object>> response =
                controller.getCaptchaConfig(request);

        assertEquals(200, response.getStatusCode().value());
        assertTrue((Boolean) response.getBody().get("required"));
        assertEquals("site-key", response.getBody().get("siteKey"));
        assertEquals(2, response.getBody().size());
    }

    @Test
    void captchaConfigDoesNotRequireChallengeBelowThreshold() {
        CaptchaService captchaService = mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor = mock(ClientIpAddressExtractor.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(ipExtractor.extract(request)).thenReturn("192.0.2.11");
        when(captchaService.isCaptchaRequired("192.0.2.11")).thenReturn(false);

        CaptchaController controller =
                new CaptchaController(captchaService, ipExtractor, "site-key");
        ResponseEntity<Map<String, Object>> response =
                controller.getCaptchaConfig(request);

        assertFalse((Boolean) response.getBody().get("required"));
    }
}
