package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.pratik.loginmonitor.dto.CaptchaChallengeResponse;
import com.pratik.loginmonitor.dto.CaptchaVerificationRequest;
import com.pratik.loginmonitor.service.CaptchaService;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
class CaptchaControllerTest {

    @Mock
    private CaptchaService captchaService;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @InjectMocks
    private CaptchaController captchaController;

    @Test
    @DisplayName("Should generate a challenge for the server-detected IP")
    void challengeUsesServerDetectedIp() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.10");
        CaptchaChallengeResponse challenge = new CaptchaChallengeResponse(
                "secure-token", "What is 10 + 20?", Instant.parse("2026-01-01T00:02:00Z"));
        when(captchaService.generateChallenge("10.0.0.10")).thenReturn(challenge);

        ResponseEntity<CaptchaChallengeResponse> response =
                captchaController.generateChallenge(httpRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(challenge, response.getBody());
        verify(captchaService).generateChallenge("10.0.0.10");
    }

    @Test
    @DisplayName("Should verify a challenge using the server-detected IP")
    void verificationUsesServerDetectedIp() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.11");
        when(captchaService.verifyChallenge("10.0.0.11", "secure-token", 30)).thenReturn(true);

        ResponseEntity<Map<String, Object>> response = captchaController.verifyChallenge(
                new CaptchaVerificationRequest("secure-token", 30), httpRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Boolean) response.getBody().get("verified"));
        verify(captchaService).verifyChallenge("10.0.0.11", "secure-token", 30);
    }

    @Test
    @DisplayName("Should return a clear failure response for failed verification")
    void verificationFailureUsesBadRequest() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.12");
        when(captchaService.verifyChallenge("10.0.0.12", "bad-token", 99)).thenReturn(false);

        ResponseEntity<Map<String, Object>> response = captchaController.verifyChallenge(
                new CaptchaVerificationRequest("bad-token", 99), httpRequest);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertFalse((Boolean) response.getBody().get("verified"));
    }
}
