package com.pratik.loginmonitor.service;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Service
public class HcaptchaVerifier {

    private static final String VERIFY_URL = "https://api.hcaptcha.com/siteverify";
    private static final Logger LOGGER =
            LoggerFactory.getLogger(HcaptchaVerifier.class);

    private final RestClient restClient;
    private final String secret;

    public HcaptchaVerifier(
            RestClient.Builder restClientBuilder,
            @Value("${app.captcha.hcaptcha.secret:}") String secret) {
        this.restClient = restClientBuilder.build();
        this.secret = secret.trim();
        if (this.secret.isBlank()) {
            LOGGER.error("hCaptcha secret is not configured; required challenges will fail closed.");
        }
    }

    public boolean verify(String token, String ipAddress) {
        if (secret.isBlank() || token == null || token.isBlank()) {
            return false;
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secret);
        form.add("response", token);
        if (ipAddress != null && !ipAddress.isBlank()) {
            form.add("remoteip", ipAddress);
        }

        try {
            Map<?, ?> response = restClient.post()
                    .uri(VERIFY_URL)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            return response != null && Boolean.TRUE.equals(response.get("success"));
        } catch (RestClientException exception) {
            throw new HcaptchaVerificationException(
                    "The CAPTCHA provider could not verify the challenge.", exception);
        }
    }

    public static class HcaptchaVerificationException extends RuntimeException {
        public HcaptchaVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
