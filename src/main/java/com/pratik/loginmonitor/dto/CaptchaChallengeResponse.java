package com.pratik.loginmonitor.dto;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CaptchaChallengeResponse {

    private String captchaToken;
    private String question;
    private Instant expiresAt;
}
