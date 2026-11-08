package com.pratik.loginmonitor.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CaptchaVerificationRequest {

    private String captchaToken;
    private Integer answer;
}
