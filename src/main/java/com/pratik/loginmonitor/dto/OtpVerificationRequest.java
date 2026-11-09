package com.pratik.loginmonitor.dto;

import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpVerificationRequest {

    @Pattern(regexp = "\\d{6}", message = "OTP must contain six digits")
    private String otp;
}
