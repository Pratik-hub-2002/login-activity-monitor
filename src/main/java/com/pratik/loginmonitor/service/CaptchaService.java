package com.pratik.loginmonitor.service;

import java.time.Clock;
import java.time.LocalDateTime;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

@Service
public class CaptchaService {

    private static final int CAPTCHA_FAILURE_THRESHOLD = 5;
    private static final int FAILURE_WINDOW_MINUTES = 10;

    private final LoginAttemptRepository loginAttemptRepository;
    private final HcaptchaVerifier hcaptchaVerifier;
    private final Clock clock;
    private final boolean captchaRequired;

    public CaptchaService(
            LoginAttemptRepository loginAttemptRepository,
            HcaptchaVerifier hcaptchaVerifier,
            Clock clock,
            @Value("${app.captcha.hcaptcha.required:false}") boolean captchaRequired) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.hcaptchaVerifier = hcaptchaVerifier;
        this.clock = clock;
        this.captchaRequired = captchaRequired;
    }

    public boolean isCaptchaRequired(String ipAddress) {
        if (captchaRequired) {
            return true;
        }
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }

        LocalDateTime windowStart =
                LocalDateTime.now(clock).minusMinutes(FAILURE_WINDOW_MINUTES);
        long failures = loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                ipAddress, LoginStatus.FAILURE, windowStart);
        return failures >= CAPTCHA_FAILURE_THRESHOLD;
    }

    public boolean verifyCaptcha(String ipAddress, String token) {
        return hcaptchaVerifier.verify(token, ipAddress);
    }

}
