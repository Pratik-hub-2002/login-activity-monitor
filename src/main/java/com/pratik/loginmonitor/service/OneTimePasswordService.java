package com.pratik.loginmonitor.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

@Service
public class OneTimePasswordService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(OneTimePasswordService.class);

    private final GoogleAuthenticator authenticator;
    private final NotificationEmailService emailService;
    private final Clock clock;
    private final Duration validity;
    private final ConcurrentHashMap<String, PendingOtp> pendingOtps =
            new ConcurrentHashMap<>();

    public OneTimePasswordService(
            GoogleAuthenticator authenticator,
            NotificationEmailService emailService,
            Clock clock,
            @Value("${app.auth.otp.validity-seconds:90}") long validitySeconds) {
        if (validitySeconds <= 0) {
            throw new IllegalArgumentException("OTP validity must be positive");
        }
        this.authenticator = authenticator;
        this.emailService = emailService;
        this.clock = clock;
        this.validity = Duration.ofSeconds(validitySeconds);
    }

    public void sendOtp(String username, String ipAddress, String emailAddress) {
        if (emailAddress == null || emailAddress.isBlank()) {
            throw new OtpDeliveryException("No email recipient is configured for this user.");
        }

        GoogleAuthenticatorKey credentials = authenticator.createCredentials();
        int code = authenticator.getTotpPassword(
                credentials.getKey(), clock.millis());
        String otp = String.format(Locale.ROOT, "%06d", code);
        String challengeKey = challengeKey(username, ipAddress);
        Instant now = clock.instant();
        pendingOtps.entrySet().removeIf(
                entry -> !entry.getValue().expiresAt().isAfter(now));
        PendingOtp pending = new PendingOtp(
                credentials.getKey(), now.plus(validity));
        pendingOtps.put(challengeKey, pending);

        try {
            emailService.sendOneTimePassword(username, emailAddress, otp);
        } catch (MailException exception) {
            pendingOtps.remove(challengeKey, pending);
            LOGGER.error("Could not deliver a login OTP to the configured recipient.",
                    exception);
            throw new OtpDeliveryException("Unable to deliver the login verification code.");
        }
    }

    public boolean verifyOtp(String username, String ipAddress, String otp) {
        if (otp == null || !otp.matches("\\d{6}")) {
            return false;
        }

        String challengeKey = challengeKey(username, ipAddress);
        Instant now = clock.instant();
        AtomicBoolean verified = new AtomicBoolean();
        pendingOtps.compute(challengeKey, (key, pending) -> {
            if (pending == null) {
                return null;
            }
            if (!pending.expiresAt().isAfter(now)) {
                return null;
            }

            boolean valid = authenticator.authorize(
                    pending.secret(), Integer.parseInt(otp), now.toEpochMilli());
            if (valid) {
                verified.set(true);
                return null;
            }
            return pending;
        });
        return verified.get();
    }

    private String challengeKey(String username, String ipAddress) {
        return username + "\u0000" + ipAddress;
    }

    private record PendingOtp(String secret, Instant expiresAt) {
    }

    public static class OtpDeliveryException extends RuntimeException {
        public OtpDeliveryException(String message) {
            super(message);
        }
    }
}
