package com.pratik.loginmonitor.service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.dto.CaptchaChallengeResponse;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

@Service
public class CaptchaService {

    private static final int CAPTCHA_FAILURE_THRESHOLD = 5;
    private static final Duration FAILURE_WINDOW = Duration.ofMinutes(10);
    private static final Duration CHALLENGE_DURATION = Duration.ofMinutes(2);
    private static final Duration PERMISSION_DURATION = Duration.ofMinutes(5);

    private final LoginAttemptRepository loginAttemptRepository;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ConcurrentHashMap<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, VerificationPermission> permissions = new ConcurrentHashMap<>();

    public CaptchaService(LoginAttemptRepository loginAttemptRepository, Clock clock) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.clock = clock;
    }

    public boolean isCaptchaRequired(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }

        LocalDateTime windowStart = LocalDateTime.now(clock).minusMinutes(FAILURE_WINDOW.toMinutes());
        long failures = loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                ipAddress,
                LoginStatus.FAILURE,
                windowStart
        );

        return failures >= CAPTCHA_FAILURE_THRESHOLD;
    }

    public CaptchaChallengeResponse generateChallenge(String ipAddress) {
        int firstNumber = secureRandom.nextInt(99) + 1;
        int secondNumber = secureRandom.nextInt(99) + 1;
        boolean useAddition = secureRandom.nextBoolean();

        String question;
        int answer;
        if (useAddition) {
            question = "What is " + firstNumber + " + " + secondNumber + "?";
            answer = firstNumber + secondNumber;
        } else {
            int larger = Math.max(firstNumber, secondNumber);
            int smaller = Math.min(firstNumber, secondNumber);
            question = "What is " + larger + " - " + smaller + "?";
            answer = larger - smaller;
        }

        String token = generateSecureToken();
        Instant expiresAt = clock.instant().plus(CHALLENGE_DURATION);
        challenges.put(ipAddress, new Challenge(token, answer, expiresAt));

        return new CaptchaChallengeResponse(token, question, expiresAt);
    }

    public boolean verifyChallenge(String ipAddress, String token, Integer answer) {
        if (ipAddress == null || token == null || answer == null) {
            return false;
        }

        Instant now = clock.instant();
        final boolean[] verified = {false};

        challenges.compute(ipAddress, (key, challenge) -> {
            if (challenge == null || !challenge.expiresAt().isAfter(now)) {
                return null;
            }
            if (!challenge.token().equals(token) || challenge.answer() != answer.intValue()) {
                return challenge;
            }

            permissions.put(ipAddress, new VerificationPermission(now.plus(PERMISSION_DURATION)));
            verified[0] = true;
            return null;
        });

        return verified[0];
    }

    public boolean consumePermission(String ipAddress) {
        if (ipAddress == null) {
            return false;
        }

        Instant now = clock.instant();
        final boolean[] consumed = {false};

        permissions.compute(ipAddress, (key, permission) -> {
            if (permission == null || !permission.expiresAt().isAfter(now)) {
                return null;
            }

            consumed[0] = true;
            return null;
        });

        return consumed[0];
    }

    private String generateSecureToken() {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    private record Challenge(String token, int answer, Instant expiresAt) {
    }

    private record VerificationPermission(Instant expiresAt) {
    }
}
