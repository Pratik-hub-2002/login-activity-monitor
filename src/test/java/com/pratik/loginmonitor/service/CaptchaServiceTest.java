package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.pratik.loginmonitor.dto.CaptchaChallengeResponse;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

@ExtendWith(MockitoExtension.class)
class CaptchaServiceTest {

    private static final String IP_ONE = "192.168.1.10";
    private static final String IP_TWO = "192.168.1.11";

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Test
    @DisplayName("Should not require CAPTCHA when failures are fewer than five")
    void fewerThanFiveFailuresDoesNotRequireCaptcha() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_ONE), eq(LoginStatus.FAILURE), any(LocalDateTime.class))).thenReturn(4L);

        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);

        assertFalse(captchaService.isCaptchaRequired(IP_ONE));
    }

    @Test
    @DisplayName("Should require CAPTCHA at exactly five failures")
    void exactlyFiveFailuresRequiresCaptcha() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_ONE), eq(LoginStatus.FAILURE), any(LocalDateTime.class))).thenReturn(5L);

        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);

        assertTrue(captchaService.isCaptchaRequired(IP_ONE));
    }

    @Test
    @DisplayName("Should count failures only within the last ten minutes")
    void failuresOutsideWindowAreNotCounted() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:30:00Z"));
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_ONE), eq(LoginStatus.FAILURE), any(LocalDateTime.class))).thenReturn(0L);

        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        captchaService.isCaptchaRequired(IP_ONE);

        ArgumentCaptor<LocalDateTime> windowCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(loginAttemptRepository).countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_ONE), eq(LoginStatus.FAILURE), windowCaptor.capture());
        assertEquals(LocalDateTime.of(2026, 1, 1, 0, 20, 0), windowCaptor.getValue());
    }

    @Test
    @DisplayName("Should keep CAPTCHA state independent for different IP addresses")
    void independentIpAddresses() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_ONE), eq(LoginStatus.FAILURE), any(LocalDateTime.class))).thenReturn(5L);
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq(IP_TWO), eq(LoginStatus.FAILURE), any(LocalDateTime.class))).thenReturn(1L);

        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);

        assertTrue(captchaService.isCaptchaRequired(IP_ONE));
        assertFalse(captchaService.isCaptchaRequired(IP_TWO));
    }

    @Test
    @DisplayName("Should verify the correct answer for the correct IP")
    void correctAnswerAndIpVerifies() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);

        assertNotNull(challenge.getCaptchaToken());
        assertTrue(captchaService.verifyChallenge(IP_ONE, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));
        assertTrue(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should reject a wrong answer")
    void wrongAnswerIsRejected() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);
        int wrongAnswer = answerFor(challenge.getQuestion()) + 1;

        assertFalse(captchaService.verifyChallenge(IP_ONE, challenge.getCaptchaToken(), wrongAnswer));
        assertFalse(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should reject a wrong token")
    void wrongTokenIsRejected() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);

        assertFalse(captchaService.verifyChallenge(
                IP_ONE, "wrong-token", answerFor(challenge.getQuestion())));
        assertFalse(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should reject verification from a different IP")
    void wrongIpIsRejected() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);

        assertFalse(captchaService.verifyChallenge(
                IP_TWO, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));
        assertFalse(captchaService.consumePermission(IP_TWO));
    }

    @Test
    @DisplayName("Should expire a challenge after two minutes")
    void challengeExpiresAfterTwoMinutes() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);

        clock.advance(Duration.ofMinutes(2));

        assertFalse(captchaService.verifyChallenge(
                IP_ONE, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));
        assertFalse(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should consume a verification permission exactly once")
    void permissionIsConsumedExactlyOnce() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);
        assertTrue(captchaService.verifyChallenge(
                IP_ONE, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));

        assertTrue(captchaService.consumePermission(IP_ONE));
        assertFalse(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should consume a verification permission only once under concurrent requests")
    void concurrentPermissionConsumptionIsAtomic() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);
        assertTrue(captchaService.verifyChallenge(
                IP_ONE, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger successfulConsumes = new AtomicInteger();
        try {
            for (int i = 0; i < 2; i++) {
                executor.submit(() -> {
                    try {
                        start.await();
                        if (captchaService.consumePermission(IP_ONE)) {
                            successfulConsumes.incrementAndGet();
                        }
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            start.countDown();
        } finally {
            executor.shutdown();
        }

        executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS);
        assertEquals(1, successfulConsumes.get());
    }

    @Test
    @DisplayName("Should expire an unused verification permission after five minutes")
    void permissionExpiresAfterFiveMinutes() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        CaptchaService captchaService = new CaptchaService(loginAttemptRepository, clock);
        CaptchaChallengeResponse challenge = captchaService.generateChallenge(IP_ONE);
        assertTrue(captchaService.verifyChallenge(
                IP_ONE, challenge.getCaptchaToken(), answerFor(challenge.getQuestion())));

        clock.advance(Duration.ofMinutes(5));

        assertFalse(captchaService.consumePermission(IP_ONE));
    }

    @Test
    @DisplayName("Should not expose an answer field in the challenge response")
    void challengeResponseDoesNotExposeAnswer() {
        CaptchaChallengeResponse response = new CaptchaChallengeResponse(
                "token", "What is 2 + 2?", Instant.parse("2026-01-01T00:02:00Z"));
        assertFalse(java.util.Arrays.stream(CaptchaChallengeResponse.class.getDeclaredFields())
                .anyMatch(field -> field.getName().equalsIgnoreCase("answer")));
        assertNotNull(response.getCaptchaToken());
        assertNotNull(response.getQuestion());
    }

    private static int answerFor(String question) {
        Matcher additionCorrect = Pattern.compile("What is (\\d+) \\+ (\\d+)\\?").matcher(question);
        if (additionCorrect.matches()) {
            return Integer.parseInt(additionCorrect.group(1)) + Integer.parseInt(additionCorrect.group(2));
        }

        Matcher subtraction = Pattern.compile("What is (\\d+) - (\\d+)\\?").matcher(question);
        if (subtraction.matches()) {
            return Integer.parseInt(subtraction.group(1)) - Integer.parseInt(subtraction.group(2));
        }

        throw new AssertionError("Unknown CAPTCHA question: " + question);
    }

    private static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
