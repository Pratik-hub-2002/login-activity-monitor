package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailSendException;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

class OneTimePasswordServiceTest {

    private GoogleAuthenticator authenticator;
    private NotificationEmailService emailService;
    private MutableClock clock;
    private OneTimePasswordService service;

    @BeforeEach
    void setUp() {
        authenticator = mock(GoogleAuthenticator.class);
        emailService = mock(NotificationEmailService.class);
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        GoogleAuthenticatorKey credentials = mock(GoogleAuthenticatorKey.class);
        when(authenticator.createCredentials()).thenReturn(credentials);
        when(credentials.getKey()).thenReturn("test-secret");
        when(authenticator.getTotpPassword("test-secret", clock.millis()))
                .thenReturn(123456);
        service = new OneTimePasswordService(
                authenticator, emailService, clock, 90);
    }

    @Test
    void sendsOtpAndConsumesItAfterSuccessfulVerification() {
        when(authenticator.authorize(
                "test-secret", 123456, clock.millis())).thenReturn(true);
        service.sendOtp("alice", "192.0.2.1", "alice@example.test");

        verify(emailService).sendOneTimePassword(
                "alice", "alice@example.test", "123456");
        assertTrue(service.verifyOtp("alice", "192.0.2.1", "123456"));
        assertFalse(service.verifyOtp("alice", "192.0.2.1", "123456"));
    }

    @Test
    void rejectsInvalidOtpWithoutCreatingSessionState() {
        when(authenticator.authorize(
                "test-secret", 654321, clock.millis())).thenReturn(false);
        service.sendOtp("alice", "192.0.2.1", "alice@example.test");

        assertFalse(service.verifyOtp("alice", "192.0.2.1", "654321"));
    }

    @Test
    void rejectsExpiredOtp() {
        service.sendOtp("alice", "192.0.2.1", "alice@example.test");
        clock.advance(Duration.ofSeconds(90));

        assertFalse(service.verifyOtp("alice", "192.0.2.1", "123456"));
    }

    @Test
    void challengeIsBoundToUsernameAndIpAddress() {
        when(authenticator.authorize(
                "test-secret", 123456, clock.millis())).thenReturn(true);
        service.sendOtp("alice", "192.0.2.1", "alice@example.test");

        assertFalse(service.verifyOtp("alice", "192.0.2.2", "123456"));
        assertFalse(service.verifyOtp("bob", "192.0.2.1", "123456"));
        assertTrue(service.verifyOtp("alice", "192.0.2.1", "123456"));
    }

    @Test
    void doesNotRetainOtpWhenEmailDeliveryFails() {
        doThrow(new MailSendException("mail unavailable"))
                .when(emailService)
                .sendOneTimePassword("alice", "alice@example.test", "123456");

        assertThrows(
                OneTimePasswordService.OtpDeliveryException.class,
                () -> service.sendOtp("alice", "192.0.2.1", "alice@example.test"));
        assertFalse(service.verifyOtp("alice", "192.0.2.1", "123456"));
    }

    @Test
    void requiresConfiguredRecipient() {
        assertThrows(
                OneTimePasswordService.OtpDeliveryException.class,
                () -> service.sendOtp("alice", "192.0.2.1", null));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
    }
}
