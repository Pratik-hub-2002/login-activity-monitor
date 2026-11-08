package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class LoginRateLimiterTest {

    @Test
    @DisplayName("Should allow the first five requests from an IP address")
    void firstFiveRequestsAreAllowed() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(clock);

        for (int request = 0; request < 5; request++) {
            assertTrue(limiter.isAllowed("192.168.1.10"));
        }
    }

    @Test
    @DisplayName("Should block the sixth request from an IP address within the window")
    void sixthRequestIsBlocked() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(clock);

        for (int request = 0; request < 5; request++) {
            limiter.isAllowed("192.168.1.10");
        }

        assertFalse(limiter.isAllowed("192.168.1.10"));
    }

    @Test
    @DisplayName("Should allow requests again after the 60-second window expires")
    void requestsAreAllowedAfterWindowExpiration() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(clock);

        for (int request = 0; request < 5; request++) {
            limiter.isAllowed("192.168.1.10");
        }
        assertFalse(limiter.isAllowed("192.168.1.10"));

        clock.advance(Duration.ofSeconds(60));

        assertTrue(limiter.isAllowed("192.168.1.10"));
    }

    @Test
    @DisplayName("Should keep rate limits independent for different IP addresses")
    void differentIpAddressesHaveIndependentLimits() {
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(clock);

        for (int request = 0; request < 5; request++) {
            assertTrue(limiter.isAllowed("192.168.1.10"));
        }
        assertFalse(limiter.isAllowed("192.168.1.10"));

        assertTrue(limiter.isAllowed("192.168.1.11"));
        assertTrue(limiter.isAllowed("192.168.1.11"));
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
