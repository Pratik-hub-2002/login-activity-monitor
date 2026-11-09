package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

@ExtendWith(MockitoExtension.class)
class CaptchaServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private HcaptchaVerifier hcaptchaVerifier;

    @Test
    void captchaIsNotRequiredBeforeFiveRecentFailures() {
        CaptchaService service = service();
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq("192.0.2.1"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(4L);

        assertFalse(service.isCaptchaRequired("192.0.2.1"));
    }

    @Test
    void captchaIsRequiredAtFiveRecentFailures() {
        CaptchaService service = service();
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq("192.0.2.1"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(5L);

        assertTrue(service.isCaptchaRequired("192.0.2.1"));
    }

    @Test
    void configuredRequiredFlagForcesCaptchaWithoutFailureHistory() {
        CaptchaService service = new CaptchaService(
                loginAttemptRepository,
                hcaptchaVerifier,
                Clock.fixed(Instant.parse("2026-01-01T00:30:00Z"), ZoneOffset.UTC),
                true);

        assertTrue(service.isCaptchaRequired("192.0.2.1"));
    }

    @Test
    void onlyFailuresWithinTenMinuteWindowAreCounted() {
        CaptchaService service = service();
        Clock clock = Clock.fixed(
                Instant.parse("2026-01-01T00:30:00Z"), ZoneOffset.UTC);
        service = new CaptchaService(loginAttemptRepository, hcaptchaVerifier, clock, false);
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq("192.0.2.1"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(0L);

        assertFalse(service.isCaptchaRequired("192.0.2.1"));
        verify(loginAttemptRepository).countByIpAddressAndStatusAndAttemptTimeAfter(
                "192.0.2.1", LoginStatus.FAILURE,
                LocalDateTime.of(2026, 1, 1, 0, 20));
    }

    @Test
    void differentIpsHaveIndependentFailureThresholds() {
        CaptchaService service = service();
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq("192.0.2.1"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(5L);
        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeAfter(
                eq("192.0.2.2"), eq(LoginStatus.FAILURE), any(LocalDateTime.class)))
                .thenReturn(1L);

        assertTrue(service.isCaptchaRequired("192.0.2.1"));
        assertFalse(service.isCaptchaRequired("192.0.2.2"));
    }

    @Test
    void invalidProviderTokenIsRejected() {
        CaptchaService service = service();
        when(hcaptchaVerifier.verify("invalid-token", "192.0.2.1"))
                .thenReturn(false);

        assertFalse(service.verifyCaptcha("192.0.2.1", "invalid-token"));
    }

    @Test
    void validProviderTokenIsAccepted() {
        CaptchaService service = service();
        when(hcaptchaVerifier.verify("valid-token", "192.0.2.1"))
                .thenReturn(true);

        assertTrue(service.verifyCaptcha("192.0.2.1", "valid-token"));
    }

    private CaptchaService service() {
        return new CaptchaService(
                loginAttemptRepository,
                hcaptchaVerifier,
                Clock.fixed(Instant.parse("2026-01-01T00:30:00Z"), ZoneOffset.UTC),
                false);
    }
}
