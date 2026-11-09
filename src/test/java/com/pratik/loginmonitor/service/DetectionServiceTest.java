package com.pratik.loginmonitor.service;

import java.time.LocalDateTime;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.annotation.Scheduled;

import com.pratik.loginmonitor.LoginActivityMonitorApplication;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.scheduling.annotation.EnableScheduling;

@ExtendWith(MockitoExtension.class)
class DetectionServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Mock
    private NotificationEmailService notificationEmailService;

    @InjectMocks
    private DetectionService detectionService;

    @Test
    @DisplayName("Scheduling is enabled and periodic detection is configured every minute")
    void testPeriodicDetectionSchedulingConfiguration() throws Exception {
        assertNotNull(LoginActivityMonitorApplication.class
                .getAnnotation(EnableScheduling.class));
        Scheduled scheduled = DetectionService.class
                .getMethod("runPeriodicDetection")
                .getAnnotation(Scheduled.class);
        assertNotNull(scheduled);
        assertEquals(60_000L, scheduled.fixedRate());
    }

    @Test
    @DisplayName("Periodic detection scans the 10-minute window and invokes detection")
    void testPeriodicDetection_scansRecentAttemptsAndInvokesDetection() {
        Clock fixedClock = Clock.fixed(
                Instant.parse("2026-11-09T12:00:00Z"),
                ZoneOffset.UTC);
        detectionService.setClock(fixedClock);

        LocalDateTime now = LocalDateTime.ofInstant(
                fixedClock.instant(), ZoneOffset.UTC);
        LoginAttempt success = new LoginAttempt(
                101L,
                "periodic-user",
                "192.0.2.10",
                now.minusMinutes(2),
                LoginStatus.SUCCESS);

        when(loginAttemptRepository
                .findByAttemptTimeAfterOrderByAttemptTimeAsc(
                        now.minusMinutes(10)))
                .thenReturn(List.of(success));
        when(suspiciousActivityRepository
                .existsByUsernameAndActivityTypeAndDetectedAtAfter(
                        "periodic-user",
                        SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES,
                        now.minusMinutes(12)))
                .thenReturn(false);
        when(loginAttemptRepository
                .countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                        "periodic-user",
                        LoginStatus.FAILURE,
                        now.minusMinutes(12),
                        now.minusMinutes(2)))
                .thenReturn(3L);
        when(suspiciousActivityRepository.save(any(SuspiciousActivity.class)))
                        .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.runPeriodicDetection();

        ArgumentCaptor<LocalDateTime> windowCaptor =
                ArgumentCaptor.forClass(LocalDateTime.class);
        verify(loginAttemptRepository)
                .findByAttemptTimeAfterOrderByAttemptTimeAsc(
                        windowCaptor.capture());
        assertEquals(now.minusMinutes(10), windowCaptor.getValue());
        verify(suspiciousActivityRepository).save(any(SuspiciousActivity.class));
        verify(notificationEmailService).notifySuspiciousActivity(
                any(SuspiciousActivity.class));
    }

    // ==============================================================
    // Rule 1: Username-based detection tests
    // ==============================================================

    @Test
    @DisplayName("Should flag suspicious activity when 5 or more failures occur for same username within 10 minutes")
    void testUsernameThresholdReached_savesSuspiciousActivity() {
        LoginAttempt failedAttempt = new LoginAttempt(
                1L,
                "alice",
                "192.168.1.10",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("alice"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(5L);

        // Suppress IP detection for test isolation
        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(failedAttempt);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository).save(captor.capture());

        SuspiciousActivity saved = captor.getValue();
        assertEquals("alice", saved.getUsername());
        assertEquals("192.168.1.10", saved.getIpAddress());
        assertEquals(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME, saved.getActivityType());
        assertNotNull(saved.getDescription());
        assertNotNull(saved.getDetectedAt());
    }

    @Test
    @DisplayName("Should not flag username suspicious activity when failure count is below threshold (4)")
    void testUsernameThresholdNotReached_doesNotSave() {
        LoginAttempt failedAttempt = new LoginAttempt(
                2L,
                "bob",
                "10.0.0.1",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("bob"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeBetween(
                eq("bob"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(4L);

        // Suppress IP detection for test isolation
        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(failedAttempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Should prevent duplicate username alerts within the same 10-minute window")
    void testUsernameAlreadyReportedInWindow_doesNotSaveDuplicate() {
        LoginAttempt failedAttempt = new LoginAttempt(
                3L,
                "charlie",
                "172.16.0.5",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("charlie"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME),
                any(LocalDateTime.class)
        )).thenReturn(true);

        // Suppress IP detection for test isolation
        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(failedAttempt);

        verify(loginAttemptRepository, never()).countByUsernameAndStatusAndAttemptTimeBetween(any(), any(), any(), any());
        verify(suspiciousActivityRepository, never()).save(any());
    }

    // ==============================================================
    // Rule 2: IP-based detection tests
    // ==============================================================

    @Test
    @DisplayName("Should flag suspicious activity when 5 failures occur from the same IP across different usernames")
    void testIpRule_fiveFailuresWithDifferentUsernames_triggersAlert() {
        LoginAttempt failedAttempt = new LoginAttempt(
                4L,
                "user_e",
                "192.168.1.100",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        // Suppress username detection for test isolation
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                eq("192.168.1.100"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeBetween(
                eq("192.168.1.100"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(5L);

        detectionService.checkSuspiciousActivity(failedAttempt);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository).save(captor.capture());

        SuspiciousActivity saved = captor.getValue();
        assertEquals("user_e", saved.getUsername());
        assertEquals("192.168.1.100", saved.getIpAddress());
        assertEquals(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP, saved.getActivityType());
        assertEquals("5 failed login attempts from IP 192.168.1.100 within 10 minutes.", saved.getDescription());
        assertNotNull(saved.getDetectedAt());
    }

    @Test
    @DisplayName("Should not flag IP suspicious activity when failure count is below threshold (4)")
    void testIpRule_fourFailures_doesNotTriggerAlert() {
        LoginAttempt failedAttempt = new LoginAttempt(
                5L,
                "user_f",
                "10.0.0.50",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        // Suppress username detection for test isolation
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                eq("10.0.0.50"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeBetween(
                eq("10.0.0.50"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(4L);

        detectionService.checkSuspiciousActivity(failedAttempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Should prevent duplicate IP alerts within the same 10-minute window")
    void testIpRule_alreadyReportedInWindow_doesNotSaveDuplicate() {
        LoginAttempt failedAttempt = new LoginAttempt(
                6L,
                "user_g",
                "10.0.0.99",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        // Suppress username detection for test isolation
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                eq("10.0.0.99"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP),
                any(LocalDateTime.class)
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(failedAttempt);

        verify(loginAttemptRepository, never()).countByIpAddressAndStatusAndAttemptTimeBetween(any(), any(), any(), any());
        verify(suspiciousActivityRepository, never()).save(any());
    }

    // ==============================================================
    // Common behavior / Isolation test
    // ==============================================================

    @Test
    @DisplayName("Should ignore SUCCESS login attempts and not count them for IP or username")
    void testSuccessAttempt_notCountedForIpOrUsername() {
        LoginAttempt successAttempt = new LoginAttempt(
                7L,
                "dave",
                "192.168.1.50",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        // Suppress Rule 3 check so we isolate that IP/username failure rules ignore SUCCESS
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("dave"),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any(LocalDateTime.class)
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(successAttempt);

        verify(suspiciousActivityRepository, never()).existsByUsernameAndActivityTypeAndDetectedAtAfter(any(), eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME), any());
        verify(suspiciousActivityRepository, never()).existsByIpAddressAndActivityTypeAndDetectedAtAfter(any(), eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP), any());
        verify(loginAttemptRepository, never()).countByUsernameAndStatusAndAttemptTimeBetween(any(), any(), any(), any());
        verify(loginAttemptRepository, never()).countByIpAddressAndStatusAndAttemptTimeBetween(any(), any(), any(), any());
        verify(suspiciousActivityRepository, never()).save(any());
    }

    // ==============================================================
    // Dual detection test
    // ==============================================================

    @Test
    @DisplayName("Should trigger both username and IP detection when both thresholds are reached and neither alert exists")
    void testBothThresholdsReached_savesBothAlerts() {
        LoginAttempt failedAttempt = new LoginAttempt(
                8L,
                "attacker",
                "198.51.100.25",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        // Neither alert exists yet
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("attacker"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                eq("198.51.100.25"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP),
                any(LocalDateTime.class)
        )).thenReturn(false);

        // Both failure counts reach 5
        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeBetween(
                eq("attacker"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(5L);

        when(loginAttemptRepository.countByIpAddressAndStatusAndAttemptTimeBetween(
                eq("198.51.100.25"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(5L);

        detectionService.checkSuspiciousActivity(failedAttempt);

        // Verify that save was called twice (once for username, once for IP)
        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository, times(2)).save(captor.capture());

        List<SuspiciousActivity> savedActivities = captor.getAllValues();
        assertEquals(2, savedActivities.size());

        boolean hasUsernameAlert = savedActivities.stream()
                .anyMatch(a -> a.getActivityType() == SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME);
        boolean hasIpAlert = savedActivities.stream()
                .anyMatch(a -> a.getActivityType() == SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP);

        assertTrue(hasUsernameAlert);
        assertTrue(hasIpAlert);
    }

    // ==============================================================
    // Rule 3: Success after multiple failures tests
    // ==============================================================

    @Test
    @DisplayName("Should flag suspicious activity when 3 failures are followed by SUCCESS within 10 minutes")
    void testSuccessAfterThreeFailures_triggersAlert() {
        LoginAttempt successAttempt = new LoginAttempt(
                9L,
                "victim",
                "192.168.1.200",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("victim"),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                eq("victim"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(3L);

        detectionService.checkSuspiciousActivity(successAttempt);

        ArgumentCaptor<SuspiciousActivity> captor = ArgumentCaptor.forClass(SuspiciousActivity.class);
        verify(suspiciousActivityRepository).save(captor.capture());

        SuspiciousActivity saved = captor.getValue();
        assertEquals("victim", saved.getUsername());
        assertEquals("192.168.1.200", saved.getIpAddress());
        assertEquals(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES, saved.getActivityType());
        assertNotNull(saved.getDescription());
        assertNotNull(saved.getDetectedAt());
    }

    @Test
    @DisplayName("Should not flag suspicious activity when SUCCESS occurs after only 2 failures")
    void testSuccessAfterTwoFailures_doesNotTriggerAlert() {
        LoginAttempt successAttempt = new LoginAttempt(
                10L,
                "user_k",
                "192.168.1.201",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("user_k"),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                eq("user_k"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(2L);

        detectionService.checkSuspiciousActivity(successAttempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Should not flag suspicious activity when SUCCESS occurs with 0 prior failures")
    void testSuccessWithoutPriorFailures_doesNotTriggerAlert() {
        LoginAttempt successAttempt = new LoginAttempt(
                11L,
                "clean_user",
                "192.168.1.202",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("clean_user"),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any(LocalDateTime.class)
        )).thenReturn(false);

        when(loginAttemptRepository.countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                eq("clean_user"),
                eq(LoginStatus.FAILURE),
                any(LocalDateTime.class),
                any(LocalDateTime.class)
        )).thenReturn(0L);

        detectionService.checkSuspiciousActivity(successAttempt);

        verify(suspiciousActivityRepository, never()).save(any(SuspiciousActivity.class));
    }

    @Test
    @DisplayName("Should prevent duplicate SUCCESS_AFTER_MULTIPLE_FAILURES alerts within the same 10-minute window")
    void testSuccessAfterFailures_alreadyReportedInWindow_doesNotSaveDuplicate() {
        LoginAttempt successAttempt = new LoginAttempt(
                12L,
                "victim",
                "192.168.1.200",
                LocalDateTime.now(),
                LoginStatus.SUCCESS
        );

        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("victim"),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any(LocalDateTime.class)
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(successAttempt);

        verify(loginAttemptRepository, never()).countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(any(), any(), any(), any());
        verify(suspiciousActivityRepository, never()).save(any());
    }

    @Test
    @DisplayName("Should not trigger SUCCESS_AFTER_MULTIPLE_FAILURES for FAILURE attempts")
    void testFailureAttempt_doesNotTriggerSuccessAfterFailuresRule() {
        LoginAttempt failedAttempt = new LoginAttempt(
                13L,
                "user_fail",
                "192.168.1.203",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        // Suppress Rule 1 and Rule 2
        when(suspiciousActivityRepository.existsByUsernameAndActivityTypeAndDetectedAtAfter(
                eq("user_fail"),
                eq(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME),
                any(LocalDateTime.class)
        )).thenReturn(true);

        when(suspiciousActivityRepository.existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                any(), any(), any()
        )).thenReturn(true);

        detectionService.checkSuspiciousActivity(failedAttempt);

        verify(suspiciousActivityRepository, never()).existsByUsernameAndActivityTypeAndDetectedAtAfter(
                any(),
                eq(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES),
                any()
        );
    }
}
