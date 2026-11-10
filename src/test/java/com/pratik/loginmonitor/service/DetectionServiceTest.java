package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.pratik.loginmonitor.LoginActivityMonitorApplication;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

@ExtendWith(MockitoExtension.class)
class DetectionServiceTest {

    private static final Instant FIXED_INSTANT =
            Instant.parse("2026-11-09T12:00:00Z");
    private static final LocalDateTime FIXED_TIME =
            LocalDateTime.ofInstant(FIXED_INSTANT, ZoneOffset.UTC);

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @Mock
    private NotificationEmailService notificationEmailService;

    private DetectionService detectionService;

    @BeforeEach
    void setUp() {
        detectionService = new DetectionService(
                loginAttemptRepository,
                suspiciousActivityRepository,
                notificationEmailService,
                Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC));
    }

    @Test
    void usernameRuleFingerprintsSortedQualifyingFailureIds() throws Exception {
        List<LoginAttempt> failures =
                failures("alice", "192.0.2.1", 5L, 2L, 4L, 1L, 3L);
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures);
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));

        SuspiciousActivity saved = savedActivities().get(0);
        assertEquals(
                expectedFingerprint(
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                        "alice",
                        List.of(1L, 2L, 3L, 4L, 5L),
                        null),
                saved.getDetectionFingerprint());
        assertEquals(64, saved.getDetectionFingerprint().length());
        assertEquals(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                saved.getActivityType());
    }

    @Test
    void ipRuleFingerprintsSortedQualifyingFailureIds() throws Exception {
        List<LoginAttempt> failures =
                failures("attacker", "198.51.100.10", 50L, 20L, 40L, 10L, 30L);
        when(loginAttemptRepository.findByIpAddressAndStatusAndAttemptTimeBetween(
                eq("198.51.100.10"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures);
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(attempt(
                50L, "attacker", "198.51.100.10", FIXED_TIME, LoginStatus.FAILURE));

        SuspiciousActivity saved = savedActivities().get(0);
        assertEquals(
                expectedFingerprint(
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP,
                        "198.51.100.10",
                        List.of(10L, 20L, 30L, 40L, 50L),
                        null),
                saved.getDetectionFingerprint());
        assertEquals(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP,
                saved.getActivityType());
    }

    @Test
    void successAfterFailuresFingerprintIncludesSuccessIdAndPriorFailureIds()
            throws Exception {
        List<LoginAttempt> failures =
                failures("alice", "192.0.2.1", 3L, 1L, 2L);
        when(loginAttemptRepository
                .findByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                        eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures);
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(
                attempt(99L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.SUCCESS));

        SuspiciousActivity saved = savedActivities().get(0);
        assertEquals(
                expectedFingerprint(
                        SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES,
                        "alice",
                        List.of(1L, 2L, 3L),
                        99L),
                saved.getDetectionFingerprint());
        assertEquals(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES,
                saved.getActivityType());
    }

    @Test
    void repeatedProcessingInDifferentOrderUsesSameFingerprintAndSavesOnce()
            throws Exception {
        List<LoginAttempt> firstOrder =
                failures("alice", "192.0.2.1", 5L, 3L, 1L, 4L, 2L);
        List<LoginAttempt> secondOrder = new ArrayList<>(firstOrder);
        Collections.reverse(secondOrder);
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(firstOrder, secondOrder);
        stubFingerprintStore();
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        LoginAttempt event =
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE);
        detectionService.checkSuspiciousActivity(event);
        detectionService.checkSuspiciousActivity(event);

        ArgumentCaptor<String> fingerprints = ArgumentCaptor.forClass(String.class);
        verify(suspiciousActivityRepository, times(2))
                .existsByDetectionFingerprint(fingerprints.capture());
        assertEquals(fingerprints.getAllValues().get(0), fingerprints.getAllValues().get(1));
        verify(suspiciousActivityRepository).saveAndFlush(any());
        verify(notificationEmailService).notifySuspiciousActivity(any());
    }

    @Test
    void liveDetectionThenPeriodicDetectionDoesNotDuplicateAlert() {
        LoginAttempt trigger =
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME.minusMinutes(1),
                        LoginStatus.FAILURE);
        List<LoginAttempt> failures = failuresAt(
                "alice", "192.0.2.1", trigger.getAttemptTime(),
                1L, 2L, 3L, 4L, 5L);
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures);
        when(loginAttemptRepository
                .findByAttemptTimeAfterOrderByAttemptTimeAsc(any()))
                .thenReturn(List.of(trigger));
        stubFingerprintStore();
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(trigger);
        detectionService.runPeriodicDetection();

        verify(suspiciousActivityRepository).saveAndFlush(any());
        verify(notificationEmailService).notifySuspiciousActivity(any());
    }

    @Test
    void differentQualifyingSequencesWithinSameTenMinutesCreateSeparateAlerts() {
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L, 5L));
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("bob"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("bob", "192.0.2.2", 6L, 7L, 8L, 9L, 10L));
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));
        detectionService.checkSuspiciousActivity(
                attempt(10L, "bob", "192.0.2.2", FIXED_TIME, LoginStatus.FAILURE));

        List<SuspiciousActivity> saved = savedActivities();
        assertEquals(2, saved.size());
        assertNotNull(saved.get(0).getDetectionFingerprint());
        assertNotNull(saved.get(1).getDetectionFingerprint());
        assertTrue(!saved.get(0).getDetectionFingerprint()
                .equals(saved.get(1).getDetectionFingerprint()));
    }

    @Test
    void newQualifyingAttemptSequenceCreatesNewFingerprint() {
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(
                        failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L, 5L),
                        failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L, 5L, 6L));
        stubFingerprintStore();
        when(suspiciousActivityRepository.saveAndFlush(any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        detectionService.checkSuspiciousActivity(
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));
        detectionService.checkSuspiciousActivity(
                attempt(6L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));

        List<SuspiciousActivity> saved = savedActivities();
        assertEquals(2, saved.size());
        assertTrue(!saved.get(0).getDetectionFingerprint()
                .equals(saved.get(1).getDetectionFingerprint()));
    }

    @Test
    void thresholdsAndTenMinuteQueryBoundariesRemainUnchanged() {
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L));

        detectionService.checkSuspiciousActivity(
                attempt(4L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));

        verify(loginAttemptRepository).findByUsernameAndStatusAndAttemptTimeBetween(
                "alice", LoginStatus.FAILURE,
                FIXED_TIME.minusMinutes(10), FIXED_TIME);
        verify(suspiciousActivityRepository, never()).saveAndFlush(any());
    }

    @Test
    void successRuleStillRequiresThreeFailuresStrictlyBeforeSuccessTime() {
        when(loginAttemptRepository
                .findByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                        eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("alice", "192.0.2.1", 1L, 2L));

        detectionService.checkSuspiciousActivity(
                attempt(99L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.SUCCESS));

        verify(loginAttemptRepository)
                .findByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                        "alice", LoginStatus.FAILURE,
                        FIXED_TIME.minusMinutes(10), FIXED_TIME);
        verify(suspiciousActivityRepository, never()).saveAndFlush(any());
    }

    @Test
    void expectedFingerprintConstraintViolationIsTreatedAsDuplicate() {
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L, 5L));
        when(suspiciousActivityRepository.existsByDetectionFingerprint(anyString()))
                .thenReturn(false);
        ConstraintViolationException cause =
                org.mockito.Mockito.mock(ConstraintViolationException.class);
        when(cause.getConstraintName())
                .thenReturn("PUBLIC."
                        + SuspiciousActivity.DETECTION_FINGERPRINT_UNIQUE_CONSTRAINT
                        + " INDEX PUBLIC."
                        + SuspiciousActivity.DETECTION_FINGERPRINT_UNIQUE_CONSTRAINT
                        + "_INDEX");
        DataIntegrityViolationException duplicate =
                new DataIntegrityViolationException("duplicate fingerprint", cause);
        doThrow(duplicate).when(suspiciousActivityRepository)
                .saveAndFlush(any(SuspiciousActivity.class));

        detectionService.checkSuspiciousActivity(
                attempt(5L, "alice", "192.0.2.1", FIXED_TIME, LoginStatus.FAILURE));

        verify(notificationEmailService, never()).notifySuspiciousActivity(any());
    }

    @Test
    void unrelatedPersistenceConstraintViolationIsNotSwallowed() {
        when(loginAttemptRepository.findByUsernameAndStatusAndAttemptTimeBetween(
                eq("alice"), eq(LoginStatus.FAILURE), any(), any()))
                .thenReturn(failures("alice", "192.0.2.1", 1L, 2L, 3L, 4L, 5L));
        when(suspiciousActivityRepository.existsByDetectionFingerprint(anyString()))
                .thenReturn(false);
        ConstraintViolationException cause =
                org.mockito.Mockito.mock(ConstraintViolationException.class);
        when(cause.getConstraintName()).thenReturn("uk_unrelated_constraint");
        DataIntegrityViolationException persistenceFailure =
                new DataIntegrityViolationException("unrelated failure", cause);
        doThrow(persistenceFailure).when(suspiciousActivityRepository)
                .saveAndFlush(any(SuspiciousActivity.class));

        DataIntegrityViolationException thrown = assertThrows(
                DataIntegrityViolationException.class,
                () -> detectionService.checkSuspiciousActivity(
                        attempt(5L, "alice", "192.0.2.1",
                                FIXED_TIME, LoginStatus.FAILURE)));

        assertEquals(persistenceFailure, thrown);
    }

    @Test
    void schedulingRemainsEnabledAtOneMinuteIntervals() throws Exception {
        assertNotNull(LoginActivityMonitorApplication.class
                .getAnnotation(EnableScheduling.class));
        Scheduled scheduled = DetectionService.class
                .getMethod("runPeriodicDetection")
                .getAnnotation(Scheduled.class);
        assertNotNull(scheduled);
        assertEquals(60_000L, scheduled.fixedRate());
    }

    private List<SuspiciousActivity> savedActivities() {
        ArgumentCaptor<SuspiciousActivity> captor =
                ArgumentCaptor.forClass(SuspiciousActivity.class);
        org.mockito.Mockito.verify(suspiciousActivityRepository,
                org.mockito.Mockito.atLeast(0)).saveAndFlush(captor.capture());
        return captor.getAllValues();
    }

    private void stubFingerprintStore() {
        Set<String> existing = new HashSet<>();
        when(suspiciousActivityRepository.existsByDetectionFingerprint(anyString()))
                .thenAnswer(invocation ->
                        !existing.add(invocation.getArgument(0)));
    }

    private List<LoginAttempt> failures(
            String username, String ipAddress, Long... ids) {
        return failuresAt(username, ipAddress, FIXED_TIME, ids);
    }

    private List<LoginAttempt> failuresAt(
            String username,
            String ipAddress,
            LocalDateTime attemptTime,
            Long... ids) {
        List<LoginAttempt> attempts = new ArrayList<>();
        for (Long id : ids) {
            attempts.add(attempt(
                    id, username, ipAddress, attemptTime, LoginStatus.FAILURE));
        }
        return attempts;
    }

    private LoginAttempt attempt(
            Long id,
            String username,
            String ipAddress,
            LocalDateTime time,
            LoginStatus status) {
        return new LoginAttempt(id, username, ipAddress, time, status);
    }

    private String expectedFingerprint(
            SuspiciousActivityType activityType,
            String scope,
            List<Long> failureIds,
            Long successId) throws NoSuchAlgorithmException {
        List<Long> sortedIds = failureIds.stream().sorted().toList();
        StringBuilder canonical = new StringBuilder("v1\n")
                .append(activityType.name()).append('\n')
                .append(scope.length()).append(':').append(scope).append('\n')
                .append(successId == null ? "-" : successId)
                .append('\n')
                .append(sortedIds.size()).append(':');
        sortedIds.forEach(id -> canonical.append(id).append(','));
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    }
}
