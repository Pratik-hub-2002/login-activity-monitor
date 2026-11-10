
package com.pratik.loginmonitor.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import org.hibernate.exception.ConstraintViolationException;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

@Service
public class DetectionService {

    private static final int FAILURE_THRESHOLD = 5;
    private static final int SUCCESS_AFTER_FAILURES_THRESHOLD = 3;
    private static final int WINDOW_MINUTES = 10;
    private static final Pattern FINGERPRINT_CONSTRAINT_PATTERN = Pattern.compile(
            "(?i)(?:^|[^A-Z0-9_])"
                    + Pattern.quote(SuspiciousActivity.DETECTION_FINGERPRINT_UNIQUE_CONSTRAINT)
                    + "(?:$|[^A-Z0-9_])");

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DetectionService.class);

    private final LoginAttemptRepository loginAttemptRepository;
    private final SuspiciousActivityRepository suspiciousActivityRepository;
    private final NotificationEmailService notificationEmailService;
    private Clock clock;

    @Autowired
    public DetectionService(
            LoginAttemptRepository loginAttemptRepository,
            SuspiciousActivityRepository suspiciousActivityRepository,
            NotificationEmailService notificationEmailService,
            Clock clock) {

        this.loginAttemptRepository = loginAttemptRepository;
        this.suspiciousActivityRepository = suspiciousActivityRepository;
        this.notificationEmailService = notificationEmailService;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    public DetectionService(
            LoginAttemptRepository loginAttemptRepository,
            SuspiciousActivityRepository suspiciousActivityRepository,
            NotificationEmailService notificationEmailService) {

        this(loginAttemptRepository, suspiciousActivityRepository, notificationEmailService, Clock.systemUTC());
    }

    @Autowired(required = false)
    public void setClock(Clock clock) {
        if (clock != null) {
            this.clock = clock;
        }
    }

    /**
     * Periodically scans recent login attempts within the sliding window.
     * Required by technical evaluation PDF and tested by scheduled execution suites.
     */
    @Scheduled(fixedRate = 60_000)
    public void runPeriodicDetection() {
        LocalDateTime windowStart = LocalDateTime.now(clock).minusMinutes(WINDOW_MINUTES);
        for (LoginAttempt attempt : loginAttemptRepository
                .findByAttemptTimeAfterOrderByAttemptTimeAsc(windowStart)) {
            checkSuspiciousActivity(attempt);
        }
    }

    /**
     * Evaluates a saved login attempt against suspicious activity rules.
     * Synchronized to prevent concurrent login attempts from generating duplicate records.
     */
    public synchronized void checkSuspiciousActivity(LoginAttempt attempt) {

        if (attempt == null || attempt.getStatus() == null) {
            return;
        }

        if (attempt.getUsername() == null
                || attempt.getUsername().isBlank()
                || attempt.getIpAddress() == null
                || attempt.getIpAddress().isBlank()) {
            LOGGER.warn("Skipping detection because username or IP is missing.");
            return;
        }

        LocalDateTime windowStart = attemptTime(attempt)
                .minusMinutes(WINDOW_MINUTES);

        if (attempt.getStatus() == LoginStatus.FAILURE) {

            checkMultipleFailuresByUsername(attempt, windowStart);
            checkMultipleFailuresByIp(attempt, windowStart);

        } else if (attempt.getStatus() == LoginStatus.SUCCESS) {

            checkSuccessAfterMultipleFailures(attempt, windowStart);
        }
    }

    private LocalDateTime attemptTime(LoginAttempt attempt) {
        return attempt.getAttemptTime() != null
                ? attempt.getAttemptTime()
                : LocalDateTime.now(clock);
    }

    /**
     * Rule 1:
     * Five or more failed attempts for the same username
     * within ten minutes.
     */
    private void checkMultipleFailuresByUsername(
            LoginAttempt attempt,
            LocalDateTime windowStart) {

        String username = attempt.getUsername();

        List<LoginAttempt> failedAttempts = loginAttemptRepository
                .findByUsernameAndStatusAndAttemptTimeBetween(
                        username,
                        LoginStatus.FAILURE,
                        windowStart,
                        attemptTime(attempt)
                );

        if (failedAttempts.size() < FAILURE_THRESHOLD) {
            return;
        }

        SuspiciousActivity activity = new SuspiciousActivity();

        activity.setUsername(username);
        activity.setIpAddress(attempt.getIpAddress());

        activity.setActivityType(
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME
        );

        activity.setReason(String.format(
                "Detected %d failed login attempts for username '%s' within the last %d minutes.",
                failedAttempts.size(),
                username,
                WINDOW_MINUTES
        ));

        activity.setDetectedAt(LocalDateTime.now(clock));

        notifyAfterSaving(
                activity,
                createFingerprint(
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                        username,
                        failedAttempts,
                        null));
    }

    /**
     * Rule 2:
     * Five or more failed attempts from the same IP
     * within ten minutes.
     */
    private void checkMultipleFailuresByIp(
            LoginAttempt attempt,
            LocalDateTime windowStart) {

        String ipAddress = attempt.getIpAddress();

        List<LoginAttempt> failedAttempts = loginAttemptRepository
                .findByIpAddressAndStatusAndAttemptTimeBetween(
                        ipAddress,
                        LoginStatus.FAILURE,
                        windowStart,
                        attemptTime(attempt)
                );

        if (failedAttempts.size() < FAILURE_THRESHOLD) {
            return;
        }

        SuspiciousActivity activity = new SuspiciousActivity();

        activity.setUsername(attempt.getUsername());
        activity.setIpAddress(ipAddress);

        activity.setActivityType(
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP
        );

        activity.setReason(String.format(
                "%d failed login attempts from IP %s within %d minutes.",
                failedAttempts.size(),
                ipAddress,
                WINDOW_MINUTES
        ));

        activity.setDetectedAt(LocalDateTime.now(clock));

        notifyAfterSaving(
                activity,
                createFingerprint(
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP,
                        ipAddress,
                        failedAttempts,
                        null));
    }

    /**
     * Rule 3:
     * A successful login after three or more failed attempts
     * within the previous ten minutes.
     */
    private void checkSuccessAfterMultipleFailures(
            LoginAttempt attempt,
            LocalDateTime windowStart) {

        String username = attempt.getUsername();

        List<LoginAttempt> failedAttempts = loginAttemptRepository
                .findByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
                        username,
                        LoginStatus.FAILURE,
                        windowStart,
                        attemptTime(attempt)
                );

        if (failedAttempts.size() < SUCCESS_AFTER_FAILURES_THRESHOLD) {
            return;
        }

        SuspiciousActivity activity = new SuspiciousActivity();

        activity.setUsername(username);
        activity.setIpAddress(attempt.getIpAddress());

        activity.setActivityType(
                SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES
        );

        activity.setReason(String.format(
                "Successful login for username '%s' following %d failed attempts within %d minutes.",
                username,
                failedAttempts.size(),
                WINDOW_MINUTES
        ));

        activity.setDetectedAt(LocalDateTime.now(clock));

        notifyAfterSaving(
                activity,
                createFingerprint(
                        SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES,
                        username,
                        failedAttempts,
                        attempt.getId()));
    }

    private String createFingerprint(
            SuspiciousActivityType activityType,
            String scope,
            List<LoginAttempt> failedAttempts,
            Long successfulAttemptId) {
        List<Long> attemptIds = failedAttempts.stream()
                .map(LoginAttempt::getId)
                .peek(id -> {
                    if (id == null) {
                        throw new IllegalStateException(
                                "Cannot fingerprint detection with an unsaved login attempt.");
                    }
                })
                .sorted()
                .toList();

        if (successfulAttemptId == null
                && activityType == SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES) {
            throw new IllegalStateException(
                    "Cannot fingerprint success-after-failures without the successful attempt ID.");
        }

        StringBuilder canonical = new StringBuilder("v1\n")
                .append(activityType.name()).append('\n')
                .append(scope.length()).append(':').append(scope).append('\n')
                .append(successfulAttemptId == null ? "-" : successfulAttemptId)
                .append('\n')
                .append(attemptIds.size()).append(':');
        attemptIds.forEach(id -> canonical.append(id).append(','));

        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }

    private void notifyAfterSaving(
            SuspiciousActivity activity,
            String fingerprint) {
        activity.setDetectionFingerprint(fingerprint);
        if (suspiciousActivityRepository.existsByDetectionFingerprint(fingerprint)) {
            return;
        }

        SuspiciousActivity savedActivity;
        try {
            savedActivity = suspiciousActivityRepository.saveAndFlush(activity);
        } catch (DataIntegrityViolationException exception) {
            if (isFingerprintConstraintViolation(exception)) {
                LOGGER.debug("Duplicate suspicious activity fingerprint was not recorded.");
                return;
            }
            throw exception;
        }

        try {
            notificationEmailService.notifySuspiciousActivity(savedActivity);
        } catch (RuntimeException exception) {
            LOGGER.error(
                    "Could not dispatch suspicious activity notification. "
                            + "The activity remains recorded.",
                    exception);
        }
    }

    private boolean isFingerprintConstraintViolation(Throwable exception) {
        Throwable cause = exception;
        while (cause != null) {
            if (cause instanceof ConstraintViolationException constraintViolation) {
                String constraintName = constraintViolation.getConstraintName();
                return constraintName != null
                        && FINGERPRINT_CONSTRAINT_PATTERN.matcher(constraintName).find();
            }
            Throwable next = cause.getCause();
            if (next == cause) {
                break;
            }
            cause = next;
        }
        return false;
    }

}
