package com.pratik.loginmonitor.service;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

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

    private final LoginAttemptRepository loginAttemptRepository;
    private final SuspiciousActivityRepository suspiciousActivityRepository;

    public DetectionService(LoginAttemptRepository loginAttemptRepository,
                            SuspiciousActivityRepository suspiciousActivityRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.suspiciousActivityRepository = suspiciousActivityRepository;
    }

    /**
     * Evaluates a saved login attempt against suspicious activity detection rules.
     */
    public void checkSuspiciousActivity(LoginAttempt attempt) {
        if (attempt == null) {
            return;
        }

        if (attempt.getStatus() == LoginStatus.FAILURE) {
            checkMultipleFailuresByUsername(attempt);
            checkMultipleFailuresByIp(attempt);
        } else if (attempt.getStatus() == LoginStatus.SUCCESS) {
            checkSuccessAfterMultipleFailures(attempt);
        }
    }

    /**
     * Rule 1: Checks if the same username has generated 5 or more FAILURE attempts
     * within the last 10 minutes, avoiding duplicate alerts in the same window.
     */
    private void checkMultipleFailuresByUsername(LoginAttempt attempt) {
        String username = attempt.getUsername();
        LocalDateTime windowStartTime = LocalDateTime.now().minusMinutes(WINDOW_MINUTES);

        // Prevent duplicate alerts: check if an alert for this username was already recorded in this window
        boolean alreadyReported = suspiciousActivityRepository
                .existsByUsernameAndActivityTypeAndDetectedAtAfter(
                        username,
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                        windowStartTime
                );

        if (alreadyReported) {
            return;
        }

        // Count failed attempts for this username within the 10-minute window
        long failedCount = loginAttemptRepository
                .countByUsernameAndStatusAndAttemptTimeAfter(
                        username,
                        LoginStatus.FAILURE,
                        windowStartTime
                );

        if (failedCount >= FAILURE_THRESHOLD) {
            SuspiciousActivity activity = new SuspiciousActivity();
            activity.setUsername(username);
            activity.setIpAddress(attempt.getIpAddress());
            activity.setActivityType(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME);
            activity.setDescription(String.format(
                    "Detected %d failed login attempts for username '%s' within the last %d minutes.",
                    failedCount, username, WINDOW_MINUTES
            ));
            activity.setDetectedAt(LocalDateTime.now());

            suspiciousActivityRepository.save(activity);
        }
    }

    /**
     * Rule 2: Checks if the same IP address has generated 5 or more FAILURE attempts
     * within the last 10 minutes (across any usernames), avoiding duplicate alerts in the same window.
     */
    private void checkMultipleFailuresByIp(LoginAttempt attempt) {
        String ipAddress = attempt.getIpAddress();
        LocalDateTime windowStartTime = LocalDateTime.now().minusMinutes(WINDOW_MINUTES);

        // Prevent duplicate alerts: check if an alert for this IP was already recorded in this window
        boolean alreadyReported = suspiciousActivityRepository
                .existsByIpAddressAndActivityTypeAndDetectedAtAfter(
                        ipAddress,
                        SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP,
                        windowStartTime
                );

        if (alreadyReported) {
            return;
        }

        // Count failed attempts for this IP address within the 10-minute window
        long failedCount = loginAttemptRepository
                .countByIpAddressAndStatusAndAttemptTimeAfter(
                        ipAddress,
                        LoginStatus.FAILURE,
                        windowStartTime
                );

        if (failedCount >= FAILURE_THRESHOLD) {
            SuspiciousActivity activity = new SuspiciousActivity();
            activity.setUsername(attempt.getUsername());
            activity.setIpAddress(ipAddress);
            activity.setActivityType(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP);
            activity.setDescription(String.format(
                    "%d failed login attempts from IP %s within %d minutes.",
                    failedCount, ipAddress, WINDOW_MINUTES
            ));
            activity.setDetectedAt(LocalDateTime.now());

            suspiciousActivityRepository.save(activity);
        }
    }

    /**
     * Rule 3: Checks if a successful login occurs for a username that had 3 or more
     * failed attempts within the previous 10 minutes, avoiding duplicate alerts in the same window.
     */
    private void checkSuccessAfterMultipleFailures(LoginAttempt attempt) {
        String username = attempt.getUsername();
        LocalDateTime windowStartTime = LocalDateTime.now().minusMinutes(WINDOW_MINUTES);

        // Prevent duplicate alerts: check if a success-after-failures alert was already recorded in this window
        boolean alreadyReported = suspiciousActivityRepository
                .existsByUsernameAndActivityTypeAndDetectedAtAfter(
                        username,
                        SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES,
                        windowStartTime
                );

        if (alreadyReported) {
            return;
        }

        // Count failed attempts for this username within the previous 10 minutes
        long failedCount = loginAttemptRepository
                .countByUsernameAndStatusAndAttemptTimeAfter(
                        username,
                        LoginStatus.FAILURE,
                        windowStartTime
                );

        if (failedCount >= SUCCESS_AFTER_FAILURES_THRESHOLD) {
            SuspiciousActivity activity = new SuspiciousActivity();
            activity.setUsername(username);
            activity.setIpAddress(attempt.getIpAddress());
            activity.setActivityType(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES);
            activity.setDescription(String.format(
                    "Successful login for username '%s' following %d failed attempts within %d minutes.",
                    username, failedCount, WINDOW_MINUTES
            ));
            activity.setDetectedAt(LocalDateTime.now());

            suspiciousActivityRepository.save(activity);
        }
    }
}
