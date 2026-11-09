package com.pratik.loginmonitor.service;

import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.dto.DashboardResponse;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

@Service
public class DashboardService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final SuspiciousActivityRepository suspiciousActivityRepository;

    public DashboardService(LoginAttemptRepository loginAttemptRepository,
                            SuspiciousActivityRepository suspiciousActivityRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.suspiciousActivityRepository = suspiciousActivityRepository;
    }

    /**
     * Aggregates dashboard metrics via direct database count queries.
     */
    public DashboardResponse getDashboardStatistics() {
        long totalAttempts = loginAttemptRepository.count();
        long successfulAttempts = loginAttemptRepository.countByStatus(LoginStatus.SUCCESS);
        long failedAttempts = loginAttemptRepository.countByStatus(LoginStatus.FAILURE);
        long totalSuspicious = suspiciousActivityRepository.count();

        return new DashboardResponse(
                totalAttempts,
                successfulAttempts,
                failedAttempts,
                totalSuspicious
        );
    }

    public DashboardResponse getDashboardStatistics(String username, boolean administrator) {
        if (administrator) {
            return getDashboardStatistics();
        }

        return new DashboardResponse(
                loginAttemptRepository.countByUsername(username),
                loginAttemptRepository.countByUsernameAndStatus(
                        username, LoginStatus.SUCCESS),
                loginAttemptRepository.countByUsernameAndStatus(
                        username, LoginStatus.FAILURE),
                0);
    }
}
