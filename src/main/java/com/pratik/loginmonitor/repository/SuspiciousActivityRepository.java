package com.pratik.loginmonitor.repository;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;

@Repository
public interface SuspiciousActivityRepository
        extends JpaRepository<SuspiciousActivity, Long>,
                JpaSpecificationExecutor<SuspiciousActivity> {

    /**
     * Checks if a suspicious activity of a specific type has already been recorded
     * for a username after a given timestamp (used for duplicate alert suppression).
     */
    boolean existsByUsernameAndActivityTypeAndDetectedAtAfter(
            String username,
            SuspiciousActivityType activityType,
            LocalDateTime after
    );

    /**
     * Checks if a suspicious activity of a specific type has already been recorded
     * for an IP address after a given timestamp (used for duplicate alert suppression).
     */
    boolean existsByIpAddressAndActivityTypeAndDetectedAtAfter(
            String ipAddress,
            SuspiciousActivityType activityType,
            LocalDateTime after
    );
}
