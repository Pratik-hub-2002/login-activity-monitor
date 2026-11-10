package com.pratik.loginmonitor.repository;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;

@Repository
public interface LoginAttemptRepository
        extends JpaRepository<LoginAttempt, Long>, JpaSpecificationExecutor<LoginAttempt> {
    java.util.List<LoginAttempt> findByAttemptTimeAfterOrderByAttemptTimeAsc(
            LocalDateTime after
    );

    /**
     * Counts login attempts for a specific username and status after a given timestamp.
     */
    long countByUsernameAndStatusAndAttemptTimeAfter(
            String username,
            LoginStatus status,
            LocalDateTime after
    );

    long countByUsernameAndStatusAndAttemptTimeBetween(
            String username,
            LoginStatus status,
            LocalDateTime from,
            LocalDateTime to
    );

    long countByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
            String username,
            LoginStatus status,
            LocalDateTime after,
            LocalDateTime before
    );

    /**
     * Counts login attempts for a specific IP address and status after a given timestamp.
     */
    long countByIpAddressAndStatusAndAttemptTimeAfter(
            String ipAddress,
            LoginStatus status,
            LocalDateTime after
    );

    long countByIpAddressAndStatusAndAttemptTimeBetween(
            String ipAddress,
            LoginStatus status,
            LocalDateTime from,
            LocalDateTime to
    );

    /**
     * Counts all login attempts matching the given status.
     */
    long countByStatus(LoginStatus status);

    long countByUsername(String username);

    long countByUsernameAndStatus(String username, LoginStatus status);

    /**
     * Returns login attempts matching the given username, status and time range.
     * Used by fingerprint-based detection to identify qualifying attempts.
     */
    java.util.List<LoginAttempt> findByUsernameAndStatusAndAttemptTimeBetween(
            String username, LoginStatus status,
            LocalDateTime from, LocalDateTime to);

    java.util.List<LoginAttempt> findByIpAddressAndStatusAndAttemptTimeBetween(
            String ipAddress, LoginStatus status,
            LocalDateTime from, LocalDateTime to);

    java.util.List<LoginAttempt> findByUsernameAndStatusAndAttemptTimeAfterAndAttemptTimeBefore(
            String username, LoginStatus status,
            LocalDateTime after, LocalDateTime before);
}
