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

    /**
     * Counts login attempts for a specific username and status after a given timestamp.
     */
    long countByUsernameAndStatusAndAttemptTimeAfter(
            String username,
            LoginStatus status,
            LocalDateTime after
    );

    /**
     * Counts login attempts for a specific IP address and status after a given timestamp.
     */
    long countByIpAddressAndStatusAndAttemptTimeAfter(
            String ipAddress,
            LoginStatus status,
            LocalDateTime after
    );

    /**
     * Counts all login attempts matching the given status.
     */
    long countByStatus(LoginStatus status);
}
