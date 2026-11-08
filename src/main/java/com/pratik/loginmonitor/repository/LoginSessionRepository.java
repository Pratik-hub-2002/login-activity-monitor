
package com.pratik.loginmonitor.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.pratik.loginmonitor.entity.LoginSession;

@Repository
public interface LoginSessionRepository extends JpaRepository<LoginSession, Long> {

    Optional<LoginSession> findBySessionId(String sessionId);

    List<LoginSession> findByUsernameOrderByCreatedAtDesc(String username);

    List<LoginSession> findByUsernameAndActiveTrue(String username);

    List<LoginSession> findByActiveTrueAndExpiresAtBefore(LocalDateTime expiresAt);

    List<LoginSession> findByActiveTrueAndExpiresAtAfterOrderByCreatedAtDesc(
            LocalDateTime currentTime);
}
