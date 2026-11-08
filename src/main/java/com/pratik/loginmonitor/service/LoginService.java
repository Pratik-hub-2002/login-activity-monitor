package com.pratik.loginmonitor.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

import jakarta.persistence.criteria.Predicate;

@Service
public class LoginService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final DetectionService detectionService;

    public LoginService(LoginAttemptRepository loginAttemptRepository,
                        DetectionService detectionService) {
        this.loginAttemptRepository = loginAttemptRepository;
        this.detectionService = detectionService;
    }

    public LoginAttempt recordLoginAttempt(String username, String ipAddress, LoginStatus status) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username);
        attempt.setIpAddress(ipAddress);
        attempt.setAttemptTime(LocalDateTime.now());
        attempt.setStatus(status);

        LoginAttempt savedAttempt = loginAttemptRepository.save(attempt);

        detectionService.checkSuspiciousActivity(savedAttempt);

        return savedAttempt;
    }

    /**
     * Retrieves login attempts with optional filtering by username, IP address, and status,
     * ordered by attemptTime descending (newest first).
     */
    public List<LoginAttempt> getLoginAttempts(String username, String ipAddress, LoginStatus status) {
        Specification<LoginAttempt> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (username != null && !username.isBlank()) {
                predicates.add(cb.equal(root.get("username"), username.trim()));
            }

            if (ipAddress != null && !ipAddress.isBlank()) {
                predicates.add(cb.equal(root.get("ipAddress"), ipAddress.trim()));
            }

            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        return loginAttemptRepository.findAll(spec, Sort.by(Sort.Direction.DESC, "attemptTime"));
    }
}
