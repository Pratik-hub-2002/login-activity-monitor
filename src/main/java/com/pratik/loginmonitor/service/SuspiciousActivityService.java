package com.pratik.loginmonitor.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

import jakarta.persistence.criteria.Predicate;

@Service
public class SuspiciousActivityService {

    private final SuspiciousActivityRepository suspiciousActivityRepository;

    public SuspiciousActivityService(SuspiciousActivityRepository suspiciousActivityRepository) {
        this.suspiciousActivityRepository = suspiciousActivityRepository;
    }

    /**
     * Retrieves suspicious activities with optional filtering by username, IP address, and activity type,
     * sorted by detectedAt descending (newest first).
     */
    public List<SuspiciousActivity> getSuspiciousActivities(String username, String ipAddress, SuspiciousActivityType activityType) {
        Specification<SuspiciousActivity> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (username != null && !username.isBlank()) {
                predicates.add(cb.equal(root.get("username"), username.trim()));
            }

            if (ipAddress != null && !ipAddress.isBlank()) {
                predicates.add(cb.equal(root.get("ipAddress"), ipAddress.trim()));
            }

            if (activityType != null) {
                predicates.add(cb.equal(root.get("activityType"), activityType));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        return suspiciousActivityRepository.findAll(spec, Sort.by(Sort.Direction.DESC, "detectedAt"));
    }
}

