package com.pratik.loginmonitor.entity;

import java.time.LocalDateTime;

import com.pratik.loginmonitor.enums.SuspiciousActivityType;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "suspicious_activities")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SuspiciousActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String ipAddress;

    @Enumerated(EnumType.STRING)
    private SuspiciousActivityType activityType;

    private String description;

    private LocalDateTime detectedAt;
}

