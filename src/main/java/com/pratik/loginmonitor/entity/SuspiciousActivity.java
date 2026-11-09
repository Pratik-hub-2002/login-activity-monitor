package com.pratik.loginmonitor.entity;

import java.time.LocalDateTime;

import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Column;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "suspicious_activity")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SuspiciousActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    @Column(name = "ip_address")
    @JsonProperty("ip_address")
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    private SuspiciousActivityType activityType;

    @Column(name = "reason", nullable = false)
    private String reason;

    @Column(name = "timestamp", nullable = false)
    @JsonProperty("timestamp")
    private LocalDateTime detectedAt;

    public String getDescription() {
        return reason;
    }

    public void setDescription(String description) {
        this.reason = description;
    }

    public LocalDateTime getTimestamp() {
        return detectedAt;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.detectedAt = timestamp;
    }
}
