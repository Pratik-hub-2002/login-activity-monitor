package com.pratik.loginmonitor.entity;

import java.time.LocalDateTime;

import com.pratik.loginmonitor.enums.LoginStatus;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.*;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "login_attempts")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    @Column(name = "ip_address")
    @JsonProperty("ip_address")
    private String ipAddress;

    @Column(name = "timestamp")
    @JsonProperty("timestamp")
    private LocalDateTime attemptTime;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private LoginStatus status;

    public LocalDateTime getTimestamp() {
        return attemptTime;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.attemptTime = timestamp;
    }
}