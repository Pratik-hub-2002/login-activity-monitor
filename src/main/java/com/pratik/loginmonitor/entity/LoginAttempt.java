package com.pratik.loginmonitor.entity;

import java.time.LocalDateTime;

import com.pratik.loginmonitor.enums.LoginStatus;

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

    private String ipAddress;

    private LocalDateTime attemptTime;

    @Enumerated(EnumType.STRING)
    private LoginStatus status;
}