package com.pratik.loginmonitor.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActiveSessionResponse {
    private String username;
    private String ipAddress;
    private LocalDateTime createdAt;
    private LocalDateTime lastActivityAt;
    private LocalDateTime expiresAt;
}
