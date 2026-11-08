package com.pratik.loginmonitor.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardResponse {
    private long totalLoginAttempts;
    private long successfulLoginAttempts;
    private long failedLoginAttempts;
    private long totalSuspiciousActivities;
}

