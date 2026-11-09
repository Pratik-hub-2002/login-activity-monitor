package com.pratik.loginmonitor.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SuspiciousActivityResponse {
    private Long id;

    @JsonProperty("ip_address")
    private String ipAddress;

    private String username;
    private String reason;
    private LocalDateTime timestamp;
}
