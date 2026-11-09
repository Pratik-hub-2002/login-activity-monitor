package com.pratik.loginmonitor.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.pratik.loginmonitor.enums.LoginStatus;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginAttemptResponse {
    private Long id;
    private String username;

    @JsonProperty("ip_address")
    private String ipAddress;

    private LocalDateTime timestamp;
    private LoginStatus status;
}
