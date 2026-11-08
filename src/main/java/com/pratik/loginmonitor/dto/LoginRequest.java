package com.pratik.loginmonitor.dto;

import com.pratik.loginmonitor.enums.LoginStatus;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Username is required and cannot be blank")
    private String username;

    @NotNull(message = "Login status is required (SUCCESS or FAILURE)")
    private LoginStatus status;
}

