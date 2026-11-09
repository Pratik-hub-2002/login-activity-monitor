package com.pratik.loginmonitor.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.pratik.loginmonitor.enums.LoginStatus;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PublicLoginFailureRequest {

    @NotBlank(message = "Username is required and cannot be blank")
    @Size(max = 255, message = "Username must not exceed 255 characters")
    @Pattern(regexp = "^[^\\p{Cntrl}]+$", message = "Username contains invalid control characters")
    private String username;

    @NotBlank(message = "IP address is required")
    @Size(max = 64, message = "IP address is too long")
    @JsonProperty("ip_address")
    @JsonAlias({"ipAddress", "ip_address"})
    private String ipAddress;

    @NotNull(message = "Status is required")
    private LoginStatus status;

    public PublicLoginFailureRequest(String username) {
        this.username = username;
    }

    public PublicLoginFailureRequest(String username, String ipAddress, LoginStatus status) {
        setUsername(username);
        setIpAddress(ipAddress);
        this.status = status;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username == null ? null : username.trim();
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress == null ? null : ipAddress.trim();
    }

    public LoginStatus getStatus() {
        return status;
    }

    public void setStatus(LoginStatus status) {
        this.status = status;
    }

    @AssertTrue(message = "IP address must be a valid IPv4 or IPv6 literal")
    @JsonIgnore
    public boolean isIpAddressLiteral() {
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }
        try {
            if (ipAddress.indexOf(':') >= 0) {
                return java.net.InetAddress.getByName(ipAddress)
                        instanceof java.net.Inet6Address;
            }
            String[] octets = ipAddress.split("\\.", -1);
            if (octets.length != 4) {
                return false;
            }
            for (String octet : octets) {
                if (octet.isEmpty() || !octet.chars().allMatch(Character::isDigit)) {
                    return false;
                }
                int value = Integer.parseInt(octet);
                if (value > 255) {
                    return false;
                }
            }
            return true;
        } catch (java.net.UnknownHostException | NumberFormatException exception) {
            return false;
        }
    }
}
