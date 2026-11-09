package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.dto.SuspiciousActivityResponse;
import com.pratik.loginmonitor.service.SuspiciousActivityService;

@RestController
@RequestMapping
public class SuspiciousActivityController {

    private final SuspiciousActivityService suspiciousActivityService;

    public SuspiciousActivityController(SuspiciousActivityService suspiciousActivityService) {
        this.suspiciousActivityService = suspiciousActivityService;
    }

    @GetMapping({"/suspicious", "/api/suspicious"})
    public ResponseEntity<List<SuspiciousActivityResponse>> getSuspiciousActivities(
            @RequestParam(required = false) String username,
            @RequestParam(name = "ip_address", required = false) String ipAddressSnake,
            @RequestParam(name = "ipAddress", required = false) String ipAddressCamel,
            @RequestParam(required = false) SuspiciousActivityType activityType) {

        String ipAddress = (ipAddressSnake != null && !ipAddressSnake.isBlank())
                ? ipAddressSnake
                : ipAddressCamel;

        List<SuspiciousActivity> activities = suspiciousActivityService
                .getSuspiciousActivities(username, ipAddress, activityType);

        List<SuspiciousActivityResponse> responses = activities.stream()
                .map(activity -> new SuspiciousActivityResponse(
                        activity.getId(),
                        activity.getIpAddress(),
                        activity.getUsername(),
                        activity.getReason(),
                        activity.getDetectedAt()))
                .toList();

        return ResponseEntity.ok(responses);
    }

    public ResponseEntity<List<SuspiciousActivityResponse>> getSuspiciousActivities(
            String username,
            String ipAddress,
            SuspiciousActivityType activityType) {
        return getSuspiciousActivities(username, ipAddress, null, activityType);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        Map<String, Object> error = new HashMap<>();
        error.put("timestamp", LocalDateTime.now());
        error.put("status", HttpStatus.BAD_REQUEST.value());
        error.put("error", "Bad Request");
        error.put("message", String.format(
                "Invalid value '%s' for parameter '%s'. Allowed values for activityType are: %s",
                ex.getValue(), ex.getName(), Arrays.toString(SuspiciousActivityType.values())
        ));
        return ResponseEntity.badRequest().body(error);
    }
}
