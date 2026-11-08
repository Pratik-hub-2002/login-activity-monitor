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
import com.pratik.loginmonitor.service.SuspiciousActivityService;

@RestController
@RequestMapping("/api/suspicious")
public class SuspiciousActivityController {

    private final SuspiciousActivityService suspiciousActivityService;

    public SuspiciousActivityController(SuspiciousActivityService suspiciousActivityService) {
        this.suspiciousActivityService = suspiciousActivityService;
    }

    @GetMapping
    public ResponseEntity<List<SuspiciousActivity>> getSuspiciousActivities(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) SuspiciousActivityType activityType) {

        List<SuspiciousActivity> activities = suspiciousActivityService.getSuspiciousActivities(username, ipAddress, activityType);
        return ResponseEntity.ok(activities);
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

