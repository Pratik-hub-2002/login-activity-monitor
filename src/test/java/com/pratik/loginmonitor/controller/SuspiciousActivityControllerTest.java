package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.service.SuspiciousActivityService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SuspiciousActivityControllerTest {

    @Mock
    private SuspiciousActivityService suspiciousActivityService;

    @InjectMocks
    private SuspiciousActivityController suspiciousActivityController;

    @Test
    @DisplayName("Should return 200 OK and list of suspicious activities from service")
    void testGetSuspiciousActivities_returnsList() {
        SuspiciousActivity sa = new SuspiciousActivity(
                1L, "user1", "10.0.0.1",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                "Description", LocalDateTime.now()
        );

        when(suspiciousActivityService.getSuspiciousActivities("user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME))
                .thenReturn(List.of(sa));

        ResponseEntity<List<SuspiciousActivity>> response = suspiciousActivityController.getSuspiciousActivities(
                "user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        verify(suspiciousActivityService).getSuspiciousActivities("user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME);
    }

    @Test
    @DisplayName("Should return 400 Bad Request when activityType parameter is invalid")
    void testHandleTypeMismatch_returnsBadRequest() {
        MethodArgumentTypeMismatchException ex = new MethodArgumentTypeMismatchException(
                "INVALID_TYPE",
                SuspiciousActivityType.class,
                "activityType",
                (MethodParameter) null,
                null
        );

        ResponseEntity<Map<String, Object>> response = suspiciousActivityController.handleTypeMismatch(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(400, response.getBody().get("status"));
        assertEquals("Bad Request", response.getBody().get("error"));
        assertNotNull(response.getBody().get("message"));
    }
}

