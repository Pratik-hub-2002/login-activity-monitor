package com.pratik.loginmonitor.controller;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.service.SuspiciousActivityService;
import com.pratik.loginmonitor.dto.SuspiciousActivityResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@ExtendWith(MockitoExtension.class)
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:suspiciouscontracttest;DB_CLOSE_DELAY=-1;MODE=MySQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class SuspiciousActivityControllerTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Mock
    private SuspiciousActivityService suspiciousActivityService;

    @InjectMocks
    private SuspiciousActivityController suspiciousActivityController;

    @Test
    @DisplayName("Should return 200 OK and list of suspicious activities from service")
    void testGetSuspiciousActivities_returnsList() throws Exception {
        LocalDateTime timestamp = LocalDateTime.of(2026, 1, 2, 3, 4, 5);
        SuspiciousActivity sa = new SuspiciousActivity(
                1L, "user1", "10.0.0.1",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME,
                "Five failures", timestamp
        );

        when(suspiciousActivityService.getSuspiciousActivities("user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME))
                .thenReturn(List.of(sa));

        ResponseEntity<List<SuspiciousActivityResponse>> response = suspiciousActivityController.getSuspiciousActivities(
                "user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME
        );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());

        SuspiciousActivityResponse dto = response.getBody().get(0);
        assertEquals("user1", dto.getUsername());
        assertEquals("10.0.0.1", dto.getIpAddress());
        assertEquals("Five failures", dto.getReason());
        JsonNode item = objectMapper.readTree(
                objectMapper.writeValueAsString(response.getBody())).get(0);
        assertEquals(Set.of("id", "ip_address", "username", "reason", "timestamp"),
                jsonKeys(item));
        assertEquals("1", item.get("id").toString());
        assertEquals("\"10.0.0.1\"", item.get("ip_address").toString());
        assertEquals("\"user1\"", item.get("username").toString());
        assertEquals("\"Five failures\"", item.get("reason").toString());
        assertEquals("\"2026-01-02T03:04:05\"", item.get("timestamp").toString());
        verify(suspiciousActivityService).getSuspiciousActivities("user1", "10.0.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME);
    }

    @Test
    void testGetSuspiciousActivities_serializesNullFieldsAsNullProperties() throws Exception {
        when(suspiciousActivityService.getSuspiciousActivities(null, null, null))
                .thenReturn(List.of(new SuspiciousActivity(
                        null, null, null, null, null, null)));

        ResponseEntity<List<SuspiciousActivityResponse>> response =
                suspiciousActivityController.getSuspiciousActivities(null, null, null);

        JsonNode item = objectMapper.readTree(
                objectMapper.writeValueAsString(response.getBody())).get(0);
        assertEquals(Set.of("id", "ip_address", "username", "reason", "timestamp"),
                jsonKeys(item));
        assertEquals(true, item.get("id").isNull());
        assertEquals(true, item.get("ip_address").isNull());
        assertEquals(true, item.get("username").isNull());
        assertEquals(true, item.get("reason").isNull());
        assertEquals(true, item.get("timestamp").isNull());
    }

    private Set<String> jsonKeys(JsonNode node) {
        return new TreeSet<>(node.propertyNames());
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
