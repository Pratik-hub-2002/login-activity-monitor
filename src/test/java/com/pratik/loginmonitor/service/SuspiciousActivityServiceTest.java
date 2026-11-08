package com.pratik.loginmonitor.service;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;

import com.pratik.loginmonitor.entity.SuspiciousActivity;
import com.pratik.loginmonitor.enums.SuspiciousActivityType;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SuspiciousActivityServiceTest {

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @InjectMocks
    private SuspiciousActivityService suspiciousActivityService;

    @Test
    @DisplayName("Should fetch all suspicious activities ordered by detectedAt DESC when no filters provided")
    void testGetAllSuspiciousActivities_noFilters() {
        SuspiciousActivity sa1 = new SuspiciousActivity(1L, "user1", "10.0.0.1",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME, "Description 1", LocalDateTime.now());
        SuspiciousActivity sa2 = new SuspiciousActivity(2L, "user2", "10.0.0.2",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP, "Description 2", LocalDateTime.now().minusMinutes(5));

        when(suspiciousActivityRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(sa1, sa2));

        List<SuspiciousActivity> results = suspiciousActivityService.getSuspiciousActivities(null, null, null);

        assertEquals(2, results.size());
        ArgumentCaptor<Sort> sortCaptor = ArgumentCaptor.forClass(Sort.class);
        verify(suspiciousActivityRepository).findAll(any(Specification.class), sortCaptor.capture());

        Sort sort = sortCaptor.getValue();
        assertNotNull(sort.getOrderFor("detectedAt"));
        assertEquals(Sort.Direction.DESC, sort.getOrderFor("detectedAt").getDirection());
    }

    @Test
    @DisplayName("Should filter suspicious activities by username")
    void testGetSuspiciousActivities_filterByUsername() {
        SuspiciousActivity sa1 = new SuspiciousActivity(1L, "alice", "10.0.0.1",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME, "Description 1", LocalDateTime.now());

        when(suspiciousActivityRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(sa1));

        List<SuspiciousActivity> results = suspiciousActivityService.getSuspiciousActivities("alice", null, null);

        assertEquals(1, results.size());
        assertEquals("alice", results.get(0).getUsername());
        verify(suspiciousActivityRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should filter suspicious activities by IP address")
    void testGetSuspiciousActivities_filterByIpAddress() {
        SuspiciousActivity sa1 = new SuspiciousActivity(1L, "bob", "192.168.1.100",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_IP, "Description 1", LocalDateTime.now());

        when(suspiciousActivityRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(sa1));

        List<SuspiciousActivity> results = suspiciousActivityService.getSuspiciousActivities(null, "192.168.1.100", null);

        assertEquals(1, results.size());
        assertEquals("192.168.1.100", results.get(0).getIpAddress());
        verify(suspiciousActivityRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should filter suspicious activities by activityType")
    void testGetSuspiciousActivities_filterByActivityType() {
        SuspiciousActivity sa1 = new SuspiciousActivity(1L, "charlie", "10.0.0.5",
                SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES, "Description 1", LocalDateTime.now());

        when(suspiciousActivityRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(sa1));

        List<SuspiciousActivity> results = suspiciousActivityService.getSuspiciousActivities(
                null, null, SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES);

        assertEquals(1, results.size());
        assertEquals(SuspiciousActivityType.SUCCESS_AFTER_MULTIPLE_FAILURES, results.get(0).getActivityType());
        verify(suspiciousActivityRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should combine multiple filters: username, IP address, and activityType")
    void testGetSuspiciousActivities_combineMultipleFilters() {
        SuspiciousActivity sa1 = new SuspiciousActivity(1L, "david", "172.16.0.1",
                SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME, "Description 1", LocalDateTime.now());

        when(suspiciousActivityRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(sa1));

        List<SuspiciousActivity> results = suspiciousActivityService.getSuspiciousActivities(
                "david", "172.16.0.1", SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME);

        assertEquals(1, results.size());
        assertEquals("david", results.get(0).getUsername());
        assertEquals("172.16.0.1", results.get(0).getIpAddress());
        assertEquals(SuspiciousActivityType.MULTIPLE_FAILED_ATTEMPTS_BY_USERNAME, results.get(0).getActivityType());
        verify(suspiciousActivityRepository).findAll(any(Specification.class), any(Sort.class));
    }
}

