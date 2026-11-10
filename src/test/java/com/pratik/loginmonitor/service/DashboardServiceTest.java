package com.pratik.loginmonitor.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.pratik.loginmonitor.dto.DashboardResponse;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.SuspiciousActivityRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private SuspiciousActivityRepository suspiciousActivityRepository;

    @InjectMocks
    private DashboardService dashboardService;

    @Test
    @DisplayName("Should return accurate dashboard statistics using database count queries")
    void testGetDashboardStatistics_returnsAccurateCounts() {
        when(loginAttemptRepository.count()).thenReturn(150L);
        when(loginAttemptRepository.countByStatus(LoginStatus.SUCCESS)).thenReturn(112L);
        when(loginAttemptRepository.countByStatus(LoginStatus.FAILURE)).thenReturn(38L);
        when(suspiciousActivityRepository.count()).thenReturn(7L);

        DashboardResponse stats = dashboardService.getDashboardStatistics();

        assertNotNull(stats);
        assertEquals(150L, stats.getTotalLoginAttempts());
        assertEquals(112L, stats.getSuccessfulLoginAttempts());
        assertEquals(38L, stats.getFailedLoginAttempts());
        assertEquals(7L, stats.getTotalSuspiciousActivities());

        verify(loginAttemptRepository).count();
        verify(loginAttemptRepository).countByStatus(LoginStatus.SUCCESS);
        verify(loginAttemptRepository).countByStatus(LoginStatus.FAILURE);
        verify(suspiciousActivityRepository).count();
    }

    @Test
    @DisplayName("Should return zero counts when database is empty")
    void testGetDashboardStatistics_emptyDatabase_returnsZeros() {
        when(loginAttemptRepository.count()).thenReturn(0L);
        when(loginAttemptRepository.countByStatus(LoginStatus.SUCCESS)).thenReturn(0L);
        when(loginAttemptRepository.countByStatus(LoginStatus.FAILURE)).thenReturn(0L);
        when(suspiciousActivityRepository.count()).thenReturn(0L);

        DashboardResponse stats = dashboardService.getDashboardStatistics();

        assertNotNull(stats);
        assertEquals(0L, stats.getTotalLoginAttempts());
        assertEquals(0L, stats.getSuccessfulLoginAttempts());
        assertEquals(0L, stats.getFailedLoginAttempts());
        assertEquals(0L, stats.getTotalSuspiciousActivities());
    }

    @Test
    @DisplayName("Regular user statistics count only the authenticated user's attempts")
    void userDashboardStatisticsAreScopedToUser() {
        when(loginAttemptRepository.countByUsername("alice")).thenReturn(3L);
        when(loginAttemptRepository.countByUsernameAndStatus(
                "alice", LoginStatus.SUCCESS)).thenReturn(2L);
        when(loginAttemptRepository.countByUsernameAndStatus(
                "alice", LoginStatus.FAILURE)).thenReturn(1L);
        when(suspiciousActivityRepository.countByUsername("alice")).thenReturn(0L);

        DashboardResponse stats =
                dashboardService.getDashboardStatistics("alice", false);

        assertEquals(3L, stats.getTotalLoginAttempts());
        assertEquals(2L, stats.getSuccessfulLoginAttempts());
        assertEquals(1L, stats.getFailedLoginAttempts());
        assertEquals(0L, stats.getTotalSuspiciousActivities());
        verify(loginAttemptRepository).countByUsername("alice");
    }
}
