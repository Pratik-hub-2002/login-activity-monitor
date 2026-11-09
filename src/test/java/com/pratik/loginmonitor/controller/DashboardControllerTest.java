package com.pratik.loginmonitor.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.pratik.loginmonitor.dto.DashboardResponse;
import com.pratik.loginmonitor.service.DashboardService;

@ExtendWith(MockitoExtension.class)
class DashboardControllerTest {

    @Mock
    private DashboardService dashboardService;

    @InjectMocks
    private DashboardController controller;

    @Test
    void regularUserDashboardIsScopedToAuthenticatedUsername() {
        Authentication authentication = new TestingAuthenticationToken(
                "alice", null,
                java.util.List.of(new SimpleGrantedAuthority("ROLE_USER")));
        DashboardResponse expected = new DashboardResponse(2, 1, 1, 0);
        when(dashboardService.getDashboardStatistics("alice", false))
                .thenReturn(expected);

        ResponseEntity<DashboardResponse> response =
                controller.getDashboardStatistics(authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(expected, response.getBody());
        verify(dashboardService).getDashboardStatistics("alice", false);
    }

    @Test
    void adminDashboardUsesSystemWideStatistics() {
        Authentication authentication = new TestingAuthenticationToken(
                "admin", null,
                java.util.List.of(new SimpleGrantedAuthority("ROLE_SUPERADMIN")));
        DashboardResponse expected = new DashboardResponse(10, 7, 3, 2);
        when(dashboardService.getDashboardStatistics("admin", true))
                .thenReturn(expected);

        ResponseEntity<DashboardResponse> response =
                controller.getDashboardStatistics(authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(dashboardService).getDashboardStatistics("admin", true);
    }

    @Test
    void unauthenticatedDashboardRequestIsRejected() {
        ResponseEntity<DashboardResponse> response =
                controller.getDashboardStatistics(null);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        verify(dashboardService, never()).getDashboardStatistics(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyBoolean());
    }
}
