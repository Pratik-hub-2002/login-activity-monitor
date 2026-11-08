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

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private LoginAttemptRepository loginAttemptRepository;

    @Mock
    private DetectionService detectionService;

    @InjectMocks
    private LoginService loginService;

    @Test
    @DisplayName("Should save attempt and call DetectionService for SUCCESS attempt")
    void testRecordLoginAttempt_success_callsDetectionService() {
        LoginAttempt savedAttempt = new LoginAttempt(1L, "user1", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(savedAttempt);

        LoginAttempt result = loginService.recordLoginAttempt("user1", "10.0.0.1", LoginStatus.SUCCESS);

        assertNotNull(result);
        assertEquals(LoginStatus.SUCCESS, result.getStatus());
        verify(loginAttemptRepository).save(any(LoginAttempt.class));
        verify(detectionService).checkSuspiciousActivity(savedAttempt);
    }

    @Test
    @DisplayName("Should save attempt and call DetectionService for FAILURE attempt")
    void testRecordLoginAttempt_failure_callsDetectionService() {
        LoginAttempt savedAttempt = new LoginAttempt(2L, "user2", "10.0.0.2", LocalDateTime.now(), LoginStatus.FAILURE);
        when(loginAttemptRepository.save(any(LoginAttempt.class))).thenReturn(savedAttempt);

        LoginAttempt result = loginService.recordLoginAttempt("user2", "10.0.0.2", LoginStatus.FAILURE);

        assertNotNull(result);
        assertEquals(LoginStatus.FAILURE, result.getStatus());
        verify(loginAttemptRepository).save(any(LoginAttempt.class));
        verify(detectionService).checkSuspiciousActivity(savedAttempt);
    }

    @Test
    @DisplayName("Should fetch all login attempts ordered by attemptTime DESC when no filters provided")
    void testGetAllLoginAttempts_noFilters() {
        LoginAttempt a1 = new LoginAttempt(1L, "user1", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        LoginAttempt a2 = new LoginAttempt(2L, "user2", "10.0.0.2", LocalDateTime.now().minusMinutes(1), LoginStatus.FAILURE);

        when(loginAttemptRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(a1, a2));

        List<LoginAttempt> results = loginService.getLoginAttempts(null, null, null);

        assertEquals(2, results.size());
        ArgumentCaptor<Sort> sortCaptor = ArgumentCaptor.forClass(Sort.class);
        verify(loginAttemptRepository).findAll(any(Specification.class), sortCaptor.capture());

        Sort sort = sortCaptor.getValue();
        assertNotNull(sort.getOrderFor("attemptTime"));
        assertEquals(Sort.Direction.DESC, sort.getOrderFor("attemptTime").getDirection());
    }

    @Test
    @DisplayName("Should filter login attempts by username")
    void testGetLoginAttempts_filterByUsername() {
        LoginAttempt a1 = new LoginAttempt(1L, "alice", "10.0.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);

        when(loginAttemptRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(a1));

        List<LoginAttempt> results = loginService.getLoginAttempts("alice", null, null);

        assertEquals(1, results.size());
        assertEquals("alice", results.get(0).getUsername());
        verify(loginAttemptRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should filter login attempts by IP address")
    void testGetLoginAttempts_filterByIpAddress() {
        LoginAttempt a1 = new LoginAttempt(1L, "bob", "192.168.1.100", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(a1));

        List<LoginAttempt> results = loginService.getLoginAttempts(null, "192.168.1.100", null);

        assertEquals(1, results.size());
        assertEquals("192.168.1.100", results.get(0).getIpAddress());
        verify(loginAttemptRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should filter login attempts by status")
    void testGetLoginAttempts_filterByStatus() {
        LoginAttempt a1 = new LoginAttempt(1L, "charlie", "10.0.0.3", LocalDateTime.now(), LoginStatus.FAILURE);

        when(loginAttemptRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(a1));

        List<LoginAttempt> results = loginService.getLoginAttempts(null, null, LoginStatus.FAILURE);

        assertEquals(1, results.size());
        assertEquals(LoginStatus.FAILURE, results.get(0).getStatus());
        verify(loginAttemptRepository).findAll(any(Specification.class), any(Sort.class));
    }

    @Test
    @DisplayName("Should combine multiple filters: username, IP address, and status")
    void testGetLoginAttempts_combineMultipleFilters() {
        LoginAttempt a1 = new LoginAttempt(1L, "david", "172.16.0.1", LocalDateTime.now(), LoginStatus.SUCCESS);

        when(loginAttemptRepository.findAll(any(Specification.class), any(Sort.class)))
                .thenReturn(List.of(a1));

        List<LoginAttempt> results = loginService.getLoginAttempts("david", "172.16.0.1", LoginStatus.SUCCESS);

        assertEquals(1, results.size());
        assertEquals("david", results.get(0).getUsername());
        assertEquals("172.16.0.1", results.get(0).getIpAddress());
        assertEquals(LoginStatus.SUCCESS, results.get(0).getStatus());
        verify(loginAttemptRepository).findAll(any(Specification.class), any(Sort.class));
    }
}
