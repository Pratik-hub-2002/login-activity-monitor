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

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginAttemptControllerTest {

    @Mock
    private LoginService loginService;

    @InjectMocks
    private LoginAttemptController loginAttemptController;

    @Test
    @DisplayName("Should return 200 OK and list of login attempts from service")
    void testGetLoginAttempts_returnsList() {
        LoginAttempt a1 = new LoginAttempt(1L, "john", "192.168.1.1", LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS))
                .thenReturn(List.of(a1));

        ResponseEntity<List<LoginAttempt>> response = loginAttemptController.getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        verify(loginService).getLoginAttempts("john", "192.168.1.1", LoginStatus.SUCCESS);
    }

    @Test
    @DisplayName("Should return 400 Bad Request when status parameter is invalid")
    void testHandleTypeMismatch_returnsBadRequest() {
        MethodArgumentTypeMismatchException ex = new MethodArgumentTypeMismatchException(
                "INVALID_STATUS",
                LoginStatus.class,
                "status",
                (MethodParameter) null,
                null
        );

        ResponseEntity<Map<String, Object>> response = loginAttemptController.handleTypeMismatch(ex);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(400, response.getBody().get("status"));
        assertEquals("Bad Request", response.getBody().get("error"));
        assertNotNull(response.getBody().get("message"));
    }
}

