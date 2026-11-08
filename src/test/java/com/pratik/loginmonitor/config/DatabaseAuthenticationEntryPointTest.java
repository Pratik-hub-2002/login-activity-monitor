package com.pratik.loginmonitor.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.LoginService;

@ExtendWith(MockitoExtension.class)
class DatabaseAuthenticationEntryPointTest {

    @Mock
    private LoginService loginService;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @Test
    void recordsIncorrectPasswordFailureWithAttemptedUsernameAndIp() {
        DatabaseAuthenticationEntryPoint entryPoint =
                new DatabaseAuthenticationEntryPoint(
                        loginService, clientIpAddressExtractor);
        MockHttpServletRequest request =
                basicRequest("alice", "wrong-password", "192.168.1.20");
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.20");

        entryPoint.commence(
                request, response,
                new BadCredentialsException("invalid credentials"));

        verify(loginService).recordLoginAttempt(
                "alice", "192.168.1.20", LoginStatus.FAILURE);
        assertEquals(401, response.getStatus());
    }

    @Test
    void recordsUnknownUsernameAndDisabledAccountFailuresTheSameWay() {
        DatabaseAuthenticationEntryPoint entryPoint =
                new DatabaseAuthenticationEntryPoint(
                        loginService, clientIpAddressExtractor);

        MockHttpServletRequest unknownRequest =
                basicRequest("missing", "secret", "10.0.0.1");
        when(clientIpAddressExtractor.extract(unknownRequest)).thenReturn("10.0.0.1");
        entryPoint.commence(
                unknownRequest, new MockHttpServletResponse(),
                new BadCredentialsException("bad credentials"));

        MockHttpServletRequest disabledRequest =
                basicRequest("disabled-user", "secret", "10.0.0.2");
        when(clientIpAddressExtractor.extract(disabledRequest)).thenReturn("10.0.0.2");
        entryPoint.commence(
                disabledRequest, new MockHttpServletResponse(),
                new DisabledException("disabled"));

        verify(loginService).recordLoginAttempt(
                "missing", "10.0.0.1", LoginStatus.FAILURE);
        verify(loginService).recordLoginAttempt(
                "disabled-user", "10.0.0.2", LoginStatus.FAILURE);
    }

    @Test
    void doesNotRecordWithoutABasicUsername() {
        DatabaseAuthenticationEntryPoint entryPoint =
                new DatabaseAuthenticationEntryPoint(
                        loginService, clientIpAddressExtractor);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(
                request, response,
                new BadCredentialsException("missing credentials"));

        verify(clientIpAddressExtractor, never()).extract(request);
        verify(loginService, never()).recordLoginAttempt(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any());
        assertEquals(401, response.getStatus());
    }

    @Test
    void recordsOnlyOnceForTheSameRequest() {
        DatabaseAuthenticationEntryPoint entryPoint =
                new DatabaseAuthenticationEntryPoint(
                        loginService, clientIpAddressExtractor);
        MockHttpServletRequest request =
                basicRequest("alice", "wrong-password", "192.168.1.20");
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.20");

        entryPoint.commence(
                request, new MockHttpServletResponse(),
                new BadCredentialsException("bad credentials"));
        entryPoint.commence(
                request, new MockHttpServletResponse(),
                new BadCredentialsException("bad credentials"));

        verify(loginService).recordLoginAttempt(
                "alice", "192.168.1.20", LoginStatus.FAILURE);
    }

    @Test
    void persistenceFailureStillReturnsGenericUnauthorizedResponse() throws Exception {
        DatabaseAuthenticationEntryPoint entryPoint =
                new DatabaseAuthenticationEntryPoint(
                        loginService, clientIpAddressExtractor);
        MockHttpServletRequest request =
                basicRequest("alice", "wrong-password", "192.168.1.20");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(clientIpAddressExtractor.extract(request)).thenReturn("192.168.1.20");
        doThrow(new RuntimeException("database details"))
                .when(loginService)
                .recordLoginAttempt("alice", "192.168.1.20", LoginStatus.FAILURE);

        entryPoint.commence(
                request, response,
                new BadCredentialsException("bad credentials"));

        assertEquals(401, response.getStatus());
        assertEquals(
                "{\"message\":\"Authentication required\"}",
                response.getContentAsString());
    }

    private MockHttpServletRequest basicRequest(
            String username, String password, String remoteAddress) {
        String credentials = Base64.getEncoder().encodeToString(
                (username + ":" + password).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddress);
        request.addHeader("Authorization", "Basic " + credentials);
        return request;
    }
}
