
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
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.pratik.loginmonitor.dto.PublicLoginFailureRequest;
import com.pratik.loginmonitor.dto.LoginAttemptResponse;
import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.service.CaptchaService;
import com.pratik.loginmonitor.service.LoginRateLimiter;
import com.pratik.loginmonitor.service.LoginService;

import jakarta.validation.Validator;
import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:logincontracttest;DB_CLOSE_DELAY=-1;MODE=MySQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "app.captcha.hcaptcha.site-key=test-public-site-key",
        "app.captcha.hcaptcha.required=true"
})
class LoginAttemptControllerTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Validator validator;

    @Autowired
    private CaptchaController captchaController;

    @Mock
    private LoginService loginService;

    @Mock
    private LoginRateLimiter loginRateLimiter;

    @Mock
    private CaptchaService captchaService;

    @Mock
    private ClientIpAddressExtractor clientIpAddressExtractor;

    @InjectMocks
    private LoginAttemptController loginAttemptController;

    @Test
    @DisplayName("CAPTCHA config exposes the configured public key and required flag")
    void captchaConfigUsesApplicationConfiguration() {
        HttpServletRequest request =
                org.mockito.Mockito.mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("192.0.2.50");

        ResponseEntity<Map<String, Object>> response =
                captchaController.getCaptchaConfig(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("test-public-site-key", response.getBody().get("siteKey"));
        assertEquals(true, response.getBody().get("required"));
        assertEquals(2, response.getBody().size());
    }

    // 1. GET login attempts
    @Test
    @DisplayName("Should return 200 OK and list of login attempts")
    void testGetLoginAttempts_returnsList() throws Exception {

        LocalDateTime timestamp = LocalDateTime.of(2026, 1, 2, 3, 4, 5);
        LoginAttempt a1 = new LoginAttempt(
                1L,
                "john",
                "192.168.1.1",
                timestamp,
                LoginStatus.SUCCESS
        );

        when(loginService.getLoginAttempts(
                "john", "192.168.1.1", LoginStatus.SUCCESS
        )).thenReturn(List.of(a1));

        Authentication authentication = new TestingAuthenticationToken(
                "john", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        "john", "192.168.1.1", LoginStatus.SUCCESS, authentication
                );

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, ((List<?>) response.getBody()).size());

        LoginAttemptResponse dto =
                ((List<LoginAttemptResponse>) response.getBody()).get(0);
        assertEquals("john", dto.getUsername());
        assertEquals("192.168.1.1", dto.getIpAddress());
        assertEquals(LoginStatus.SUCCESS, dto.getStatus());
        JsonNode json = objectMapper.readTree(
                objectMapper.writeValueAsString(response.getBody()));
        JsonNode item = json.get(0);
        assertEquals(Set.of("id", "username", "ip_address", "timestamp", "status"),
                jsonKeys(item));
        assertEquals("1", item.get("id").toString());
        assertEquals("\"john\"", item.get("username").toString());
        assertEquals("\"192.168.1.1\"", item.get("ip_address").toString());
        assertEquals("\"SUCCESS\"", item.get("status").toString());
        assertEquals("\"2026-01-02T03:04:05\"", item.get("timestamp").toString());

        verify(loginService).getLoginAttempts(
                "john", "192.168.1.1", LoginStatus.SUCCESS
        );

        verifyNoInteractions(
                loginRateLimiter,
                captchaService,
                clientIpAddressExtractor
        );
    }

    @Test
    void testGetLoginAttempts_serializesNullFieldsAsNullProperties() throws Exception {
        when(loginService.getLoginAttempts(null, null, null))
                .thenReturn(List.of(new LoginAttempt(
                        null, "john", null, null, null)));
        Authentication authentication = new TestingAuthenticationToken(
                "john", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(null, null, null, authentication);

        JsonNode item = objectMapper.readTree(
                objectMapper.writeValueAsString(response.getBody())).get(0);
        assertEquals(Set.of("id", "username", "ip_address", "timestamp", "status"),
                jsonKeys(item));
        assertEquals(true, item.get("id").isNull());
        assertEquals(true, item.get("ip_address").isNull());
        assertEquals(true, item.get("timestamp").isNull());
        assertEquals(true, item.get("status").isNull());
    }

    private Set<String> jsonKeys(JsonNode node) {
        return new TreeSet<>(node.propertyNames());
    }

    @Test
    @DisplayName("USER should be able to retrieve only their own login history")
    void testGetLoginAttempts_userOwnHistory() {
        Authentication authentication = new TestingAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        LoginAttempt attempt = new LoginAttempt(
                1L, "alice", "192.168.1.10",
                LocalDateTime.now(), LoginStatus.SUCCESS);
        when(loginService.getLoginAttempts(
                "alice", null, null)).thenReturn(List.of(attempt));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        null, null, null, authentication);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(loginService).getLoginAttempts("alice", null, null);
    }

    @Test
    @DisplayName("USER should not retrieve another user's login history")
    void testGetLoginAttempts_userCannotViewAnotherUser() {
        Authentication authentication = new TestingAuthenticationToken(
                "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        ResponseEntity<?> response =
                loginAttemptController.getLoginAttempts(
                        "bob", null, null, authentication);

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        verify(loginService, never()).getLoginAttempts(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    // 2. Rate limiter blocks request
    @Test
    @DisplayName("Should return 429 when IP is blocked")
    void testPostLoginAttempt_returnsTooManyRequestsWithoutSaving() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.1");

        when(loginRateLimiter.isAllowed("10.0.0.1"))
                .thenReturn(false);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest(
                                "user1", "192.0.2.10", LoginStatus.FAILURE),
                        httpRequest
                );

        assertEquals(
                HttpStatus.TOO_MANY_REQUESTS,
                response.getStatusCode()
        );

        verify(loginRateLimiter).isAllowed("10.0.0.1");

        verify(loginService, never()).recordLoginAttempt(
                anyString(), anyString(), any(LoginStatus.class)
        );

        verifyNoInteractions(loginService, captchaService);
    }

    // 3. Successful login creates a session
    @Test
    @DisplayName("Should record a public failure without treating it as an authenticated success")
    void testPostLoginAttempt_publicFailureReturnsCreated() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.2");

        when(loginRateLimiter.isAllowed("10.0.0.2"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.2"))
                .thenReturn(false);

        LoginAttempt savedAttempt = new LoginAttempt(
                1L,
                "user2",
                "10.0.0.2",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(loginService.recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE
        )).thenReturn(savedAttempt);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest(
                                "user2", "192.0.2.20", LoginStatus.FAILURE),
                        httpRequest
                );

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(
                new LoginAttemptResponse(
                        savedAttempt.getId(),
                        savedAttempt.getUsername(),
                        savedAttempt.getIpAddress(),
                        savedAttempt.getAttemptTime(),
                        savedAttempt.getStatus()),
                response.getBody());

        verify(loginService).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE
        );
    }

    @Test
    @DisplayName("Should never create a public SUCCESS record or authenticated session")
    void testPostLoginAttempt_failureOnlyPayloadNeverUsesSuccessStatus() {
        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.2");
        when(loginRateLimiter.isAllowed("10.0.0.2"))
                .thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.2"))
                .thenReturn(false);

        LoginAttempt savedFailure = new LoginAttempt(
                2L,
                "user2",
                "10.0.0.2",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );
        when(loginService.recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE))
                .thenReturn(savedFailure);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest(
                                "user2", "192.0.2.20", LoginStatus.FAILURE),
                        httpRequest);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        verify(loginService, org.mockito.Mockito.never()).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.SUCCESS);
        verify(loginService, org.mockito.Mockito.times(1)).recordLoginAttempt(
                "user2", "10.0.0.2", LoginStatus.FAILURE);
    }

    // 4. Fifth failure requires CAPTCHA
    @Test
    @DisplayName("Should save fifth failure and require CAPTCHA")
    void testPostLoginAttempt_fifthFailureSavedAndRequiresCaptcha() {

        HttpServletRequest httpRequest =
                org.mockito.Mockito.mock(HttpServletRequest.class);

        when(clientIpAddressExtractor.extract(httpRequest))
                .thenReturn("10.0.0.3");

        when(loginRateLimiter.isAllowed("10.0.0.3"))
                .thenReturn(true);

        when(captchaService.isCaptchaRequired("10.0.0.3"))
                .thenReturn(true);

        LoginAttempt savedAttempt = new LoginAttempt(
                5L,
                "user3",
                "10.0.0.3",
                LocalDateTime.now(),
                LoginStatus.FAILURE
        );

        when(loginService.recordLoginAttempt(
                "user3", "10.0.0.3", LoginStatus.FAILURE
        )).thenReturn(savedAttempt);

        ResponseEntity<?> response =
                loginAttemptController.recordLoginAttempt(
                        new PublicLoginFailureRequest(
                                "user3", "192.0.2.30", LoginStatus.FAILURE),
                        httpRequest
                );

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        Map<String, Object> responseBody =
                (Map<String, Object>) response.getBody();

        assertEquals(true, responseBody.get("captchaRequired"));

        verify(loginService).recordLoginAttempt(
                "user3", "10.0.0.3", LoginStatus.FAILURE
        );

    }

    @Test
    @DisplayName("Required request fields are rejected when missing")
    void testPostLoginAttempt_missingFieldsFailValidation() {
        PublicLoginFailureRequest request = new PublicLoginFailureRequest();

        Set<String> invalidProperties = validator.validate(request).stream()
                .map(violation -> violation.getPropertyPath().toString())
                .collect(java.util.stream.Collectors.toSet());

        assertTrue(invalidProperties.containsAll(
                Set.of("username", "ipAddress", "status", "ipAddressLiteral")));
    }

    @Test
    @DisplayName("An unrecognized status value cannot be deserialized")
    void testPostLoginAttempt_rejectsInvalidStatusValue() {
        String payload = """
                {"username":"user","ip_address":"192.0.2.1","status":"INVALID"}
                """;

        assertThrows(JacksonException.class,
                () -> objectMapper.readValue(payload, PublicLoginFailureRequest.class));
    }

    @Test
    @DisplayName("Public endpoint rejects a forged SUCCESS status")
    void testPostLoginAttempt_rejectsForgedSuccess() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.4");

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new PublicLoginFailureRequest(
                        "user4", "203.0.113.4", LoginStatus.SUCCESS),
                httpRequest);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verifyNoInteractions(loginService, loginRateLimiter, captchaService);
    }

    @Test
    @DisplayName("Valid failure uses the server-derived IP, not the submitted IP")
    void testPostLoginAttempt_validFailureUsesServerIp() {
        HttpServletRequest httpRequest = org.mockito.Mockito.mock(HttpServletRequest.class);
        when(clientIpAddressExtractor.extract(httpRequest)).thenReturn("10.0.0.5");
        when(loginRateLimiter.isAllowed("10.0.0.5")).thenReturn(true);
        when(captchaService.isCaptchaRequired("10.0.0.5")).thenReturn(false);
        LoginAttempt savedAttempt = new LoginAttempt(
                6L, "user5", "10.0.0.5", LocalDateTime.now(), LoginStatus.FAILURE);
        when(loginService.recordLoginAttempt(
                "user5", "10.0.0.5", LoginStatus.FAILURE)).thenReturn(savedAttempt);

        ResponseEntity<?> response = loginAttemptController.recordLoginAttempt(
                new PublicLoginFailureRequest(
                        " user5 ", "198.51.100.99", LoginStatus.FAILURE),
                httpRequest);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        verify(loginRateLimiter).isAllowed("10.0.0.5");
        verify(loginService).recordLoginAttempt(
                "user5", "10.0.0.5", LoginStatus.FAILURE);
    }

    // 5. Invalid status query parameter
    @Test
    @DisplayName("Should return 400 when status parameter is invalid")
    void testHandleTypeMismatch_returnsBadRequest() {

        MethodArgumentTypeMismatchException ex =
                new MethodArgumentTypeMismatchException(
                        "INVALID_STATUS",
                        LoginStatus.class,
                        "status",
                        (MethodParameter) null,
                        null
                );

        ResponseEntity<Map<String, Object>> response =
                loginAttemptController.handleTypeMismatch(ex);

        assertEquals(
                HttpStatus.BAD_REQUEST,
                response.getStatusCode()
        );

        assertNotNull(response.getBody());

        assertEquals(400, response.getBody().get("status"));
        assertEquals("Bad Request", response.getBody().get("error"));
        assertNotNull(response.getBody().get("message"));
    }
}
