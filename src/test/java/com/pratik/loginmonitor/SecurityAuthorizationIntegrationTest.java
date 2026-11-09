package com.pratik.loginmonitor;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;

import com.pratik.loginmonitor.entity.LoginAttempt;
import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.LoginStatus;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.LoginAttemptRepository;
import com.pratik.loginmonitor.repository.LoginSessionRepository;
import com.pratik.loginmonitor.repository.UserRepository;
import com.pratik.loginmonitor.service.SessionService;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:securityauthorization;DB_CLOSE_DELAY=-1;MODE=MySQL",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "app.captcha.hcaptcha.site-key=integration-public-site-key",
        "app.captcha.hcaptcha.required=false",
        "app.notification.user-emails=alice=alice@example.test"
})
class SecurityAuthorizationIntegrationTest {

    private static final String CLIENT_IP = "127.0.0.1";

    @Autowired
    private WebApplicationContext applicationContext;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Autowired
    private LoginSessionRepository loginSessionRepository;

    @Autowired
    private SessionService sessionService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JavaMailSender mailSender;

    private MockMvc mockMvc;
    private String aliceSession;
    private String adminSession;
    private String superadminSession;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
        userRepository.save(user("alice", UserRole.USER));
        userRepository.save(user("bob", UserRole.USER));
        userRepository.save(user("admin", UserRole.ADMIN));
        userRepository.save(user("superadmin", UserRole.SUPERADMIN));
        aliceSession = sessionService.createSession("alice", CLIENT_IP).getSessionId();
        adminSession = sessionService.createSession("admin", CLIENT_IP).getSessionId();
        superadminSession =
                sessionService.createSession("superadmin", CLIENT_IP).getSessionId();
        loginAttemptRepository.save(new LoginAttempt(
                null, "alice", CLIENT_IP, java.time.LocalDateTime.now(),
                LoginStatus.SUCCESS));
        loginAttemptRepository.save(new LoginAttempt(
                null, "alice", CLIENT_IP, java.time.LocalDateTime.now(),
                LoginStatus.FAILURE));
        loginAttemptRepository.save(new LoginAttempt(
                null, "bob", CLIENT_IP, java.time.LocalDateTime.now(),
                LoginStatus.SUCCESS));
    }

    @Test
    @Transactional
    void anonymousRequestsCannotReadProtectedLoginOrSuspiciousData() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/suspicious"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Transactional
    void captchaConfigurationIsPublicAndUsesConfiguredValues() throws Exception {
        mockMvc.perform(get("/api/captcha/config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.siteKey")
                        .value("integration-public-site-key"))
                .andExpect(jsonPath("$.required").value(false))
                .andExpect(jsonPath("$.secret").doesNotExist());
    }

    @Test
    @Transactional
    void regularUserCanReadOnlyOwnLoginHistoryAndCannotReadSuspiciousLogs()
            throws Exception {
        mockMvc.perform(get("/login").header("X-Session-Id", aliceSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("alice"))
                .andExpect(jsonPath("$.length()").value(2));

        mockMvc.perform(get("/login")
                        .header("X-Session-Id", aliceSession)
                        .param("username", "bob"))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/suspicious")
                        .header("X-Session-Id", aliceSession))
                .andExpect(status().isForbidden());
    }

    @Test
    @Transactional
    void adminAndSuperadminCanReadSuspiciousLogsAndActiveSessions()
            throws Exception {
        mockMvc.perform(get("/suspicious")
                        .header("X-Session-Id", adminSession))
                .andExpect(status().isOk());
        mockMvc.perform(get("/suspicious")
                        .header("X-Session-Id", superadminSession))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/sessions/active")
                        .header("X-Session-Id", adminSession))
                .andExpect(status().isOk());
    }

    @Test
    @Transactional
    void validPasswordRequiresOtpBeforeSessionCreation() throws Exception {
        loginSessionRepository.findBySessionId(aliceSession)
                .ifPresent(loginSessionRepository::delete);
        org.junit.jupiter.api.Assertions.assertTrue(
                sessionService.getActiveSessionsByUsername("alice").isEmpty());

        RequestPostProcessor credentials =
                SecurityMockMvcRequestPostProcessors.httpBasic(
                        "alice", "test-password");
        mockMvc.perform(post("/api/auth/login").with(credentials))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.otpRequired").value(true))
                .andExpect(jsonPath("$.otp").doesNotExist());

        org.mockito.ArgumentCaptor<SimpleMailMessage> sentMessage =
                org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(sentMessage.capture());
        Matcher code = Pattern.compile("\\b(\\d{6})\\b")
                .matcher(sentMessage.getValue().getText());
        org.junit.jupiter.api.Assertions.assertTrue(code.find());
        String otp = code.group(1);

        mockMvc.perform(post("/api/auth/otp/verify")
                        .with(credentials)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"otp\":\"" + otp + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.session.sessionId").isNotEmpty())
                .andExpect(jsonPath("$.role").value("USER"));
        org.junit.jupiter.api.Assertions.assertEquals(
                1, sessionService.getActiveSessionsByUsername("alice").size());
    }

    @Test
    @Transactional
    void invalidPasswordCannotStartOtpFlow() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic(
                                "alice", "wrong-password")))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(mailSender);
    }

    private User user(String username, UserRole role) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode("test-password"));
        user.setRole(role);
        user.setEnabled(true);
        return user;
    }

    @TestConfiguration
    static class TestMailConfiguration {
        @Bean
        @Primary
        JavaMailSender testJavaMailSender() {
            return mock(JavaMailSender.class);
        }
    }
}
