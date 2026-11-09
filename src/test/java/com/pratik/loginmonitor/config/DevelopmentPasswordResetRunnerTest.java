package com.pratik.loginmonitor.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class DevelopmentPasswordResetRunnerTest {

    @Mock
    private UserRepository userRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private MockEnvironment environment;
    private DevelopmentPasswordResetRunner runner;

    private User testUser;
    private User testAdmin;
    private User testSuperAdmin;

    @BeforeEach
    void setUp() {
        environment = new MockEnvironment();
        runner = new DevelopmentPasswordResetRunner(
                userRepository, passwordEncoder, environment);

        testUser = user("testuser", UserRole.USER, true);
        testAdmin = user("testadmin", UserRole.ADMIN, false);
        testSuperAdmin = user("testsuperadmin", UserRole.SUPERADMIN, true);
    }

    @Test
    void resetsAllPasswordsAndPreservesRoleAndEnabledStatus() {
        environment
                .withProperty("TEST_USER_PASSWORD", "known-user-password")
                .withProperty("TEST_ADMIN_PASSWORD", "known-admin-password")
                .withProperty("TEST_SUPERADMIN_PASSWORD", "known-superadmin-password");

        when(userRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(testUser));
        lenient().when(userRepository.findByUsername("testadmin"))
                .thenReturn(Optional.of(testAdmin));
        lenient().when(userRepository.findByUsername("testsuperadmin"))
                .thenReturn(Optional.of(testSuperAdmin));

        runner.run();

        assertTrue(passwordEncoder.matches(
                "known-user-password", testUser.getPassword()));
        assertTrue(passwordEncoder.matches(
                "known-admin-password", testAdmin.getPassword()));
        assertTrue(passwordEncoder.matches(
                "known-superadmin-password", testSuperAdmin.getPassword()));

        assertEquals(UserRole.USER, testUser.getRole());
        assertTrue(testUser.isEnabled());
        assertEquals(UserRole.ADMIN, testAdmin.getRole());
        assertFalse(testAdmin.isEnabled());
        assertEquals(UserRole.SUPERADMIN, testSuperAdmin.getRole());
        assertTrue(testSuperAdmin.isEnabled());

        verify(userRepository).save(testUser);
        verify(userRepository).save(testAdmin);
        verify(userRepository).save(testSuperAdmin);
    }

    @Test
    void missingPasswordEnvironmentVariablePreventsAllDatabaseChanges() {
        environment
                .withProperty("TEST_USER_PASSWORD", "known-user-password")
                .withProperty("TEST_SUPERADMIN_PASSWORD", "known-superadmin-password");

        when(userRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(testUser));
        lenient().when(userRepository.findByUsername("testadmin"))
                .thenReturn(Optional.of(testAdmin));
        lenient().when(userRepository.findByUsername("testsuperadmin"))
                .thenReturn(Optional.of(testSuperAdmin));

        runner.run();

        verify(userRepository, never()).save(org.mockito.ArgumentMatchers.any(User.class));
        verify(userRepository).findByUsername("testuser");
        verify(userRepository, never()).findByUsername("testadmin");
        verify(userRepository, never()).findByUsername("testsuperadmin");
        assertEquals("existing-encoded-password", testUser.getPassword());
        assertEquals("existing-encoded-password", testAdmin.getPassword());
        assertEquals("existing-encoded-password", testSuperAdmin.getPassword());
    }

    @Test
    void missingExistingAccountPreventsAllDatabaseChanges() {
        environment
                .withProperty("TEST_USER_PASSWORD", "known-user-password")
                .withProperty("TEST_ADMIN_PASSWORD", "known-admin-password")
                .withProperty("TEST_SUPERADMIN_PASSWORD", "known-superadmin-password");

        when(userRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(testUser));
        when(userRepository.findByUsername("testadmin"))
                .thenReturn(Optional.empty());

        runner.run();

        verify(userRepository, never()).save(org.mockito.ArgumentMatchers.any(User.class));
    }

    private User user(String username, UserRole role, boolean enabled) {
        User user = new User();
        user.setUsername(username);
        user.setPassword("existing-encoded-password");
        user.setRole(role);
        user.setEnabled(enabled);
        return user;
    }
}
