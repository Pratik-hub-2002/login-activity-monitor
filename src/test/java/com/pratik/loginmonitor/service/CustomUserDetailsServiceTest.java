package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void loadsDatabaseUserAndRole() {
        User user = databaseUser("alice", "secret", UserRole.ADMIN, true);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        CustomUserDetailsService service = new CustomUserDetailsService(userRepository);

        UserDetails details = service.loadUserByUsername("alice");

        assertEquals("alice", details.getUsername());
        assertTrue(details.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void rejectsMissingDatabaseUser() {
        when(userRepository.findByUsername("missing"))
                .thenReturn(Optional.empty());
        CustomUserDetailsService service = new CustomUserDetailsService(userRepository);

        assertThrows(UsernameNotFoundException.class,
                () -> service.loadUserByUsername("missing"));
    }

    @Test
    void acceptsValidDatabasePassword() {
        User user = databaseUser("alice", "secret", UserRole.USER, true);
        user.setPassword(passwordEncoder.encode("secret"));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        CustomUserDetailsService service = new CustomUserDetailsService(userRepository);
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(service);
        provider.setPasswordEncoder(passwordEncoder);

        assertTrue(provider.authenticate(
                        UsernamePasswordAuthenticationToken.unauthenticated(
                                "alice", "secret"))
                .isAuthenticated());
    }

    @Test
    void rejectsIncorrectPassword() {
        User user = databaseUser("alice", "secret", UserRole.USER, true);
        user.setPassword(passwordEncoder.encode("secret"));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        CustomUserDetailsService service = new CustomUserDetailsService(userRepository);
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(service);
        provider.setPasswordEncoder(passwordEncoder);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "alice", "wrong-password")));
    }

    @Test
    void rejectsDisabledAccount() {
        User user = databaseUser("alice", "secret", UserRole.USER, false);
        user.setPassword(passwordEncoder.encode("secret"));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        CustomUserDetailsService service = new CustomUserDetailsService(userRepository);
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(service);
        provider.setPasswordEncoder(passwordEncoder);

        assertThrows(DisabledException.class, () -> provider.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "alice", "secret")));
    }

    private User databaseUser(
            String username, String password, UserRole role, boolean enabled) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setRole(role);
        user.setEnabled(enabled);
        return user;
    }
}
