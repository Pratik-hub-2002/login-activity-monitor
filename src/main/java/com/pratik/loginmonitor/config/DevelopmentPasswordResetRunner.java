package com.pratik.loginmonitor.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.repository.UserRepository;

@Component
@Profile("dev")
@ConditionalOnProperty(
        name = "app.dev-password-reset.enabled",
        havingValue = "true",
        matchIfMissing = false)
public class DevelopmentPasswordResetRunner implements CommandLineRunner {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(DevelopmentPasswordResetRunner.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Environment environment;

    public DevelopmentPasswordResetRunner(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            Environment environment) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.environment = environment;
    }

    @Override
    @Transactional
    public void run(String... args) {
        List<PasswordReset> resets = List.of(
                new PasswordReset("testuser", "TEST_USER_PASSWORD"),
                new PasswordReset("testadmin", "TEST_ADMIN_PASSWORD"),
                new PasswordReset("testsuperadmin", "TEST_SUPERADMIN_PASSWORD"));

        List<PasswordUpdate> validatedUpdates = new ArrayList<>();

        for (PasswordReset reset : resets) {
            String password = environment.getProperty(reset.passwordVariable());
            if (password == null || password.isBlank()) {
                LOGGER.warn("Development password reset skipped: required environment variables are missing.");
                return;
            }

            Optional<User> existingUser =
                    userRepository.findByUsername(reset.username());
            if (existingUser.isEmpty()) {
                LOGGER.warn("Development password reset skipped: required test accounts are missing.");
                return;
            }

            validatedUpdates.add(new PasswordUpdate(existingUser.get(), password));
        }

        for (PasswordUpdate update : validatedUpdates) {
            update.user().setPassword(passwordEncoder.encode(update.password()));
            userRepository.save(update.user());
        }

        LOGGER.info("Development password reset completed for configured test accounts.");
    }

    private record PasswordReset(String username, String passwordVariable) {
    }

    private record PasswordUpdate(User user, String password) {
    }
}
