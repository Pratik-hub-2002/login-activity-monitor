package com.pratik.loginmonitor.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.UserRepository;
import com.pratik.loginmonitor.service.NotificationRecipients;

@Component
public class UserInitializer implements CommandLineRunner {

    private static final Logger logger =
            LoggerFactory.getLogger(UserInitializer.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final NotificationRecipients notificationRecipients;

    public UserInitializer(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            NotificationRecipients notificationRecipients) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.notificationRecipients = notificationRecipients;
    }

    @Override
    public void run(String... args) {
        logger.info("========== USER INITIALIZER STARTED ==========");

        initialize("USER_USERNAME", "USER_PASSWORD", UserRole.USER);
        initialize("ADMIN_USERNAME", "ADMIN_PASSWORD", UserRole.ADMIN);
        initialize("SUPERADMIN_USERNAME", "SUPERADMIN_PASSWORD", UserRole.SUPERADMIN);

        logger.info("========== USER INITIALIZER COMPLETED ==========");
    }

    private void initialize(
            String usernameVariable,
            String passwordVariable,
            UserRole role) {

        String username = System.getenv(usernameVariable);
        String password = System.getenv(passwordVariable);

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {
            logger.warn("Skipping {} initialization: environment variables missing.",
                    role);
            return;
        }

        String emailAddress = notificationRecipients.userEmail(username);
        User existingUser = userRepository.findByUsername(username).orElse(null);
        if (existingUser != null) {
            if (emailAddress != null
                    && !emailAddress.equals(existingUser.getEmailAddress())) {
                existingUser.setEmailAddress(emailAddress);
                userRepository.save(existingUser);
                logger.info("{} user '{}' email configuration updated.", role, username);
                return;
            }
            logger.info("{} user '{}' already exists. Skipping creation.",
                    role, username);
            return;
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(true);
        user.setEmailAddress(emailAddress);

        userRepository.save(user);

        logger.info("{} user '{}' created successfully.", role, username);
    }
}