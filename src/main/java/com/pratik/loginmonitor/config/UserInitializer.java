package com.pratik.loginmonitor.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.pratik.loginmonitor.entity.User;
import com.pratik.loginmonitor.enums.UserRole;
import com.pratik.loginmonitor.repository.UserRepository;

@Component
public class UserInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserInitializer(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        initialize("USER_USERNAME", "USER_PASSWORD", UserRole.USER);
        initialize("ADMIN_USERNAME", "ADMIN_PASSWORD", UserRole.ADMIN);
        initialize("SUPERADMIN_USERNAME", "SUPERADMIN_PASSWORD", UserRole.SUPERADMIN);
    }

    private void initialize(String usernameVariable, String passwordVariable, UserRole role) {
        String username = System.getenv(usernameVariable);
        String password = System.getenv(passwordVariable);

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {
            return;
        }

        if (userRepository.findByUsername(username).isPresent()) {
            return;
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);
        user.setEnabled(true);
        userRepository.save(user);
    }
}
