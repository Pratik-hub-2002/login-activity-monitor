package com.pratik.loginmonitor.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF protection specifically for /api/** endpoints to permit testing via tools like Postman,
            // while preserving CSRF protection on any potential browser-session-based web endpoints.
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
            // Allow unauthenticated access to the monitoring REST APIs during development
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }
}

