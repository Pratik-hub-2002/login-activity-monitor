package com.pratik.loginmonitor.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class NotificationRecipients {

    private final String administratorEmail;
    private final Map<String, String> userEmails;

    public NotificationRecipients(
            @Value("${app.notification.admin-email:}") String administratorEmail,
            @Value("${app.notification.user-emails:}") String configuredUserEmails) {
        this.administratorEmail = administratorEmail.trim();
        this.userEmails = parseUserEmails(configuredUserEmails);
    }

    public String administratorEmail() {
        return administratorEmail;
    }

    public String userEmail(String username) {
        return userEmails.get(username);
    }

    private Map<String, String> parseUserEmails(String configured) {
        Map<String, String> emails = new HashMap<>();
        if (configured == null || configured.isBlank()) {
            return Map.of();
        }

        for (String mapping : configured.split(",")) {
            int separator = mapping.indexOf('=');
            if (separator <= 0 || separator == mapping.length() - 1) {
                throw new IllegalArgumentException(
                        "APP_NOTIFICATION_USER_EMAILS must contain username=email entries");
            }
            String username = mapping.substring(0, separator).trim();
            String email = mapping.substring(separator + 1).trim();
            if (username.isEmpty() || email.isEmpty()) {
                throw new IllegalArgumentException(
                        "APP_NOTIFICATION_USER_EMAILS must contain username=email entries");
            }
            emails.put(username, email);
        }
        return Map.copyOf(emails);
    }
}
