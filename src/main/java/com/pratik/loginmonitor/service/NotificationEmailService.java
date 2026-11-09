package com.pratik.loginmonitor.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

import com.pratik.loginmonitor.entity.SuspiciousActivity;

@Service
public class NotificationEmailService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(NotificationEmailService.class);

    private final JavaMailSender mailSender;
    private final NotificationRecipients recipients;
    private final String fromAddress;

    public NotificationEmailService(
            JavaMailSender mailSender,
            NotificationRecipients recipients,
            @Value("${app.notification.from:${spring.mail.username:no-reply@localhost}}")
            String fromAddress) {
        this.mailSender = mailSender;
        this.recipients = recipients;
        if ((fromAddress == null || fromAddress.isBlank() || fromAddress.contains("localhost"))
                && mailSender instanceof JavaMailSenderImpl impl
                && impl.getUsername() != null && !impl.getUsername().isBlank()) {
            this.fromAddress = impl.getUsername();
        } else {
            this.fromAddress = (fromAddress != null && !fromAddress.isBlank()) ? fromAddress : "no-reply@localhost";
        }
    }

    public void sendOneTimePassword(String username, String recipient, String otp) {
        if (recipient == null || recipient.isBlank()) {
            throw new IllegalArgumentException("Recipient email must not be null or blank");
        }
        if (mailSender instanceof JavaMailSenderImpl impl
                && (impl.getHost() == null || impl.getHost().isBlank())) {
            throw new MailSendException("SMTP host is not configured.");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(recipient);
        message.setSubject("Login verification code");
        message.setText("Your one-time login verification code is " + otp
                + ". It expires shortly. If you did not initiate this login, ignore this message.");
        mailSender.send(message);
    }

    public void notifySuspiciousActivity(SuspiciousActivity activity) {
        String administratorEmail = recipients.administratorEmail();
        if (administratorEmail.isBlank()) {
            LOGGER.warn("Suspicious activity notification skipped: administrator email is not configured.");
        } else {
            deliverAlert(administratorEmail, "administrator", activity);
        }

        if (activity.getUsername() != null && !activity.getUsername().isBlank()) {
            String userEmail = recipients.userEmail(activity.getUsername());
            if (userEmail == null || userEmail.isBlank()) {
                LOGGER.warn("Suspicious activity user notification skipped: recipient mapping is not configured.");
            } else {
                deliverAlert(userEmail, "user", activity);
            }
        }
    }

    private void deliverAlert(
            String recipient, String recipientType, SuspiciousActivity activity) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(recipient);
        message.setSubject("Suspicious login activity detected");
        message.setText("Suspicious login activity was detected."
                + "\nReason: " + activity.getReason()
                + "\nIP address: " + activity.getIpAddress()
                + "\nTimestamp: " + activity.getDetectedAt());
        try {
            mailSender.send(message);
        } catch (MailException exception) {
            LOGGER.error(
                    "Could not send suspicious activity email to configured {} recipient; activity remains recorded.",
                    recipientType,
                    exception);
        }
    }
}
