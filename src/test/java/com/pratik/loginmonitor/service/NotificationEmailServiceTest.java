package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.doThrow;

import org.junit.jupiter.api.Test;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import com.pratik.loginmonitor.entity.SuspiciousActivity;

class NotificationEmailServiceTest {

    @Test
    void sendOneTimePasswordSuccessfullySendsEmail() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients = new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");

        service.sendOneTimePassword("alice", "alice@example.test", "123456");

        org.mockito.ArgumentCaptor<SimpleMailMessage> messageCaptor =
                org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());
        SimpleMailMessage sent = messageCaptor.getValue();
        assertEquals("alice@example.test", sent.getTo()[0]);
        assertEquals("noreply@example.test", sent.getFrom());
        assertEquals("Login verification code", sent.getSubject());
        org.junit.jupiter.api.Assertions.assertTrue(sent.getText().contains("123456"));
    }

    @Test
    void sendOneTimePasswordPropagatesAuthenticationFailure() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients = new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");
        doThrow(new MailAuthenticationException("Authentication failed"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        assertThrows(
                MailAuthenticationException.class,
                () -> service.sendOneTimePassword("alice", "alice@example.test", "123456"));
    }

    @Test
    void sendOneTimePasswordPropagatesConnectionFailure() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients = new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");
        doThrow(new MailSendException("Connection refused"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        assertThrows(
                MailSendException.class,
                () -> service.sendOneTimePassword("alice", "alice@example.test", "123456"));
    }

    @Test
    void sendOneTimePasswordRejectsMissingRecipient() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients = new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");

        assertThrows(
                IllegalArgumentException.class,
                () -> service.sendOneTimePassword("alice", null, "123456"));
        assertThrows(
                IllegalArgumentException.class,
                () -> service.sendOneTimePassword("alice", "   ", "123456"));
    }

    @Test
    void sendOneTimePasswordThrowsWhenSmtpHostNotConfigured() {
        JavaMailSenderImpl unconfiguredSender = new JavaMailSenderImpl();
        unconfiguredSender.setHost("");
        NotificationRecipients recipients = new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                unconfiguredSender, recipients, "noreply@example.test");

        assertThrows(
                MailSendException.class,
                () -> service.sendOneTimePassword("alice", "alice@example.test", "123456"));
    }

    @Test
    void suspiciousActivityEmailsAdministratorAndMatchingUser() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients = new NotificationRecipients(
                "admin@example.test", "alice=alice@example.test,bob=bob@example.test");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");
        SuspiciousActivity activity = new SuspiciousActivity();
        activity.setUsername("alice");
        activity.setIpAddress("192.0.2.1");
        activity.setReason("multiple failed login attempts");

        service.notifySuspiciousActivity(activity);

        org.mockito.ArgumentCaptor<SimpleMailMessage> messages =
                org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, org.mockito.Mockito.times(2)).send(messages.capture());
        assertEquals("admin@example.test", messages.getAllValues().get(0).getTo()[0]);
        assertEquals("alice@example.test", messages.getAllValues().get(1).getTo()[0]);
        assertEquals("noreply@example.test", messages.getAllValues().get(0).getFrom());
    }

    @Test
    void emailFailureDoesNotEscapeAndCorruptPersistedAlertFlow() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients =
                new NotificationRecipients("admin@example.test", "");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");
        doThrow(new org.springframework.mail.MailSendException("offline"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        service.notifySuspiciousActivity(new SuspiciousActivity());

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    void onlyUsernameAssociatedActivityNotifiesAUser() {
        JavaMailSender mailSender = org.mockito.Mockito.mock(JavaMailSender.class);
        NotificationRecipients recipients =
                new NotificationRecipients("admin@example.test", "alice=alice@example.test");
        NotificationEmailService service = new NotificationEmailService(
                mailSender, recipients, "noreply@example.test");
        SuspiciousActivity activity = new SuspiciousActivity();
        activity.setUsername(null);

        service.notifySuspiciousActivity(activity);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    void rejectsMalformedExternalRecipientMappings() {
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new NotificationRecipients("", "invalid-mapping"));
    }
}
