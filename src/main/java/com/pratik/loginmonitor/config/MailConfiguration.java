package com.pratik.loginmonitor.config;

import java.util.Properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

@Configuration
public class MailConfiguration {

    @Bean
    public JavaMailSender javaMailSender(
            @Value("${spring.mail.host:}") String host,
            @Value("${spring.mail.port:587}") int port,
            @Value("${spring.mail.username:}") String username,
            @Value("${spring.mail.password:}") String password,
            @Value("${spring.mail.properties.mail.smtp.auth:true}") boolean smtpAuth,
            @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}") boolean startTls) {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);

        Properties mailProperties = new Properties();
        mailProperties.setProperty("mail.smtp.auth", Boolean.toString(smtpAuth));
        if (port == 465) {
            mailProperties.setProperty("mail.smtp.ssl.enable", "true");
            mailProperties.setProperty("mail.smtp.starttls.enable", "false");
        } else {
            mailProperties.setProperty(
                    "mail.smtp.starttls.enable", Boolean.toString(startTls));
            mailProperties.setProperty(
                    "mail.smtp.starttls.required", Boolean.toString(startTls));
        }

        // Standard timeouts to prevent indefinite thread blocking
        mailProperties.setProperty("mail.smtp.connectiontimeout", "5000");
        mailProperties.setProperty("mail.smtp.timeout", "5000");
        mailProperties.setProperty("mail.smtp.writetimeout", "5000");

        if (host != null && !host.isBlank()) {
            mailProperties.setProperty("mail.smtp.ssl.trust", host);
        }
        mailSender.setJavaMailProperties(mailProperties);
        return mailSender;
    }
}
