package com.pratik.loginmonitor;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class LoginActivityMonitorApplication {

	public static void main(String[] args) {
		SpringApplication.run(LoginActivityMonitorApplication.class, args);
		System.err.println("Application Started..!");
	}

	@Bean
	public Clock clock() {
		return Clock.systemUTC();
	}
}