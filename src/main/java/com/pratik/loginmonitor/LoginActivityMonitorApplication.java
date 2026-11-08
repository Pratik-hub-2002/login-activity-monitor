package com.pratik.loginmonitor;

import java.time.Clock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
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