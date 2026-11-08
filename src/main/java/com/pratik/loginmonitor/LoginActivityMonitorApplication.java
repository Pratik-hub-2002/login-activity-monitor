package com.pratik.loginmonitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class LoginActivityMonitorApplication {

	public static void main(String[] args) {
		SpringApplication.run(LoginActivityMonitorApplication.class, args);
		System.err.println("Application Started..!");
	}

}
