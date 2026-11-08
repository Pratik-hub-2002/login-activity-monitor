package com.pratik.loginmonitor.controller;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class ClientIpAddressExtractor {

    public String extract(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}