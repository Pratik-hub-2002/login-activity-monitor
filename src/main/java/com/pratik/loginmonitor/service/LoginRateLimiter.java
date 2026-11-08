package com.pratik.loginmonitor.service;

import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class LoginRateLimiter {

    private static final long WINDOW_DURATION_MILLIS = 60_000;
    private static final int MAX_REQUESTS = 5;

    private final Clock clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public LoginRateLimiter(Clock clock) {
        this.clock = clock;
    }

    public boolean isAllowed(String ipAddress) {
        long now = clock.instant().toEpochMilli();

        Window updatedWindow = windows.compute(ipAddress, (key, window) -> {
            if (window == null || now - window.windowStartMillis >= WINDOW_DURATION_MILLIS) {
                return new Window(now, 1, true);
            }

            if (window.requestCount >= MAX_REQUESTS) {
                return new Window(window.windowStartMillis, window.requestCount, false);
            }

            return new Window(window.windowStartMillis, window.requestCount + 1, true);
        });

        return updatedWindow.allowed;
    }

    private record Window(long windowStartMillis, int requestCount, boolean allowed) {
    }
}
