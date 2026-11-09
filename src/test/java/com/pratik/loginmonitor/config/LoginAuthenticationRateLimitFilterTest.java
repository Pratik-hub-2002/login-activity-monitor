package com.pratik.loginmonitor.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import jakarta.servlet.FilterChain;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.service.LoginRateLimiter;

class LoginAuthenticationRateLimitFilterTest {

    @Test
    void throttlesTheSixthAuthenticationRequestBeforeOtherLoginFilters() throws Exception {
        LoginRateLimiter rateLimiter = org.mockito.Mockito.mock(LoginRateLimiter.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/api/auth/login");
        request.setServletPath("/api/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);
        when(ipExtractor.extract(request)).thenReturn("192.0.2.1");
        when(rateLimiter.isAllowed("192.0.2.1")).thenReturn(false);

        new LoginAuthenticationRateLimitFilter(rateLimiter, ipExtractor)
                .doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        verify(rateLimiter).isAllowed("192.0.2.1");
        verifyNoInteractions(chain);
    }

    @Test
    void doesNotRateLimitGetRequests() throws Exception {
        LoginRateLimiter rateLimiter = org.mockito.Mockito.mock(LoginRateLimiter.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/api/auth/login");
        request.setServletPath("/api/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new LoginAuthenticationRateLimitFilter(rateLimiter, ipExtractor)
                .doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verifyNoInteractions(rateLimiter, ipExtractor);
    }

    @Test
    void rateLimitsOtpVerificationAsAnAuthenticationAttempt() throws Exception {
        LoginRateLimiter rateLimiter = org.mockito.Mockito.mock(LoginRateLimiter.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/api/auth/otp/verify");
        request.setServletPath("/api/auth/otp/verify");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        when(ipExtractor.extract(request)).thenReturn("192.0.2.2");
        when(rateLimiter.isAllowed("192.0.2.2")).thenReturn(true);

        new LoginAuthenticationRateLimitFilter(rateLimiter, ipExtractor)
                .doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(rateLimiter).isAllowed("192.0.2.2");
    }
}
