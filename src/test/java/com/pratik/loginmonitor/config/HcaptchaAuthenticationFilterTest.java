package com.pratik.loginmonitor.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;

import com.pratik.loginmonitor.controller.ClientIpAddressExtractor;
import com.pratik.loginmonitor.service.CaptchaService;

class HcaptchaAuthenticationFilterTest {

    @Test
    void captchaIsNotRequiredBeforeFailureThreshold() throws Exception {
        CaptchaService captchaService = org.mockito.Mockito.mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request = loginRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        when(ipExtractor.extract(request)).thenReturn("192.0.2.1");
        when(captchaService.isCaptchaRequired("192.0.2.1")).thenReturn(false);

        filter(captchaService, ipExtractor).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(captchaService, never()).verifyCaptcha(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void invalidCaptchaIsRejectedBeforeAuthentication() throws Exception {
        CaptchaService captchaService = org.mockito.Mockito.mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request = loginRequest();
        request.addHeader("X-Captcha-Token", "invalid");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        when(ipExtractor.extract(request)).thenReturn("192.0.2.1");
        when(captchaService.isCaptchaRequired("192.0.2.1")).thenReturn(true);
        when(captchaService.verifyCaptcha("192.0.2.1", "invalid")).thenReturn(false);

        filter(captchaService, ipExtractor).doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verify(captchaService).verifyCaptcha("192.0.2.1", "invalid");
        verify(captchaService, never()).verifyCaptcha("192.0.2.1", null);
    }

    @Test
    void missingCaptchaTokenIsRejectedWhenRequired() throws Exception {
        CaptchaService captchaService = org.mockito.Mockito.mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request = loginRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        when(ipExtractor.extract(request)).thenReturn("192.0.2.1");
        when(captchaService.isCaptchaRequired("192.0.2.1")).thenReturn(true);
        when(captchaService.verifyCaptcha("192.0.2.1", null)).thenReturn(false);

        filter(captchaService, ipExtractor).doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        verify(captchaService).verifyCaptcha("192.0.2.1", null);
    }

    @Test
    void validCaptchaAllowsAuthenticationToContinue() throws Exception {
        CaptchaService captchaService = org.mockito.Mockito.mock(CaptchaService.class);
        ClientIpAddressExtractor ipExtractor =
                org.mockito.Mockito.mock(ClientIpAddressExtractor.class);
        MockHttpServletRequest request = loginRequest();
        request.addHeader("X-Captcha-Token", "valid");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        when(ipExtractor.extract(request)).thenReturn("192.0.2.1");
        when(captchaService.isCaptchaRequired("192.0.2.1")).thenReturn(true);
        when(captchaService.verifyCaptcha("192.0.2.1", "valid")).thenReturn(true);

        filter(captchaService, ipExtractor).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(captchaService).verifyCaptcha("192.0.2.1", "valid");
    }

    private HcaptchaAuthenticationFilter filter(
            CaptchaService captchaService,
            ClientIpAddressExtractor ipExtractor) {
        return new HcaptchaAuthenticationFilter(captchaService, ipExtractor);
    }

    private MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/api/auth/login");
        request.setServletPath("/api/auth/login");
        return request;
    }
}
