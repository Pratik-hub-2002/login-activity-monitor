package com.pratik.loginmonitor.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class HcaptchaVerifierTest {

    @Test
    void providerSuccessResultIsAccepted() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://api.hcaptcha.com/siteverify"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("secret=configured-secret")))
                .andExpect(content().string(containsString("response=response-token")))
                .andExpect(content().string(containsString("remoteip=192.0.2.1")))
                .andRespond(withSuccess(
                        "{\"success\":true}", MediaType.APPLICATION_JSON));

        HcaptchaVerifier verifier = new HcaptchaVerifier(builder, "configured-secret");

        assertTrue(verifier.verify("response-token", "192.0.2.1"));
        server.verify();
    }

    @Test
    void providerFailureIsRejected() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://api.hcaptcha.com/siteverify"))
                .andRespond(withSuccess(
                        "{\"success\":false}", MediaType.APPLICATION_JSON));

        HcaptchaVerifier verifier = new HcaptchaVerifier(builder, "configured-secret");

        assertFalse(verifier.verify("invalid-token", "192.0.2.1"));
        server.verify();
    }

    @Test
    void missingSecretFailsClosedWithoutCallingProvider() {
        HcaptchaVerifier verifier = new HcaptchaVerifier(
                RestClient.builder(), "");

        assertFalse(verifier.verify("response-token", "192.0.2.1"));
    }
}
