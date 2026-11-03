package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.service.siem.SiemAuthTelemetry;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestCorrelationFilterTest {
    private final RequestCorrelationFilter filter = new RequestCorrelationFilter(new IpAddressResolver("172.30.0.0/24"));

    private MockHttpServletRequest request(String remote, String trace) {
        var request = new MockHttpServletRequest("GET", "/api/health");
        request.setRemoteAddr(remote);
        if (trace != null) request.addHeader("X-Request-ID", trace);
        return request;
    }

    @Test void untrustedPeerCannotChooseTraceEvenWithForgedForwardedHeaders() throws Exception {
        var request = request("203.0.113.20", "untrusted-correlation-canary");
        request.addHeader("X-Forwarded-For", "172.30.0.8");
        request.addHeader("X-Real-IP", "172.30.0.8");
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> {
            assertThat(MDC.get("traceId")).isEqualTo(response.getHeader("X-Request-ID"));
            assertThat(MDC.get("traceId")).isNotEqualTo("untrusted-correlation-canary");
            assertThat(UUID.fromString(MDC.get("traceId"))).isNotNull();
        });
        assertThat(MDC.get("traceId")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"172.30.0.8", "::ffff:172.30.0.8"})
    void trustedImmediatePeerPreservesSafeProxyTraceAndSeparateAuthRequestId(String remote) throws Exception {
        var response = new MockHttpServletResponse();
        filter.doFilter(request(remote, "proxy-correlation-1234"), response, (req, res) -> {
            assertThat(MDC.get("traceId")).isEqualTo("proxy-correlation-1234");
            var authId = req.getAttribute(SiemAuthTelemetry.REQUEST_ID);
            assertThat(authId).isInstanceOf(String.class).isNotEqualTo("proxy-correlation-1234");
            assertThat(UUID.fromString((String) authId)).isNotNull();
        });
        assertThat(response.getHeader("X-Request-ID")).isEqualTo("proxy-correlation-1234");
        assertThat(MDC.get("traceId")).isNull();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "short", "bad trace id", "trace-\r\n-injection", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void trustedPeerStillCannotSupplyMissingMalformedOrOverlongTrace(String supplied) throws Exception {
        var response = new MockHttpServletResponse();
        filter.doFilter(request("172.30.0.8", supplied), response, (req, res) -> {});
        String trace = response.getHeader("X-Request-ID");
        assertThat(trace).isNotEqualTo(supplied);
        assertThat(UUID.fromString(trace)).isNotNull();
    }

    @Test void emptyTrustConfigurationDoesNotAcceptLoopbackClientTrace() throws Exception {
        var response = new MockHttpServletResponse();
        new RequestCorrelationFilter(new IpAddressResolver("")).doFilter(
                request("127.0.0.1", "caller-trace-1234"), response, (req, res) -> {});
        assertThat(response.getHeader("X-Request-ID")).isNotEqualTo("caller-trace-1234");
    }

    @Test void reusedUntrustedHeaderCannotCollapseTwoRequestsIntoOneTrace() throws Exception {
        var first = new MockHttpServletResponse();
        var second = new MockHttpServletResponse();
        var one = request("203.0.113.20", "reused-caller-trace");
        var two = request("203.0.113.20", "reused-caller-trace");
        filter.doFilter(one, first, (req, res) -> {});
        filter.doFilter(two, second, (req, res) -> {});
        assertThat(first.getHeader("X-Request-ID")).isNotEqualTo(second.getHeader("X-Request-ID"));
        assertThat(one.getAttribute(SiemAuthTelemetry.REQUEST_ID)).isNotEqualTo(two.getAttribute(SiemAuthTelemetry.REQUEST_ID));
    }

    @Test void generatedResponseAndSecurityErrorTraceRemainConsistent() throws Exception {
        var mapper = new ObjectMapper().findAndRegisterModules();
        var response = new MockHttpServletResponse();
        filter.doFilter(request("203.0.113.20", "untrusted-correlation-canary"), response, (req, res) ->
                new SecurityErrorResponseWriter(mapper).write(response, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Can dang nhap."));
        String bodyTrace = mapper.readTree(response.getContentAsString(StandardCharsets.UTF_8)).path("traceId").asText();
        assertThat(bodyTrace).isEqualTo(response.getHeader("X-Request-ID")).isNotEqualTo("untrusted-correlation-canary");
        assertThat(MDC.get("traceId")).isNull();
    }

    @Test void mdcIsRemovedWhenTheDownstreamChainThrows() {
        assertThatThrownBy(() -> filter.doFilter(request("172.30.0.8", "proxy-correlation-1234"),
                new MockHttpServletResponse(), (req, res) -> {
                    assertThat(MDC.get("traceId")).isEqualTo("proxy-correlation-1234");
                    throw new jakarta.servlet.ServletException("synthetic failure");
                })).isInstanceOf(jakarta.servlet.ServletException.class);
        assertThat(MDC.get("traceId")).isNull();
    }
}
