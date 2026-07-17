package com.flarefitness.backend.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class IpAddressResolverTest {

    @Test
    void ignoresForwardedForFromAnUntrustedDirectCaller() {
        IpAddressResolver resolver = new IpAddressResolver("172.30.0.0/24");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.20");
        request.addHeader("X-Forwarded-For", "198.51.100.99");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.20");
    }

    @Test
    void acceptsTheFirstNonProxyAddressOnlyFromConfiguredProxyNetwork() {
        IpAddressResolver resolver = new IpAddressResolver("172.30.0.0/24");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("172.30.0.8");
        request.addHeader("X-Forwarded-For", "198.51.100.99, 172.30.0.7");

        assertThat(resolver.resolve(request)).isEqualTo("198.51.100.99");
    }
}
