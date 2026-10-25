package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.flarefitness.backend.controller.ProductController;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.siem.EndpointCategory;
import com.flarefitness.backend.service.siem.SecurityEventService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

class SecurityEventFilterTelemetryTest {
    @AfterEach void clearContext() { SecurityContextHolder.clearContext(); }

    @Test
    void classificationUsesPostDispatchCanonicalPatternNotRawUriOrHeaders() throws Exception {
        authenticate();
        SiemSecurityEventRepository repository = mock(SiemSecurityEventRepository.class);
        SecurityEventFilter filter = new SecurityEventFilter(new SecurityEventService(repository, true), new IpAddressResolver(""));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/products/attacker-variable");
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("X-Forwarded-For", "198.51.100.99");
        request.addHeader("X-Endpoint-Category", "PRIVILEGED");
        request.addHeader("X-Session-Pseudonym", "forged-secret");
        request.setAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE,
                UebaSessionTelemetry.fromVerifiedClaims("customer-1", "4e86ad52-994e-4e6e-a39d-6bc9df3f8537",
                        Instant.now().minusSeconds(60)).orElseThrow());
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> {
            // Attributes become available only once the MVC handler has actually matched.
            request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/products/query");
            request.setAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, productHandler());
        });
        ArgumentCaptor<SiemSecurityEvent> capture = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(capture.capture());
        SiemSecurityEvent event = capture.getValue();
        assertThat(event.getEndpointCategory()).isEqualTo("PRODUCT_LIST");
        assertThat(event.getTelemetryContractVersion()).isEqualTo(3);
        assertThat(event.getSessionPseudonym()).matches("[0-9a-f]{64}");
        assertThat(event.getSourceIp()).isEqualTo("127.0.0.1");
        assertThat(event.getActorUserId()).isEqualTo("customer-1");
        assertThat(event.getRouteGroup()).isEqualTo("products");
    }

    @Test
    void authorizationOrBare404WithoutDispatchIsUnresolvedNotAnUnmatchedScan() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/users");
        assertThat(SecurityEventFilter.endpointCategory(request, 403)).isEqualTo(EndpointCategory.UNRESOLVED);
        assertThat(SecurityEventFilter.endpointCategory(request, 404)).isEqualTo(EndpointCategory.UNRESOLVED);
        request.setAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, new ResourceHttpRequestHandler());
        assertThat(SecurityEventFilter.endpointCategory(request, 404)).isEqualTo(EndpointCategory.UNMATCHED);
        assertThat(SecurityEventFilter.endpointCategory(request, 403)).isEqualTo(EndpointCategory.UNRESOLVED);
        request.setAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, productHandler());
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/products/{id}");
        assertThat(SecurityEventFilter.endpointCategory(request, 404)).isEqualTo(EndpointCategory.PRODUCT_DETAIL);
    }

    @Test
    void anonymousHeadersCannotInventTelemetry() throws Exception {
        SiemSecurityEventRepository repository = mock(SiemSecurityEventRepository.class);
        var request = new MockHttpServletRequest("GET", "/api/products");
        request.addHeader("X-Actor-User-Id", "customer-1");
        request.addHeader("X-Session-Pseudonym", "a".repeat(64));
        new SecurityEventFilter(new SecurityEventService(repository, true), new IpAddressResolver(""))
                .doFilter(request, new MockHttpServletResponse(), (req, res) -> { });
        verifyNoInteractions(repository);
    }

    private static HandlerMethod productHandler() {
        try { return new HandlerMethod(mock(ProductController.class), ProductController.class.getMethod("getProducts")); }
        catch (NoSuchMethodException impossible) { throw new AssertionError(impossible); }
    }

    private static void authenticate() {
        User user = new User(); user.setId("customer-1"); user.setRole("CUSTOMER");
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
    }
}
