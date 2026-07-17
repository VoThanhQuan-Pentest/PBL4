package com.flarefitness.backend.controller.analytics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.analytics.BehaviorEventResponse;
import com.flarefitness.backend.dto.analytics.BehaviorEventType;
import com.flarefitness.backend.dto.analytics.TrackBehaviorEventRequest;
import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.IpRateLimitService;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
class AnalyticsControllerTest {

    @Mock
    private BehaviorAnalyticsService behaviorAnalyticsService;
    @Mock
    private IpAddressResolver ipAddressResolver;
    @Mock
    private IpRateLimitService ipRateLimitService;
    @Mock
    private HttpServletRequest servletRequest;

    @Test
    void trackingUsesServerGeneratedHttpOnlySessionInsteadOfRequestSessionId() {
        AnalyticsController controller = new AnalyticsController(
                behaviorAnalyticsService,
                ipAddressResolver,
                ipRateLimitService,
                120,
                60,
                true);
        TrackBehaviorEventRequest request = new TrackBehaviorEventRequest(
                "client-controlled-session",
                BehaviorEventType.PRODUCT_SEARCH,
                null,
                null,
                null,
                null,
                null,
                null,
                "world cup",
                null,
                null,
                null,
                null);
        when(ipAddressResolver.resolve(servletRequest)).thenReturn("203.0.113.10");
        when(servletRequest.getCookies()).thenReturn(null);
        when(behaviorAnalyticsService.trackEvent(eq(request), any(), any(String.class)))
                .thenAnswer(invocation -> new BehaviorEventResponse(
                        "RECORDED", invocation.getArgument(2), LocalDateTime.of(2026, 1, 1, 12, 0)));

        ResponseEntity<BehaviorEventResponse> response = controller.trackEvent(request, null, servletRequest);

        ArgumentCaptor<String> sessionCaptor = ArgumentCaptor.forClass(String.class);
        verify(behaviorAnalyticsService).trackEvent(eq(request), any(), sessionCaptor.capture());
        assertThat(sessionCaptor.getValue()).startsWith("analytics-").isNotEqualTo("client-controlled-session");
        assertThat(response.getHeaders().getFirst("Set-Cookie"))
                .contains("analytics_session=")
                .contains("HttpOnly")
                .contains("Secure")
                .contains("SameSite=Lax");
        verify(ipRateLimitService).assertWithinLimit("analytics", "203.0.113.10", 120, java.time.Duration.ofMinutes(1));
        verify(ipRateLimitService).assertWithinLimit("analytics-session", sessionCaptor.getValue(), 60,
                java.time.Duration.ofMinutes(1));
    }

    @Test
    void anonymousRecommendationsUseTheServerIssuedCookieSession() {
        AnalyticsController controller = new AnalyticsController(
                behaviorAnalyticsService,
                ipAddressResolver,
                ipRateLimitService,
                120,
                60,
                false);
        when(servletRequest.getCookies()).thenReturn(null);
        when(behaviorAnalyticsService.getRecommendations(
                isNull(), anyString(), eq("home"), isNull(), isNull(), eq(8)))
                .thenReturn(List.of());

        ResponseEntity<List<ProductResponse>> response = controller.getRecommendations(
                null, "home", null, null, 8, servletRequest);

        ArgumentCaptor<String> sessionCaptor = ArgumentCaptor.forClass(String.class);
        verify(behaviorAnalyticsService).getRecommendations(
                isNull(), sessionCaptor.capture(), eq("home"), isNull(), isNull(), eq(8));
        assertThat(sessionCaptor.getValue()).startsWith("analytics-");
        assertThat(response.getHeaders().getFirst("Set-Cookie")).contains("analytics_session=").contains("HttpOnly");
    }
}
