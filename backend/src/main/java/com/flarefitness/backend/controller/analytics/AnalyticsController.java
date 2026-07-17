package com.flarefitness.backend.controller.analytics;

import com.flarefitness.backend.dto.analytics.BehaviorEventResponse;
import com.flarefitness.backend.dto.analytics.TrackBehaviorEventRequest;
import com.flarefitness.backend.dto.analytics.UserBehaviorInsightResponse;
import com.flarefitness.backend.dto.product.ProductResponse;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import jakarta.validation.Valid;
import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.IpRateLimitService;
import java.time.Duration;

@RestController
@RequestMapping("/api/analytics")
public class AnalyticsController {

    private static final String ANALYTICS_SESSION_COOKIE = "analytics_session";
    private static final String ANALYTICS_SESSION_PREFIX = "analytics-";

    private final BehaviorAnalyticsService behaviorAnalyticsService;
    private final IpAddressResolver ipAddressResolver;
    private final IpRateLimitService ipRateLimitService;
    private final int maxEventsPerMinute;
    private final int maxEventsPerSessionPerMinute;
    private final boolean analyticsCookieSecure;

    public AnalyticsController(
            BehaviorAnalyticsService behaviorAnalyticsService,
            IpAddressResolver ipAddressResolver,
            IpRateLimitService ipRateLimitService,
            @org.springframework.beans.factory.annotation.Value("${app.security.analytics.max-events-per-minute}") int maxEventsPerMinute,
            @org.springframework.beans.factory.annotation.Value("${app.security.analytics.max-events-per-session-minute:60}") int maxEventsPerSessionPerMinute,
            @org.springframework.beans.factory.annotation.Value("${app.security.auth-cookie-secure:false}") boolean analyticsCookieSecure
    ) {
        this.behaviorAnalyticsService = behaviorAnalyticsService;
        this.ipAddressResolver = ipAddressResolver;
        this.ipRateLimitService = ipRateLimitService;
        this.maxEventsPerMinute = maxEventsPerMinute;
        this.maxEventsPerSessionPerMinute = maxEventsPerSessionPerMinute;
        this.analyticsCookieSecure = analyticsCookieSecure;
    }

    @PostMapping("/events")
    public ResponseEntity<BehaviorEventResponse> trackEvent(
            @Valid @RequestBody TrackBehaviorEventRequest request,
            Authentication authentication,
            HttpServletRequest httpServletRequest
    ) {
        String ipAddress = ipAddressResolver.resolve(httpServletRequest);
        ipRateLimitService.assertWithinLimit(
                "analytics",
                ipAddress,
                maxEventsPerMinute,
                Duration.ofMinutes(1));
        SessionResolution sessionResolution = resolveAnalyticsSession(httpServletRequest);
        // The cookie is HttpOnly and server-generated, so a browser cannot simply rotate the
        // session identifier supplied in the JSON body to evade this second limit.
        ipRateLimitService.assertWithinLimit(
                "analytics-session",
                sessionResolution.sessionId(),
                maxEventsPerSessionPerMinute,
                Duration.ofMinutes(1));
        BehaviorEventResponse response = behaviorAnalyticsService.trackEvent(
                request,
                authentication,
                sessionResolution.sessionId());
        ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();
        if (sessionResolution.newSession()) {
            responseBuilder.header("Set-Cookie", analyticsSessionCookie(sessionResolution.sessionId()));
        }
        return responseBuilder.body(response);
    }

    @GetMapping("/me/insights")
    public ResponseEntity<UserBehaviorInsightResponse> getCurrentInsights(Authentication authentication) {
        return ResponseEntity.ok(behaviorAnalyticsService.getCurrentUserInsights(authentication));
    }

    @GetMapping("/recommendations")
    public ResponseEntity<List<ProductResponse>> getRecommendations(
            Authentication authentication,
            @RequestParam(defaultValue = "home") String context,
            @RequestParam(required = false) String productId,
            @RequestParam(required = false) List<String> productIds,
            @RequestParam(defaultValue = "8") Integer limit,
            HttpServletRequest httpServletRequest
    ) {
        SessionResolution sessionResolution = resolveAnalyticsSession(httpServletRequest);
        List<ProductResponse> recommendations = behaviorAnalyticsService.getRecommendations(
                authentication,
                sessionResolution.sessionId(),
                context,
                productId,
                productIds,
                limit);
        ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();
        if (sessionResolution.newSession()) {
            responseBuilder.header("Set-Cookie", analyticsSessionCookie(sessionResolution.sessionId()));
        }
        return responseBuilder.body(recommendations);
    }

    private SessionResolution resolveAnalyticsSession(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (ANALYTICS_SESSION_COOKIE.equals(cookie.getName()) && isValidSessionId(cookie.getValue())) {
                    return new SessionResolution(cookie.getValue(), false);
                }
            }
        }
        return new SessionResolution(ANALYTICS_SESSION_PREFIX + UUID.randomUUID(), true);
    }

    private boolean isValidSessionId(String value) {
        return value != null && value.matches("analytics-[0-9a-fA-F-]{36}");
    }

    private String analyticsSessionCookie(String sessionId) {
        return ResponseCookie.from(ANALYTICS_SESSION_COOKIE, sessionId)
                .httpOnly(true)
                .secure(analyticsCookieSecure)
                .sameSite("Lax")
                .path("/api/analytics")
                .maxAge(Duration.ofDays(30))
                .build()
                .toString();
    }

    private record SessionResolution(String sessionId, boolean newSession) {
    }
}
