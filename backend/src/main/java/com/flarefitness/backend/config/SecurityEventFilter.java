package com.flarefitness.backend.config;

import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.siem.EndpointCategory;
import com.flarefitness.backend.service.siem.SecurityEventService;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

/** Runs inside Spring Security after JWT lookup, so actor IDs come from the server principal. */
public class SecurityEventFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventFilter.class);
    private final SecurityEventService events;
    private final IpAddressResolver ipResolver;

    public SecurityEventFilter(SecurityEventService events, IpAddressResolver ipResolver) {
        this.events = events;
        this.ipResolver = ipResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } finally {
            if (events.isEnabled()) {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                if (auth != null && auth.getPrincipal() instanceof CurrentUserPrincipal principal
                        && "ROLE_CUSTOMER".equals(CurrentUserPrincipal.toAuthority(principal.getUser().getRole()))) {
                    try {
                        events.recordCustomerRequest(principal.getUser().getId(), ipResolver.resolve(request),
                                request.getMethod(), request.getRequestURI(), response.getStatus(),
                                request.getHeader("User-Agent"), endpointCategory(request, response.getStatus()),
                                request.getAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE)
                                        instanceof UebaSessionTelemetry session ? session : null);
                    } catch (RuntimeException exception) {
                        LOGGER.warn("Security event persistence failed exceptionType={}",
                                exception.getClass().getSimpleName());
                    }
                }
            }
        }
    }

    static EndpointCategory endpointCategory(HttpServletRequest request, int status) {
        Object handler = request.getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE);
        Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (handler instanceof HandlerMethod method
                && method.getBeanType().getPackageName().startsWith("com.flarefitness.backend.controller")
                && pattern instanceof String template) {
            return EndpointCategory.fromHandlerPattern(request.getMethod(), template);
        }
        // A resource-handler 404 proves MVC ran and no application controller matched.
        // Absence of handler metadata alone may mean pre-MVC authorization denial, not a scan.
        if (handler instanceof ResourceHttpRequestHandler && status == 404) return EndpointCategory.UNMATCHED;
        return EndpointCategory.UNRESOLVED;
    }
}
