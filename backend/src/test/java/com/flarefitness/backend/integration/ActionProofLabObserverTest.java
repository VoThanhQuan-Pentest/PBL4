package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.service.siem.UebaSessionTelemetry;
import java.time.LocalDateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class ActionProofLabObserverTest {
    @AfterEach void clear() { SecurityContextHolder.clearContext(); RequestContextHolder.resetRequestAttributes(); }
    @Test void proofBackendFailureDoesNotRejectOrRewriteTheExistingBusinessRequest() {
        var request = new MockHttpServletRequest(); request.addHeader(ActionProofLabConfiguration.HEADER, "a".repeat(43));
        request.setAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE,
                new UebaSessionTelemetry("b".repeat(64), LocalDateTime.of(2026, 10, 19, 0, 0)));
        var user = new User(); user.setId("owned"); user.setAuthVersion(0L);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(new CurrentUserPrincipal(user), null));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        var service = mock(ActionProofLabConfiguration.Service.class);
        when(service.consume(any(), eq("PASSWORD_CHANGE"), eq("new-private-value"), any()))
                .thenThrow(new IllegalStateException("fixture backend outage"));
        var body = new ChangePasswordRequest("current-private", "new-private-value", "new-private-value");
        Object returned = new ActionProofLabConfiguration.Observer(service).afterBodyRead(body, null, null, null, null);
        assertThat(returned).isSameAs(body);
        var evidence = (ActionProofLabConfiguration.Evidence) request.getAttribute(ActionProofLabConfiguration.EVIDENCE_ATTRIBUTE);
        assertThat(evidence.state()).isEqualTo("UNAVAILABLE"); assertThat(evidence.values()).containsExactly(0.0, 0.0, 0.0, 0.0);
    }
}
