package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class PostLoginSecurityTelemetryTest {
    private final SiemSecurityEventRepository repository = mock(SiemSecurityEventRepository.class);
    private final SecurityEventService events = new SecurityEventService(repository, true, true);
    private final UebaSessionTelemetry session = UebaSessionTelemetry.fromVerifiedClaims("customer-1",
            "4e86ad52-994e-4e6e-a39d-6bc9df3f8537", Instant.now().minusSeconds(60)).orElseThrow();
    @TempDir Path output;

    @AfterEach void clear() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test void verifiedSessionDirectlyAssociatesLoginAttemptAndCompletedAction() {
        verifiedRequest();
        events.recordSuccessfulLogin("customer-1", "198.51.100.1", "Firefox/128", session);
        events.recordSensitiveActionAttempt("PASSWORD_CHANGE", "customer-1");
        events.recordDomainAction("PASSWORD_CHANGE", "customer-1", "customer-1");
        var captured = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository, times(3)).save(captured.capture());
        assertThat(captured.getAllValues()).extracting(SiemSecurityEvent::getEventType)
                .containsExactly("AUTH", "SENSITIVE_ACTION_ATTEMPT", "DOMAIN_ACTION");
        assertThat(captured.getAllValues()).allSatisfy(event -> {
            assertThat(event.getActorUserId()).isEqualTo("customer-1");
            assertThat(event.getTelemetryContractVersion()).isEqualTo(4);
            assertThat(event.getSessionPseudonym()).isEqualTo(session.sessionPseudonym());
            assertThat(event.getSessionIssuedAt()).isEqualTo(session.sessionIssuedAt());
        });
        assertThat(captured.getAllValues().get(1).getOutcome()).isEqualTo("ATTEMPT");
    }

    @Test void clientHeadersAloneCannotAssociateAnAttemptOrAction() {
        var request = new MockHttpServletRequest();
        request.addHeader("X-Session-Pseudonym", "a".repeat(64));
        request.addHeader("X-Request-ID", "reused-client-trace");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        events.recordSensitiveActionAttempt("EMAIL_CHANGE", "customer-1");
        verifyNoInteractions(repository);
        events.recordDomainAction("EMAIL_CHANGE", "customer-1", "customer-1");
        var captured = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(captured.capture());
        assertThat(captured.getValue().getSessionPseudonym()).isNull();
        assertThat(captured.getValue().getTelemetryContractVersion()).isNull();
    }

    @Test void wrongAccountResetAndMissingOrFutureMetadataNeverCreatePostloginAttempts() {
        verifiedRequest();
        events.recordSensitiveActionAttempt("EMAIL_CHANGE", "other-account");
        events.recordSensitiveActionAttempt("PASSWORD_RESET", "customer-1");
        events.recordDomainAction("PASSWORD_RESET", null, "customer-1");
        var captured = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(captured.capture());
        assertThat(captured.getValue().getSessionPseudonym()).isNull();
        reset(repository);
        var request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        request.removeAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE);
        events.recordSensitiveActionAttempt("PASSWORD_CHANGE", "customer-1");
        request.setAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE,
                new UebaSessionTelemetry("b".repeat(64), session.sessionIssuedAt().plusDays(1)));
        events.recordSensitiveActionAttempt("PASSWORD_CHANGE", "customer-1");
        verifyNoInteractions(repository);
    }

    @Test void experimentalCaptureIsDisabledByDefaultAndRetainsLegacySemantics() {
        verifiedRequest();
        var legacy = new SecurityEventService(repository, true);
        assertThat(legacy.isPostLoginEnabled()).isFalse();
        legacy.recordSensitiveActionAttempt("PASSWORD_CHANGE", "customer-1");
        verifyNoInteractions(repository);
        legacy.recordDomainAction("PASSWORD_CHANGE", "customer-1", "customer-1");
        var captured = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(captured.capture());
        assertThat(captured.getValue().getSessionPseudonym()).isNull();
        assertThat(captured.getValue().getTelemetryContractVersion()).isNull();
    }

    @Test void additiveContractExportsSanitizedAssociationForAllThreeEventTypes() throws Exception {
        verifiedRequest();
        events.recordSuccessfulLogin("customer-1", "198.51.100.1", "Firefox/128", session);
        events.recordSensitiveActionAttempt("EMAIL_CHANGE", "customer-1");
        events.recordDomainAction("EMAIL_CHANGE", "customer-1", "customer-1");
        var captured = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository, times(3)).save(captured.capture());
        when(repository.findByExportedAtIsNullOrderByCreatedAtAsc(any())).thenReturn(captured.getAllValues());
        Path path = output.resolve("events.ndjson");
        var json = new ObjectMapper();
        new SecurityEventExportWorker(repository, json, true, path.toString(), 100_000).exportPending();
        var lines = Files.readAllLines(path);
        assertThat(lines).hasSize(3);
        for (String line : lines) {
            var document = json.readTree(line);
            assertThat(document.at("/telemetry/contract/version").asInt()).isEqualTo(4);
            assertThat(document.at("/session/pseudonym").asText()).isEqualTo(session.sessionPseudonym());
            assertThat(line).doesNotContain("4e86ad52-994e-4e6e-a39d-6bc9df3f8537", "token", "password_value");
            assertThat(document.at("/http/endpoint").isMissingNode()).isTrue();
        }
    }

    private void verifiedRequest() {
        var user = new User(); user.setId("customer-1"); user.setUsername("owned-customer"); user.setRole("Khach hang");
        var principal = new CurrentUserPrincipal(user);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
        var request = new MockHttpServletRequest();
        request.setAttribute(JwtAuthenticationFilter.SESSION_TELEMETRY_REQUEST_ATTRIBUTE, session);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
