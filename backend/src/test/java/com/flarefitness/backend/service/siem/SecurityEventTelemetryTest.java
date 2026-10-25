package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

class SecurityEventTelemetryTest {
    @TempDir Path temp;

    @Test
    void newHttpCaptureExportsOnlyBoundedServerFieldsWhileLegacyAndAuthStayAbsent() throws Exception {
        SiemSecurityEventRepository repository = mock(SiemSecurityEventRepository.class);
        SecurityEventService service = new SecurityEventService(repository, true);
        var session = UebaSessionTelemetry.fromVerifiedClaims("customer-1", "4e86ad52-994e-4e6e-a39d-6bc9df3f8537",
                Instant.now().minusSeconds(60)).orElseThrow();
        service.recordCustomerRequest("customer-1", "127.0.0.1", "GET", "/api/products/private-product-id",
                404, "Firefox/128 agent-secret", EndpointCategory.PRODUCT_DETAIL, session);
        ArgumentCaptor<SiemSecurityEvent> capture = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        verify(repository).save(capture.capture());
        var event = capture.getValue();
        when(repository.findByExportedAtIsNullOrderByCreatedAtAsc(any())).thenReturn(List.of(event));
        Path output = temp.resolve("events.ndjson");
        new SecurityEventExportWorker(repository, new ObjectMapper(), true, output.toString(), 100_000).exportPending();
        String json = Files.readString(output);
        var document = new ObjectMapper().readTree(json);
        assertThat(document.at("/telemetry/contract/version").asInt()).isEqualTo(3);
        assertThat(document.at("/http/endpoint/category").asText()).isEqualTo("PRODUCT_DETAIL");
        assertThat(document.at("/session/pseudonym").asText()).isEqualTo(session.sessionPseudonym());
        assertThat(document.at("/session/issued_at").asText()).endsWith("Z");
        assertThat(json).doesNotContain("private-product-id", "agent-secret", "jti", "token", "{id}");

        SiemSecurityEventRepository legacyRepository = mock(SiemSecurityEventRepository.class);
        SecurityEventService legacy = new SecurityEventService(legacyRepository, true);
        legacy.recordCustomerRequest("customer-1", "127.0.0.1", "GET", "/api/products", 200, null);
        legacy.recordAuth("LOGIN", "SUCCESS", "customer-1", "customer-1", "127.0.0.1");
        ArgumentCaptor<SiemSecurityEvent> oldCapture = ArgumentCaptor.forClass(SiemSecurityEvent.class);
        org.mockito.Mockito.verify(legacyRepository, org.mockito.Mockito.times(2)).save(oldCapture.capture());
        assertThat(oldCapture.getAllValues()).allSatisfy(old -> {
            assertThat(old.getTelemetryContractVersion()).isNull();
            assertThat(old.getEndpointCategory()).isNull();
            assertThat(old.getSessionPseudonym()).isNull();
            assertThat(old.getSessionIssuedAt()).isNull();
        });
    }

    @Test
    void invalidStoredCategoryOrRawSessionIdentifierCannotLeakThroughExport() throws Exception {
        var event = new SiemSecurityEvent(); event.setId("invalid");
        event.setEventTimestamp(LocalDateTime.of(2026, 1, 1, 0, 0)); event.setCreatedAt(event.getEventTimestamp());
        event.setActorUserId("customer-1"); event.setEventType("HTTP_REQUEST"); event.setAction("API_REQUEST");
        event.setOutcome("SUCCESS"); event.setTelemetryContractVersion(3);
        event.setEndpointCategory("/api/private-path"); event.setSessionPseudonym("raw-jti-secret");
        event.setSessionIssuedAt(event.getEventTimestamp());
        SiemSecurityEventRepository repository = mock(SiemSecurityEventRepository.class);
        when(repository.findByExportedAtIsNullOrderByCreatedAtAsc(any())).thenReturn(List.of(event));
        Path output = temp.resolve("invalid.ndjson");
        new SecurityEventExportWorker(repository, new ObjectMapper(), true, output.toString(), 100_000).exportPending();
        assertThat(Files.readString(output)).doesNotContain("private-path", "raw-jti-secret", "pseudonym");
    }
}
