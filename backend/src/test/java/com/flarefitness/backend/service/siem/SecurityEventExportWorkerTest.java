package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

class SecurityEventExportWorkerTest {
    @TempDir Path tempDir;

    @Test
    void exportsServerAllowlistAsOneNdjsonDocumentWithStableId() throws Exception {
        SiemSecurityEventRepository repository = Mockito.mock(SiemSecurityEventRepository.class);
        SiemSecurityEvent event = new SiemSecurityEvent();
        event.setId("event-1");
        event.setEventTimestamp(LocalDateTime.of(2026, 9, 26, 10, 0));
        event.setCreatedAt(LocalDateTime.of(2026, 9, 26, 10, 0));
        event.setActorUserId("customer-1");
        event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST");
        event.setOutcome("FAILURE");
        event.setRouteGroup("admin");
        event.setHttpMethod("GET");
        event.setHttpStatus(403);
        when(repository.findByExportedAtIsNullOrderByCreatedAtAsc(any())).thenReturn(List.of(event));
        Path path = tempDir.resolve("security-events.ndjson");

        new SecurityEventExportWorker(repository, new ObjectMapper(), true, path.toString(), 1_000_000)
                .exportPending();

        String line = Files.readString(path);
        var document = new ObjectMapper().readTree(line);
        assertThat(line.split("\n")).hasSize(1);
        assertThat(document.path("event").path("id").asText()).isEqualTo("event-1");
        assertThat(document.path("@timestamp").asText()).isEqualTo("2026-09-26T10:00:00Z");
        assertThat(document.path("event").path("dataset").asText()).isEqualTo("flare.security");
        assertThat(document.path("user").path("id").asText()).isEqualTo("customer-1");
        assertThat(document.path("flare").path("route_group").asText()).isEqualTo("admin");
        assertThat(document.has("body")).isFalse();
        assertThat(document.has("cookie")).isFalse();
        assertThat(event.getExportedAt()).isNotNull();
        verify(repository).save(event);
    }

    @Test
    void rotatesWithoutLosingEitherEventOrChangingTheDocumentId() throws Exception {
        SiemSecurityEventRepository repository = Mockito.mock(SiemSecurityEventRepository.class);
        SiemSecurityEvent first = event("first");
        SiemSecurityEvent second = event("second");
        when(repository.findByExportedAtIsNullOrderByCreatedAtAsc(any())).thenReturn(List.of(first, second));
        Path path = tempDir.resolve("security-events.ndjson");

        new SecurityEventExportWorker(repository, new ObjectMapper(), true, path.toString(), 1)
                .exportPending();

        try (var files = Files.list(tempDir)) {
            List<Path> exported = files.filter(file -> file.getFileName().toString()
                    .startsWith("security-events.ndjson")).toList();
            assertThat(exported).hasSize(2);
            String all = Files.readString(exported.get(0)) + Files.readString(exported.get(1));
            assertThat(all).contains("\"id\":\"first\"", "\"id\":\"second\"");
        }
        assertThat(first.getExportedAt()).isNotNull();
        assertThat(second.getExportedAt()).isNotNull();
    }

    private SiemSecurityEvent event(String id) {
        SiemSecurityEvent event = new SiemSecurityEvent();
        event.setId(id);
        event.setEventTimestamp(LocalDateTime.of(2026, 9, 26, 10, 0));
        event.setCreatedAt(LocalDateTime.of(2026, 9, 26, 10, 0));
        event.setEventType("HTTP_REQUEST");
        event.setAction("API_REQUEST");
        event.setOutcome("SUCCESS");
        return event;
    }
}
