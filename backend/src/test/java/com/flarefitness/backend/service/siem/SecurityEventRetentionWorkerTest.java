package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

class SecurityEventRetentionWorkerTest {
    @TempDir Path directory;

    @Test
    void purgesOnlyGeneratedExpiredRotationsAndBoundsDatabaseDeletes() throws Exception {
        SiemSecurityEventRepository events = Mockito.mock(SiemSecurityEventRepository.class);
        SiemAccountBehaviorWindowRepository windows = Mockito.mock(SiemAccountBehaviorWindowRepository.class);
        when(events.purgeProcessedBefore(any())).thenReturn(1000, 0);
        when(windows.purgeScoredBefore(any())).thenReturn(1000, 0);
        Path output = directory.resolve("security-events.ndjson");
        Path rotation = directory.resolve("security-events.ndjson.20260926000100000.01234567-89ab-cdef-0123-456789abcdef");
        Path unrelated = directory.resolve("security-events.ndjson.manual-not-a-rotation");
        Files.writeString(output, "current");
        Files.writeString(rotation, "expired");
        Files.writeString(unrelated, "preserve");
        FileTime expired = FileTime.from(Instant.now().minus(40, ChronoUnit.DAYS));
        Files.setLastModifiedTime(rotation, expired);
        Files.setLastModifiedTime(unrelated, expired);

        new SecurityEventRetentionWorker(events, windows, true, 30, output.toString()).purgeExpired();

        assertThat(Files.exists(rotation)).isFalse();
        assertThat(Files.readString(unrelated)).isEqualTo("preserve");
        assertThat(Files.readString(output)).isEqualTo("current");
        verify(events, times(2)).purgeProcessedBefore(any());
        verify(windows, times(2)).purgeScoredBefore(any());
    }

    @Test
    void disabledTelemetryDoesNotDeleteAnything() throws Exception {
        SiemSecurityEventRepository events = Mockito.mock(SiemSecurityEventRepository.class);
        SiemAccountBehaviorWindowRepository windows = Mockito.mock(SiemAccountBehaviorWindowRepository.class);
        Path output = directory.resolve("security-events.ndjson");
        Files.writeString(output, "keep");
        new SecurityEventRetentionWorker(events, windows, false, 30, output.toString()).purgeExpired();
        assertThat(Files.readString(output)).isEqualTo("keep");
        verifyNoInteractions(events, windows);
    }
}
