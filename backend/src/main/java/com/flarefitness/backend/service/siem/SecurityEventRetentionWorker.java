package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Bounded local retention; unexported or unaggregated events are never deleted. */
@Component
public class SecurityEventRetentionWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityEventRetentionWorker.class);
    private final SiemSecurityEventRepository events;
    private final SiemAccountBehaviorWindowRepository windows;
    private final boolean enabled;
    private final int retentionDays;
    private final Path output;

    public SecurityEventRetentionWorker(SiemSecurityEventRepository events,
                                        SiemAccountBehaviorWindowRepository windows,
                                        @Value("${siem.security-events.enabled:false}") boolean enabled,
                                        @Value("${siem.security-events.retention-days:30}") int retentionDays,
                                        @Value("${siem.security-events.output-file:/var/log/flare/security-events.ndjson}")
                                        String outputFile) {
        this.events = events;
        this.windows = windows;
        this.enabled = enabled;
        this.retentionDays = Math.max(30, retentionDays);
        this.output = Path.of(outputFile);
    }

    @Scheduled(cron = "${siem.security-events.retention-cron:0 15 3 * * *}", zone = "UTC")
    @Transactional
    public void purgeExpired() {
        if (!enabled) return;
        LocalDateTime cutoff = LocalDateTime.now(ZoneOffset.UTC).minusDays(retentionDays);
        for (int batch = 0; batch < 10 && events.purgeProcessedBefore(cutoff) == 1000; batch++) {
            // A bounded number of rows per maintenance run prevents long locks.
        }
        for (int batch = 0; batch < 10 && windows.purgeScoredBefore(cutoff) == 1000; batch++) {
            // Pending windows remain intact even when older than the retention period.
        }
        purgeRotatedFiles(Instant.now().minus(retentionDays + 7L, ChronoUnit.DAYS));
    }

    private void purgeRotatedFiles(Instant cutoff) {
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent)) return;
        String basename = output.getFileName().toString();
        Pattern generatedName = Pattern.compile(Pattern.quote(basename)
                + "\\.\\d{17}\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        try (DirectoryStream<Path> files = Files.newDirectoryStream(parent, basename + ".*")) {
            for (Path file : files) {
                if (!generatedName.matcher(file.getFileName().toString()).matches()
                        || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) continue;
                if (Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS).toInstant().isBefore(cutoff)) {
                    Files.delete(file);
                }
            }
        } catch (Exception exception) {
            LOGGER.warn("Security event rotated-file retention failed exceptionType={}",
                    exception.getClass().getSimpleName());
        }
    }
}
