package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SiemSyncWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SiemSyncWorker.class);
    private final SiemElasticGateway elasticGateway;
    private final SiemAlertIngestionService ingestionService;
    private final ObjectMapper objectMapper;
    private final AtomicBoolean running = new AtomicBoolean();
    private volatile LocalDateTime lastReconciliation;

    public SiemSyncWorker(
            SiemElasticGateway elasticGateway,
            SiemAlertIngestionService ingestionService,
            ObjectMapper objectMapper
    ) {
        this.elasticGateway = elasticGateway;
        this.ingestionService = ingestionService;
        this.objectMapper = objectMapper;
    }

    @Scheduled(
            initialDelayString = "${siem.initial-delay-ms:15000}",
            fixedDelayString = "#{${siem.poll-interval-seconds:30} * 1000}"
    )
    public void synchronize() {
        if (!elasticGateway.isEnabled() || !running.compareAndSet(false, true)) return;
        String pitId = null;
        try {
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
            boolean reconcile = lastReconciliation == null || lastReconciliation.isBefore(now.minusHours(1));
            LocalDateTime checkpoint = ingestionService.checkpointTime();
            LocalDateTime since = reconcile
                    ? now.minusHours(24)
                    : (checkpoint == null ? now.minusHours(24) : checkpoint.minusMinutes(10));
            pitId = elasticGateway.openAlertPointInTime();
            List<Object> searchAfter = List.of();
            LocalDateTime latest = checkpoint;
            while (true) {
                var page = elasticGateway.fetchAlertPage(pitId, since, searchAfter, 500);
                if (page.alerts().isEmpty()) break;
                var result = ingestionService.ingest(page.alerts());
                if (result.latestEventTime() != null
                        && (latest == null || result.latestEventTime().isAfter(latest))) {
                    latest = result.latestEventTime();
                }
                searchAfter = page.nextSort();
                if (page.alerts().size() < 500) break;
            }
            ingestionService.checkpointSuccess(latest, objectMapper.writeValueAsString(searchAfter));
            if (reconcile) lastReconciliation = now;
        } catch (Exception exception) {
            LOGGER.warn("SIEM alert synchronization failed: {}", exception.getMessage());
            ingestionService.checkpointFailure(exception.getMessage());
        } finally {
            elasticGateway.closePointInTime(pitId);
            running.set(false);
        }
    }
}
