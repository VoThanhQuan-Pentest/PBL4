package com.flarefitness.backend.service.siem;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SiemPreventionEventWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SiemPreventionEventWorker.class);
    private final SiemElasticGateway elastic;
    private final SiemPreventionEventIngestionService ingestion;
    private final boolean enabled;
    private final AtomicBoolean running = new AtomicBoolean();

    public SiemPreventionEventWorker(SiemElasticGateway elastic,
            SiemPreventionEventIngestionService ingestion,
            @Value("${siem.prevention.enabled:false}") boolean enabled) {
        this.elastic = elastic;
        this.ingestion = ingestion;
        this.enabled = enabled;
    }

    @Scheduled(initialDelayString = "${siem.prevention.initial-delay-ms:15000}",
            fixedDelayString = "${siem.prevention.event-interval-ms:5000}")
    public void synchronize() {
        if (!enabled || !running.compareAndSet(false, true)) return;
        try {
            LocalDateTime cursor = ingestion.checkpoint();
            List<SiemElasticGateway.PreventionEvent> events = elastic.recentPreventionEvents(cursor);
            ingestion.ingest(events);
        } catch (RuntimeException exception) {
            LOGGER.warn("Prevention event synchronization failed exceptionType={}",
                    exception.getClass().getSimpleName());
        } finally {
            running.set(false);
        }
    }

    @Scheduled(initialDelayString = "${siem.prevention.initial-delay-ms:15000}",
            fixedDelayString = "${siem.prevention.scan-interval-ms:10000}")
    public void detectEndpointScans() {
        if (!enabled) return;
        try {
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
            LocalDateTime completedMinute = now.truncatedTo(ChronoUnit.MINUTES);
            List<SiemElasticGateway.IpScanCandidate> candidates =
                    elastic.endpointScanCandidates(completedMinute.minusMinutes(1), completedMinute);
            candidates.forEach(candidate ->
                    ingestion.ingestScanCandidate(candidate, completedMinute.minusNanos(1)));
        } catch (RuntimeException exception) {
            LOGGER.warn("Endpoint scan aggregation failed exceptionType={}",
                    exception.getClass().getSimpleName());
        }
    }
}
