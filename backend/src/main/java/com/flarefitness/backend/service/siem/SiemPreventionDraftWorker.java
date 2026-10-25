package com.flarefitness.backend.service.siem;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SiemPreventionDraftWorker {
    private final SiemPreventionService service;
    private final boolean enabled;

    public SiemPreventionDraftWorker(SiemPreventionService service,
            @Value("${siem.prevention.enabled:false}") boolean enabled) {
        this.service = service;
        this.enabled = enabled;
    }

    @Scheduled(initialDelayString = "${siem.prevention.initial-delay-ms:15000}",
            fixedDelayString = "${siem.prevention.draft-interval-ms:60000}")
    public void propose() {
        if (enabled) service.proposeFromConfirmedIncidents();
    }
}
