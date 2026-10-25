package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.service.siem.SiemIncidentService;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SiemDashboardIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired private SiemIncidentRepository incidentRepository;
    @Autowired private SiemIncidentService incidentService;
    private final List<String> fixtureIds = new ArrayList<>();

    @AfterEach
    void cleanFixtures() {
        incidentRepository.deleteAllById(fixtureIds);
        fixtureIds.clear();
    }

    @Test
    void summaryUsesTheFullRangeAndPriorityOrderingIsServerAuthoritative() {
        String marker = "dashboard-fixture-" + UUID.randomUUID();
        LocalDateTime base = LocalDateTime.of(2035, 1, 2, 12, 0);
        save(marker, "urgent-open", 90, IncidentSeverity.URGENT,
                IncidentClassification.INVESTIGATE, IncidentStatus.IN_PROGRESS, base.plusMinutes(1));
        save(marker, "high-new", 70, IncidentSeverity.HIGH,
                IncidentClassification.INVESTIGATE, IncidentStatus.NEW, base.plusMinutes(2));
        save(marker, "high-progress", 70, IncidentSeverity.HIGH,
                IncidentClassification.INVESTIGATE, IncidentStatus.IN_PROGRESS, base.plusMinutes(3));
        save(marker, "noise-new", 100, IncidentSeverity.URGENT,
                IncidentClassification.POTENTIAL_NOISE, IncidentStatus.NEW, base.plusMinutes(4));
        save(marker, "closed", 95, IncidentSeverity.URGENT,
                IncidentClassification.INVESTIGATE, IncidentStatus.CLOSED, base.plusMinutes(5));

        SiemDtos.DashboardSummary summary = incidentService.dashboardSummary(
                base.minusHours(1), base.plusHours(1));
        assertThat(summary.totalIncidents()).isEqualTo(5);
        assertThat(summary.investigateIncidents()).isEqualTo(4);
        assertThat(summary.potentialNoiseIncidents()).isEqualTo(1);
        assertThat(summary.closedIncidents()).isEqualTo(1);
        assertThat(summary.bySeverity().get(IncidentSeverity.URGENT)).isEqualTo(3);
        assertThat(summary.byQueueTier().get(IncidentQueueTier.L1)).isEqualTo(4);
        assertThat(summary.byQueueTier().get(IncidentQueueTier.L2)).isEqualTo(1);
        assertThat(summary.byOrigin().get(IncidentOrigin.UEBA)).isEqualTo(1);

        var page = incidentService.findIncidents(
                0, 50, null, null, null,
                SiemDtos.IncidentScope.OPEN, SiemDtos.IncidentSort.PRIORITY,
                marker, null, null);

        assertThat(page.content()).extracting(SiemDtos.Incident::title)
                .containsExactly(
                        marker + " urgent-open",
                        marker + " high-new",
                        marker + " high-progress",
                        marker + " noise-new");
    }

    private void save(
            String marker,
            String suffix,
            int score,
            IncidentSeverity severity,
            IncidentClassification classification,
            IncidentStatus status,
            LocalDateTime lastSeen
    ) {
        String id = "siem-dashboard-" + UUID.randomUUID();
        fixtureIds.add(id);
        SiemIncident incident = new SiemIncident();
        incident.setId(id);
        incident.setGroupingKey("group-" + UUID.randomUUID());
        incident.setServiceId("dashboard-test");
        incident.setRuleId("rule-" + suffix);
        incident.setSourceIp("203.0.113.10");
        incident.setQueueTier("high-progress".equals(suffix) ? IncidentQueueTier.L2 : IncidentQueueTier.L1);
        incident.setOrigin("high-progress".equals(suffix) ? IncidentOrigin.UEBA : IncidentOrigin.ELASTIC);
        incident.setBucketStart(lastSeen.withSecond(0).withNano(0));
        incident.setTitle(marker + " " + suffix);
        incident.setSourceSeverity(severity.name().toLowerCase());
        incident.setScore(score);
        incident.setSeverity(severity);
        incident.setClassification(classification);
        incident.setClassificationReason("integration fixture");
        incident.setMissingData(false);
        incident.setStatus(status);
        incident.setConclusion(status == IncidentStatus.CLOSED
                ? IncidentConclusion.TRUE_POSITIVE : IncidentConclusion.UNREVIEWED);
        incident.setManualInvestigateOverride(false);
        incident.setAlertCount(1);
        incident.setDistinctRuleCount(1);
        incident.setFirstSeen(lastSeen.minusMinutes(1));
        incident.setLastSeen(lastSeen);
        incident.setCreatedAt(lastSeen.minusMinutes(1));
        incident.setUpdatedAt(lastSeen);
        incidentRepository.save(incident);
    }
}
