package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.repository.siem.SiemAlertRefRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemIngestionCheckpointRepository;
import com.flarefitness.backend.repository.siem.SiemTestWindowRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SiemAlertIngestionServiceTest {
    @Mock private SiemIncidentRepository incidents;
    @Mock private SiemAlertRefRepository alerts;
    @Mock private SiemIncidentHistoryRepository history;
    @Mock private SiemTestWindowRepository windows;
    @Mock private SiemIngestionCheckpointRepository checkpoints;
    private SiemAlertIngestionService service;

    @BeforeEach
    void setUp() {
        service = new SiemAlertIngestionService(
                incidents, alerts, history, windows, checkpoints, new SiemClassificationEngine());
    }

    @Test
    void createsAStableFiveMinuteIncidentAndClassifiesIt() {
        var alert = new SiemElasticGateway.ElasticAlert(
                "elastic-alert-1", ".alerts-security.alerts-flare-lab-000001",
                "2026-09-20T06:17:42Z", "rule-login", "flare-web",
                List.of("203.0.113.10"), "high", "Repeated login failures");
        when(alerts.existsByElasticAlertId(alert.id())).thenReturn(false);
        when(incidents.findByGroupingKey(any())).thenReturn(Optional.empty());
        when(incidents.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(alerts.countByIncidentId(any())).thenReturn(1L);
        when(alerts.findBySourceIpAndServiceIdAndEventTimestampBetween(any(), any(), any(), any()))
                .thenReturn(List.of());
        when(windows.findByActiveTrueAndStartsAtLessThanEqualAndEndsAtGreaterThanEqual(any(), any()))
                .thenReturn(List.of());

        var result = service.ingest(List.of(alert));

        ArgumentCaptor<SiemIncident> captor = ArgumentCaptor.forClass(SiemIncident.class);
        verify(incidents).save(captor.capture());
        SiemIncident incident = captor.getValue();
        assertThat(result.createdIncidents()).isEqualTo(1);
        assertThat(incident.getGroupingKey()).startsWith("group:").hasSize(70);
        assertThat(incident.getBucketStart().getMinute()).isEqualTo(15);
        assertThat(incident.getScore()).isEqualTo(65);
        assertThat(incident.getAlertCount()).isEqualTo(1);
        assertThat(incident.getNature()).isEqualTo(IncidentNature.ELASTIC_DETECTION);
    }

    @Test
    void ownedRepeatedServerErrorRuleCreatesAnOperationalNature() {
        var alert = new SiemElasticGateway.ElasticAlert(
                "elastic-5xx-alert", ".alerts-security.alerts-flare-lab-000001",
                "2026-09-20T06:17:42Z", "flare-lab-server-errors", "flare-web",
                List.of(), "high", "Flare Lab: repeated server errors");
        when(alerts.existsByElasticAlertId(alert.id())).thenReturn(false);
        when(incidents.findByGroupingKey(any())).thenReturn(Optional.empty());
        when(incidents.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(alerts.countByIncidentId(any())).thenReturn(1L);
        when(windows.findByActiveTrueAndStartsAtLessThanEqualAndEndsAtGreaterThanEqual(any(), any()))
                .thenReturn(List.of());

        service.ingest(List.of(alert));

        ArgumentCaptor<SiemIncident> captor = ArgumentCaptor.forClass(SiemIncident.class);
        verify(incidents).save(captor.capture());
        assertThat(captor.getValue().getNature()).isEqualTo(IncidentNature.OPERATIONAL_ANOMALY);
    }

    @Test
    void duplicateElasticAlertIsIgnored() {
        var alert = new SiemElasticGateway.ElasticAlert(
                "elastic-alert-1", "index", "2026-09-20T06:17:42Z",
                "rule", "flare-web", List.of("203.0.113.10"), "low", "Alert");
        when(alerts.existsByElasticAlertId(alert.id())).thenReturn(true);

        var result = service.ingest(List.of(alert));

        assertThat(result.duplicateAlerts()).isEqualTo(1);
        assertThat(result.createdIncidents()).isZero();
    }
}
