package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AccountBehaviorScoringWorkerCandidateTest {
    private static final String VERSION = "candidate-v4-abcdef";
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 12, 12, 0);

    @Test
    void explicitCandidateScorePersistsExactVersionAndSchemaWithoutChangingPrimary() {
        var windows = mock(SiemAccountBehaviorWindowRepository.class);
        var incidents = mock(SiemIncidentRepository.class);
        var history = mock(SiemIncidentHistoryRepository.class);
        var gateway = mock(SiemUebaGateway.class);
        var window = schemaFourWindow();
        when(windows.findAllById(List.of(window.getId()))).thenReturn(List.of(window));
        var score = new SiemUebaGateway.Score(0.1, 1.0, "NORMAL_RANGE", null, "COLD");
        when(gateway.scoreCandidate(eq(VERSION), anyList(), eq(4), eq(List.of("COLD"))))
                .thenReturn(new SiemUebaGateway.ScoreBatch(true, VERSION, null, List.of(score), 4));

        var worker = new AccountBehaviorScoringWorker(windows, incidents, history, gateway, true);
        ReflectionTestUtils.setField(worker, "candidateAcceptanceEnabled", true);
        worker.scorePendingCandidateAt(NOW, VERSION, List.of(window.getId()));

        assertThat(window.getScoreStatus()).isEqualTo(BehaviorScoreStatus.SCORED_MODEL);
        assertThat(window.getModelVersion()).isEqualTo(VERSION);
        assertThat(window.getScoredFeatureSchemaVersion()).isEqualTo(4);
        assertThat(window.getAnomalyPercentile()).isEqualTo(1.0);
        verify(gateway).scoreCandidate(eq(VERSION), anyList(), eq(4), eq(List.of("COLD")));
        verify(windows).save(window);
        verify(incidents, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void actualCandidateScoringLabelsFiveHundredOnlyAsOperationalNotAttack() throws Exception {
        var windows = mock(SiemAccountBehaviorWindowRepository.class);
        var incidents = mock(SiemIncidentRepository.class);
        var history = mock(SiemIncidentHistoryRepository.class);
        var gateway = mock(SiemUebaGateway.class);
        var window = schemaFourWindow(List.of(20.0, 0.0, 8.0, 0.0, 0.0, 0.0,
                4.0, 1.0, 0.0, 0.0, 0.0));
        when(windows.findAllById(List.of(window.getId()))).thenReturn(List.of(window));
        when(incidents.findByGroupingKey(org.mockito.ArgumentMatchers.anyString())).thenReturn(Optional.empty());
        var policy = UebaScorePolicy.fromWire(UebaTestPolicies.sessionEndpoint(new ObjectMapper()), 4);
        var score = new SiemUebaGateway.Score(1.0, 100.0, "VERY_UNUSUAL", policy, "COLD");
        when(gateway.scoreCandidate(eq(VERSION), anyList(), eq(4), eq(List.of("COLD"))))
                .thenReturn(new SiemUebaGateway.ScoreBatch(true, VERSION, null, List.of(score), 4, policy, "c".repeat(64)));
        var worker = new AccountBehaviorScoringWorker(windows, incidents, history, gateway, true);
        ReflectionTestUtils.setField(worker, "candidateAcceptanceEnabled", true);

        worker.scorePendingCandidateAt(NOW, VERSION, List.of(window.getId()));

        ArgumentCaptor<SiemIncident> created = ArgumentCaptor.forClass(SiemIncident.class);
        verify(incidents).save(created.capture());
        assertThat(created.getValue().getNature()).isEqualTo(IncidentNature.OPERATIONAL_ANOMALY);
        assertThat(created.getValue().getTitle()).isEqualTo("Operational server errors in account traffic");
        assertThat(created.getValue().getClassificationReason()).contains("HTTP server errors");
        assertThat(created.getValue().getTitle()).doesNotContain("confirmed attack");
    }

    @Test
    void candidateScoringRequiresExplicitAcceptanceMode() {
        var worker = new AccountBehaviorScoringWorker(mock(SiemAccountBehaviorWindowRepository.class),
                mock(SiemIncidentRepository.class), mock(SiemIncidentHistoryRepository.class),
                mock(SiemUebaGateway.class), true);
        assertThatThrownBy(() -> worker.scorePendingCandidateAt(NOW, VERSION, List.of("window-id")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void candidateWorkerFailureCannotBeSilentlyRecordedAsRuleOnly() {
        var windows = mock(SiemAccountBehaviorWindowRepository.class);
        var incidents = mock(SiemIncidentRepository.class);
        var gateway = mock(SiemUebaGateway.class);
        var window = schemaFourWindow();
        when(windows.findAllById(List.of(window.getId()))).thenReturn(List.of(window));
        when(gateway.scoreCandidate(eq(VERSION), anyList(), eq(4), eq(List.of("COLD"))))
                .thenThrow(new IllegalStateException("worker unavailable"));
        var worker = new AccountBehaviorScoringWorker(windows, incidents,
                mock(SiemIncidentHistoryRepository.class), gateway, true);
        ReflectionTestUtils.setField(worker, "candidateAcceptanceEnabled", true);

        assertThatThrownBy(() -> worker.scorePendingCandidateAt(NOW, VERSION, List.of(window.getId())))
                .isInstanceOf(IllegalStateException.class).hasMessage("worker unavailable");
        assertThat(window.getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
        verify(windows, never()).save(window);
    }

    private static SiemAccountBehaviorWindow schemaFourWindow() {
        return schemaFourWindow(java.util.Collections.nCopies(AccountBehaviorFeatures.FEATURE_COUNT, 0.0));
    }

    private static SiemAccountBehaviorWindow schemaFourWindow(List<Double> baseValues) {
        LocalDateTime start = NOW.minusMinutes(15);
        var window = new SiemAccountBehaviorWindow();
        window.setId("ueba-window-candidate-acceptance");
        window.setAccountId("candidate-acceptance-account");
        window.setWindowStart(start);
        window.setWindowEnd(NOW);
        window.setCreatedAt(start);
        var base = new AccountBehaviorFeatures.Vector(AccountBehaviorFeatures.SCHEMA_VERSION, baseValues);
        int eventCount = baseValues.get(0).intValue() + baseValues.get(3).intValue() + baseValues.get(4).intValue();
        window.replaceFeatures(base, eventCount, false, "8.8.8.8", "FIREFOX", "REAL", start);
        var personalValues = new ArrayList<>(base.values());
        personalValues.add(0.0); personalValues.add(0.0);
        personalValues.add(baseValues.get(1) / Math.max(1.0, baseValues.get(0)));
        personalValues.add(baseValues.get(3) / Math.max(1.0, baseValues.get(3) + baseValues.get(4)));
        var personal = new AccountBehaviorFeatures.Vector(2, personalValues);
        window.replacePersonalFeatures(personal, start);
        var contextualValues = new ArrayList<>(personal.values());
        contextualValues.add(baseValues.get(0) > 0 ? 1.0 : 0.0);
        contextualValues.add(baseValues.get(0) > 1 ? 1.0 : 0.0);
        contextualValues.add(0.0); contextualValues.add(0.0); contextualValues.add(0.0);
        contextualValues.add(0.0); contextualValues.add(0.0);
        contextualValues.add(baseValues.get(3) > 0 ? 1.0 : 0.0);
        contextualValues.add(baseValues.get(5) > 0 ? 1.0 : 0.0);
        contextualValues.add(baseValues.get(1) > 0 ? 1.0 : 0.0);
        var contextual = new AccountBehaviorFeatures.Vector(3, contextualValues);
        window.replaceContextualFeatures(contextual, start);
        var endpointValues = new ArrayList<>(contextual.values());
        endpointValues.add(baseValues.get(0));
        endpointValues.add(Math.min(20.0, baseValues.get(6)));
        endpointValues.add(0.0); endpointValues.add(0.0); endpointValues.add(0.0);
        endpointValues.add(baseValues.get(0) > 0 ? 1.0 : 0.0);
        endpointValues.add(0.0); endpointValues.add(0.0); endpointValues.add(0.0);
        endpointValues.add(0.0); endpointValues.add(0.0); endpointValues.add(0.0);
        var endpoint = new AccountBehaviorFeatures.Vector(4, endpointValues);
        window.replaceSessionEndpointFeatures(endpoint, start);
        assertThat(window.hasModelFeatures(4)).isTrue();
        return window;
    }
}
