package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Scores immutable window snapshots and only creates human-reviewed L1 cases. */
@Component
public class AccountBehaviorScoringWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccountBehaviorScoringWorker.class);
    private final SiemAccountBehaviorWindowRepository windows;
    private final SiemIncidentRepository incidents;
    private final SiemIncidentHistoryRepository history;
    private final SiemUebaGateway model;
    private final boolean enabled;
    @Value("${siem.ueba.candidate-acceptance.enabled:false}")
    private boolean candidateAcceptanceEnabled;
    private final AtomicBoolean running = new AtomicBoolean();

    public AccountBehaviorScoringWorker(SiemAccountBehaviorWindowRepository windows,
                                        SiemIncidentRepository incidents,
                                        SiemIncidentHistoryRepository history,
                                        SiemUebaGateway model,
                                        @Value("${siem.ueba.enabled:false}") boolean enabled) {
        this.windows = windows;
        this.incidents = incidents;
        this.history = history;
        this.model = model;
        this.enabled = enabled;
    }

    @Scheduled(initialDelayString = "${siem.ueba.initial-delay-ms:20000}",
            fixedDelayString = "${siem.ueba.score-interval-ms:30000}")
    @Transactional
    public void scorePending() {
        if (!enabled || !running.compareAndSet(false, true)) return;
        try {
            scorePendingAt(LocalDateTime.now(ZoneOffset.UTC));
        } catch (RuntimeException exception) {
            LOGGER.warn("UEBA scoring failed exceptionType={}", exception.getClass().getSimpleName());
            throw exception;
        } finally {
            running.set(false);
        }
    }

    @Transactional
    public void scorePendingAt(LocalDateTime now) {
        scorePendingAt(now, null);
    }

    /** Explicit integration-harness path; never called by the scheduler or a controller. */
    @Transactional
    public void scorePendingCandidateAt(LocalDateTime now, String modelVersion, List<String> windowIds) {
        if (!enabled || !candidateAcceptanceEnabled || now == null || modelVersion == null
                || !modelVersion.matches("[a-z0-9_-]{8,64}")) {
            throw new IllegalStateException("Explicit local selected-candidate acceptance mode required.");
        }
        if (windowIds == null || windowIds.isEmpty() || windowIds.size() > 100
                || windowIds.stream().anyMatch(id -> id == null || !id.matches("[A-Za-z0-9_-]{1,64}"))
                || Set.copyOf(windowIds).size() != windowIds.size()) {
            throw new IllegalArgumentException("A unique bounded set of server-owned window IDs is required.");
        }
        Map<String, SiemAccountBehaviorWindow> selected = new HashMap<>();
        windows.findAllById(windowIds).forEach(window -> selected.put(window.getId(), window));
        if (selected.size() != windowIds.size()) {
            throw new IllegalArgumentException("Every selected-candidate window must exist.");
        }
        List<SiemAccountBehaviorWindow> pending = windowIds.stream().map(selected::get).toList();
        if (pending.stream().anyMatch(window -> window.getScoreStatus() != BehaviorScoreStatus.PENDING
                || !window.hasModelFeatures(4))) {
            throw new IllegalArgumentException("Only explicitly selected pending schema-4 windows can be candidate-scored.");
        }
        scorePendingAt(now, modelVersion, pending);
    }

    private void scorePendingAt(LocalDateTime now, String candidateVersion) {
        List<SiemAccountBehaviorWindow> pending = windows.findByScoreStatusOrderByWindowStartAsc(
                BehaviorScoreStatus.PENDING, PageRequest.of(0, 100));
        scorePendingAt(now, candidateVersion, pending);
    }

    private void scorePendingAt(LocalDateTime now, String candidateVersion,
                                List<SiemAccountBehaviorWindow> pending) {
        if (pending.isEmpty()) return;
        SiemUebaGateway.ScoreBatch batch;
        List<SiemAccountBehaviorWindow> eligible;
        try {
            int schema = candidateVersion == null ? model.health().featureSchemaVersion() : 4;
            eligible = pending.stream().filter(window -> window.hasModelFeatures(schema)).toList();
            if (candidateVersion != null && eligible.size() != pending.size()) {
                throw new IllegalArgumentException("All selected-candidate acceptance windows must contain schema-4 snapshots.");
            }
            if (eligible.isEmpty()) {
                batch = SiemUebaGateway.ScoreBatch.unavailable("MODEL_FEATURE_SNAPSHOT_UNAVAILABLE");
            } else {
                List<List<Double>> vectors = eligible.stream()
                        .map(window -> window.modelFeatureVector(schema)).toList();
                List<String> cohorts = eligible.stream()
                        .map(window -> window.isBaselineEstablished() ? "READY" : "COLD").toList();
                batch = candidateVersion == null
                        ? model.score(vectors, schema, cohorts)
                        : model.scoreCandidate(candidateVersion, vectors, schema, cohorts);
                if (candidateVersion != null && (!batch.available() || batch.results().size() != eligible.size())) {
                    throw new IllegalStateException("Selected-candidate worker did not score the exact window batch.");
                }
            }
        } catch (RuntimeException exception) {
            if (candidateVersion != null) throw exception;
            LOGGER.warn("UEBA model unavailable; rule-only assessment used exceptionType={}",
                    exception.getClass().getSimpleName());
            batch = SiemUebaGateway.ScoreBatch.unavailable("WORKER_UNAVAILABLE");
            eligible = List.of();
        }
        Map<String, SiemUebaGateway.Score> results = new HashMap<>();
        if (batch.available()) for (int index = 0; index < eligible.size(); index++) {
            results.put(eligible.get(index).getId(), batch.results().get(index));
        }
        for (SiemAccountBehaviorWindow window : pending) {
            SiemUebaGateway.Score modelScore = results.get(window.getId());
            AccountBehaviorFeatures.Vector features = new AccountBehaviorFeatures.Vector(
                    window.getFeatureSchemaVersion(), window.featureVector());
            AccountRiskEngine.Assessment assessment = AccountRiskEngine.assess(
                    features, modelScore, window.isBaselineEstablished());
            String reason = String.join("; ", assessment.reasons());
            if (!assessment.modelAvailable()) {
                reason = (reason.isBlank() ? "" : reason + "; ") + "Model unavailable: rule-only assessment";
            }
            window.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment(
                    modelScore == null ? null : batch.modelVersion(),
                    modelScore == null ? null : modelScore.normalPercentile(),
                    assessment.riskScore(), trim(reason, 2000),
                    modelScore == null ? null : batch.featureSchemaVersion()), now);
            windows.save(window);
            if (assessment.createIncident()) upsertIncident(window, assessment, now);
        }
    }

    private void upsertIncident(SiemAccountBehaviorWindow window,
                                AccountRiskEngine.Assessment assessment, LocalDateTime now) {
        String groupingKey = "ueba:" + window.getAccountId() + ":"
                + window.getWindowStart().truncatedTo(ChronoUnit.HOURS);
        SiemIncident incident = incidents.findByGroupingKey(groupingKey).orElse(null);
        if (incident == null) {
            incident = new SiemIncident();
            incident.setId("siem-incident-" + UUID.randomUUID());
            incident.setGroupingKey(groupingKey);
            incident.setQueueTier(IncidentQueueTier.L1);
            incident.setOrigin(IncidentOrigin.UEBA);
            incident.setTargetUserId(window.getAccountId());
            incident.setServiceId("flare-web");
            incident.setRuleId("FLARE_UEBA_ACCOUNT_ANOMALY");
            incident.setBucketStart(window.getWindowStart());
            incident.setTitle("Unusual customer account activity");
            incident.setStatus(IncidentStatus.NEW);
            incident.setConclusion(IncidentConclusion.UNREVIEWED);
            incident.setManualInvestigateOverride(false);
            incident.setAlertCount(1);
            incident.setDistinctRuleCount(1);
            incident.setFirstSeen(window.getWindowStart());
            incident.setLastSeen(window.getWindowEnd());
            incident.setCreatedAt(now);
            incident.setUpdatedAt(now);
            updateRisk(incident, window, assessment, now);
            incidents.save(incident);
            recordHistory(incident.getId(), "UEBA_DETECTED", "A behavior window raised an L1 case", now);
            return;
        }
        updateNature(incident, window);
        boolean newWindow = window.getWindowEnd().isAfter(incident.getLastSeen());
        if (newWindow) {
            incident.setLastSeen(window.getWindowEnd());
            incident.setAlertCount(incident.getAlertCount() + 1);
        }
        if (window.getWindowStart().isBefore(incident.getFirstSeen())) {
            incident.setFirstSeen(window.getWindowStart());
        }
        if (assessment.riskScore() > incident.getScore()) updateRisk(incident, window, assessment, now);
        if (newWindow && incident.getStatus() == IncidentStatus.CLOSED) {
            incident.setStatus(IncidentStatus.NEW);
            incident.setConclusion(IncidentConclusion.UNREVIEWED);
            incident.setAssigneeUserId(null);
            recordHistory(incident.getId(), "UEBA_REOPENED", "New behavior after closure", now);
        }
        incident.setUpdatedAt(now);
        incidents.save(incident);
    }

    private void updateRisk(SiemIncident incident, SiemAccountBehaviorWindow window,
                            AccountRiskEngine.Assessment assessment, LocalDateTime now) {
        updateNature(incident, window);
        incident.setScore(assessment.riskScore());
        incident.setSeverity(assessment.severity());
        incident.setSourceSeverity(sourceSeverity(assessment.severity()));
        incident.setClassification(IncidentClassification.INVESTIGATE);
        incident.setClassificationReason(trim(window.getRiskReasons(), 1000));
        incident.setMissingData(!assessment.modelAvailable() || !window.isBaselineEstablished());
        incident.setDetectorModelVersion(assessment.modelAvailable() ? window.getModelVersion() : null);
        if (window.getSourceIp() != null) incident.setSourceIp(window.getSourceIp());
        incident.setUpdatedAt(now);
    }

    private void updateNature(SiemIncident incident, SiemAccountBehaviorWindow window) {
        var nature = IncidentNatureClassifier.merge(incident.getNature(),
                IncidentNatureClassifier.fromUebaWindow(window));
        incident.setNature(nature);
        incident.setTitle(switch (nature) {
            case OPERATIONAL_ANOMALY -> "Operational server errors in account traffic";
            case MIXED_ANOMALY -> "Mixed operational and account-security anomaly";
            case ACCOUNT_BEHAVIOR_ANOMALY -> "Unusual customer account activity";
            default -> "Unusual customer account activity";
        });
    }

    private String sourceSeverity(IncidentSeverity severity) {
        return switch (severity) {
            case LOW -> "low";
            case MEDIUM -> "medium";
            case HIGH -> "high";
            case URGENT -> "critical";
        };
    }

    private void recordHistory(String incidentId, String action, String detail, LocalDateTime now) {
        SiemIncidentHistory event = new SiemIncidentHistory();
        event.setId("siem-history-" + UUID.randomUUID());
        event.setIncidentId(incidentId);
        event.setAction(action);
        event.setDetail(detail);
        event.setCreatedAt(now);
        history.save(event);
    }

    private String trim(String value, int limit) {
        if (value == null) return "";
        return value.substring(0, Math.min(value.length(), limit));
    }
}
