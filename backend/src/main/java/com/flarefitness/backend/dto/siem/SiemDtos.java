package com.flarefitness.backend.dto.siem;

import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public final class SiemDtos {
    private SiemDtos() {
    }

    public record Overview(
            long openIncidents,
            long newIncidents,
            long inProgressIncidents,
            long incidentsLast24Hours,
            Map<IncidentSeverity, Long> bySeverity,
            Map<IncidentClassification, Long> byClassification,
            LocalDateTime lastIngestionSuccess,
            boolean elasticsearchAvailable
    ) {
    }

    public enum IncidentScope {
        OPEN,
        ALL
    }

    public enum IncidentSort {
        PRIORITY,
        LATEST
    }

    public enum TransitionAction {
        CLAIM,
        ESCALATE,
        RETURN_TO_L1,
        CLOSE,
        REOPEN
    }

    public record Capabilities(String role, List<TransitionAction> actions,
                               boolean canRevokeCustomerSessions, boolean canManageModels) {
    }

    public record TransitionIncident(
            @NotNull Long expectedVersion,
            @NotNull TransitionAction action,
            @Size(max = 2000) String reason,
            IncidentConclusion conclusion
    ) {
    }

    public record RevokeSessions(
            @NotNull Long expectedVersion,
            @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{8,64}") String requestId,
            @NotBlank @Size(min = 10, max = 2000) String reason
    ) {
    }

    public record SessionRevocationResult(String id, String incidentId, String targetUserId,
                                          String actorUserId, long newAuthVersion,
                                          LocalDateTime effectiveAt, boolean sessionsInvalidated) {
    }

    public record UebaStatus(boolean workerAvailable, boolean modelAvailable,
                             String activeModelVersion, String activeModelProvenance,
                             String reason, int featureSchemaVersion,
                             List<String> featureNames, long pendingAggregationEvents,
                             long pendingExportEvents, long pendingScoringWindows) { }

    public record StartUebaTraining(@NotNull LocalDateTime from, @NotNull LocalDateTime to,
                                    @Pattern(regexp = "[a-z0-9_-]{8,96}") String recipeId) {
        public StartUebaTraining(LocalDateTime from, LocalDateTime to) { this(from, to, null); }
    }

    public record EvaluateUebaModel(@Pattern(regexp = "[a-z0-9_-]{8,64}") String datasetId) { }

    public record StartUebaShadow(@NotNull @Pattern(regexp = "[a-z0-9_-]{8,64}") String modelVersion) { }

    public record UebaShadowRun(String id, String modelVersion, String status, String dataProvenance,
                                LocalDateTime createdAt, LocalDateTime updatedAt, long acknowledgedWindows,
                                String lastErrorType, Map<String, Object> state) { }

    public record UebaRecipe(String recipeId, String datasetId, String dataProvenance,
                             int featureSchemaVersion, int trainingWindows, int calibrationWindows,
                             LocalDateTime from, LocalDateTime to, int completedSearchFits) { }

    public record UebaTrainingJob(String id, String modelVersion, String status,
                                  String dataProvenance, int trainingWindows, int calibrationWindows,
                                  LocalDateTime createdAt, LocalDateTime activatedAt,
                                  int featureSchemaVersion, String recipeId, String datasetId,
                                  String evaluationStatus, String qualityGate,
                                  Map<String, Object> evaluationSummary) {
        public UebaTrainingJob(String id, String modelVersion, String status, String dataProvenance,
                                int trainingWindows, int calibrationWindows, LocalDateTime createdAt, LocalDateTime activatedAt) {
            this(id, modelVersion, status, dataProvenance, trainingWindows, calibrationWindows,
                    createdAt, activatedAt, 1, "legacy-v1", null, "NOT_RUN", "NOT_RUN", Map.of());
        }
    }

    public enum AccountWatchView { RISK, BASELINE_GAPS, ALL }

    public record WatchAccount(String accountId, int maximumRisk,
                               LocalDateTime lastWindow, long flaggedWindows,
                               String baselineStatus, long trustedWindowCount,
                               int requiredWindowCount, int historyDays,
                               LocalDateTime baselineAsOf, boolean riskAvailable) {
        public WatchAccount(String accountId, int maximumRisk, LocalDateTime lastWindow, long flaggedWindows) {
            this(accountId, maximumRisk, lastWindow, flaggedWindows, null, 0, 30, 14, null, true);
        }
    }

    public record BehaviorWindow(String id, String accountId, LocalDateTime windowStart,
                                 LocalDateTime windowEnd, int eventCount,
                                 boolean baselineEstablished, Map<String, Double> features,
                                 String sourceIp, String userAgentFamily, String demoLabel,
                                 String scoreStatus, String modelVersion,
                                 Double anomalyPercentile, Integer riskScore,
                                 String riskReasons, Integer personalFeatureSchemaVersion,
                                 Integer scoredFeatureSchemaVersion) { }

    /** Only server-authored, allowlisted fields; never request bodies, URLs or credentials. */
    public record SecurityEventEvidence(String id, LocalDateTime eventTimestamp,
                                        String eventType, String action, String outcome,
                                        String sourceIp, String routeGroup, Integer httpStatus,
                                        String userAgentFamily, String traceId,
                                        String demoLabel) { }

    public record DashboardSummary(
            LocalDateTime from,
            LocalDateTime to,
            long totalIncidents,
            long investigateIncidents,
            long potentialNoiseIncidents,
            long closedIncidents,
            Map<IncidentSeverity, Long> bySeverity,
            Map<IncidentStatus, Long> byStatus,
            Map<IncidentClassification, Long> byClassification,
            Map<IncidentQueueTier, Long> byQueueTier,
            Map<IncidentOrigin, Long> byOrigin
    ) {
    }

    /** Assigned staff identity only; never expose the underlying account or its credentials. */
    public record AssignedAnalyst(String name, String role) { }

    public record Incident(
            String id,
            String title,
            String serviceId,
            String ruleId,
            String sourceIp,
            LocalDateTime bucketStart,
            String sourceSeverity,
            int score,
            IncidentSeverity severity,
            IncidentClassification classification,
            String classificationReason,
            boolean missingData,
            IncidentStatus status,
            IncidentConclusion conclusion,
            String assigneeUserId,
            boolean manualInvestigateOverride,
            int alertCount,
            int distinctRuleCount,
            LocalDateTime firstSeen,
            LocalDateTime lastSeen,
            LocalDateTime updatedAt,
            long version,
            IncidentQueueTier queueTier,
            IncidentOrigin origin,
            String targetUserId,
            String detectorModelVersion,
            IncidentNature nature,
            @com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
            AssignedAnalyst assignedAnalyst
    ) {
        public Incident {
            if (nature == null) nature = IncidentNature.UNKNOWN;
        }

        public Incident withAssignedAnalyst(AssignedAnalyst analyst) {
            return new Incident(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score,
                    severity, classification, classificationReason, missingData, status, conclusion,
                    assigneeUserId, manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen,
                    lastSeen, updatedAt, version, queueTier, origin, targetUserId, detectorModelVersion, nature, analyst);
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, IncidentSeverity severity,
                        IncidentClassification classification, String classificationReason, boolean missingData,
                        IncidentStatus status, IncidentConclusion conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        IncidentQueueTier queueTier, IncidentOrigin origin, String targetUserId,
                        String detectorModelVersion, IncidentNature nature) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, detectorModelVersion, nature, null);
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, IncidentSeverity severity,
                        IncidentClassification classification, String classificationReason, boolean missingData,
                        IncidentStatus status, IncidentConclusion conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        IncidentQueueTier queueTier, IncidentOrigin origin, String targetUserId,
                        String detectorModelVersion) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, detectorModelVersion, IncidentNature.UNKNOWN);
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, IncidentSeverity severity,
                        IncidentClassification classification, String classificationReason, boolean missingData,
                        IncidentStatus status, IncidentConclusion conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        IncidentQueueTier queueTier, IncidentOrigin origin, String targetUserId) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, null, IncidentNature.UNKNOWN);
        }
    }

    public record IncidentDetail(Incident incident, List<Note> notes) {
    }

    public record UpdateIncident(
            @NotNull Long version,
            IncidentStatus status,
            IncidentConclusion conclusion,
            @Size(max = 2000) String note,
            Boolean manualInvestigateOverride
    ) {
    }

    public record AddNote(@NotBlank @Size(max = 2000) String content) {
    }

    public record Note(String id, String authorUserId, String content, LocalDateTime createdAt) {
    }

    public record History(
            String id,
            String incidentId,
            String actorUserId,
            String action,
            String previousValue,
            String newValue,
            String detail,
            LocalDateTime createdAt
    ) {
    }

    public record AlertRef(
            String id,
            String elasticAlertId,
            String elasticIndex,
            String ruleId,
            String serviceId,
            String sourceIp,
            String sourceSeverity,
            LocalDateTime eventTimestamp
    ) {
    }

    public record TestWindowRequest(
            @NotBlank @Size(max = 150) String name,
            @Size(max = 64) String sourceIp,
            @Size(max = 128) String serviceId,
            @NotNull LocalDateTime startsAt,
            @NotNull LocalDateTime endsAt
    ) {
    }

    public record TestWindow(
            String id,
            String name,
            String sourceIp,
            String serviceId,
            LocalDateTime startsAt,
            LocalDateTime endsAt,
            boolean active,
            String createdByUserId,
            LocalDateTime createdAt,
            LocalDateTime updatedAt,
            long version
    ) {
    }

    public record Status(
            boolean enabled,
            boolean elasticsearchAvailable,
            LocalDateTime lastSuccessAt,
            LocalDateTime lastErrorAt,
            String lastError
    ) {
    }

    public record ElasticDocument(String id, String index, Map<String, Object> source) {
    }

    public record GeoBucket(String countryCode, String countryName, double latitude, double longitude, long count) {
    }
}
