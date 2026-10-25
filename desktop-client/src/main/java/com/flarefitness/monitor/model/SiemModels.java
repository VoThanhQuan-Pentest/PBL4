package com.flarefitness.monitor.model;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public final class SiemModels {
    public record PostloginPolicy(String mode,String scope,String provenance,String modelVersion,long version,
                                  boolean operatorHold,int maximumHoldSeconds,boolean otpRequired) { }
    public record PostloginDecision(String id,String userId,String operation,String mode,String decision,String outcome,
            String context,Double normalPercentile,String incidentId,java.time.Instant createdAt,java.time.Instant holdExpiresAt,long version) { }
    public record PostloginReview(String id,String actorId,String verdict,String reason,java.time.Instant createdAt) { }
    public record PostloginDetail(PostloginDecision summary,String policyId,long policyVersion,String modelVersion,String modelSha256,
            String manifestSha256,boolean baselineEstablished,int trustedWindowCount,List<String> reasons,Map<String,Object> evidence,
            Map<String,Object> snapshot,boolean holdActive,java.time.Instant releasedAt,String releasedBy,String releaseReason,
            List<PostloginReview> reviews) { }
    public record GeoSummary(String sourceStatus,long events,long geolocated,long publicWithoutGeo,Map<String,Long> scopes,List<GeoBucket> locations) { }
    public record BlockWorkspace(Page<IpBlock> blocks,List<Map<String,Object>> ledger,String recurrenceMode,PreventionStatus policy) { }
    public record AuthCorrelationPolicy(String mode,String definitionVersion,long version) { }
    public record InvestigationQueueEntry(Incident incident,Map<String,ObservedGroup> observed,String sourceStatus,LocalDateTime firstObservedAt) {
        public InvestigationQueueEntry(Incident incident,Map<String,ObservedGroup> observed,String sourceStatus){this(incident,observed,sourceStatus,null);}
    }
    public record InvestigationTrend(String hour,long count) { }
    public record InvestigationMetrics(long open,long highOpen,long l2Open,long responsePendingFailed,List<InvestigationTrend> trend) { }
    public record ObservedValue(String value,String index,String id) { }
    public record ObservedGroup(List<ObservedValue> values,boolean hasMore) { }
    public record InvestigationSummary(Incident incident,Map<String,ObservedGroup> observed,
            Map<String,String> workflowContext,String sourceStatus,LocalDateTime from,LocalDateTime to,List<ContainmentAction> containment,LocalDateTime firstObservedAt) {
        public InvestigationSummary(Incident incident,Map<String,ObservedGroup> observed,Map<String,String> workflowContext,
                String sourceStatus,LocalDateTime from,LocalDateTime to,List<ContainmentAction> containment){this(incident,observed,workflowContext,sourceStatus,from,to,containment,null);}
    }
    public record TimelineEntry(String id,String kind,LocalDateTime occurredAt,com.fasterxml.jackson.databind.JsonNode elkHit,
            EvidenceAssociation association,com.fasterxml.jackson.databind.JsonNode details) { }
    public record TimelinePage(List<TimelineEntry> content,String nextCursor,String sourceStatus,LocalDateTime asOf) { }
    public record EvidenceAssociation(String incidentId,String matchType,String provenance) { }
    public record EvidenceItem(com.fasterxml.jackson.databind.JsonNode elkHit,EvidenceAssociation association) { }
    public record EvidencePage(List<EvidenceItem> content,String nextCursor,String sourceStatus) { }
    public record ContainmentAction(String id,String incidentId,String targetUserId,String actorUserId,
            String reason,String durationType,LocalDateTime expiresAt,String status,LocalDateTime createdAt,
            LocalDateTime releasedAt,long version) { }
    /** Client affordances mirror server role aliases; authorization remains server-side. */
    public static String socRole(User user) {
        if(user==null || user.role()==null)return "OTHER";
        String role=java.text.Normalizer.normalize(user.role(),java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}+", "").toLowerCase(java.util.Locale.ROOT)
                .replace('đ','d').replaceAll("[^a-z0-9\\s]"," ").replaceAll("\\s+"," ").trim();
        return switch(role) {
            case "admin","quan tri","quan tri vien" -> "ADMIN";
            case "soc l2","role soc l2" -> "L2";
            case "soc l1","role soc l1","analyst","security analyst","chuyen vien an ninh","chuyen vien bao mat" -> "L1";
            default -> "OTHER";
        };
    }

    private SiemModels() {
    }

    public record User(String id, String username, String role, String hoTen, String email, String sdt) {
    }

    public record LoginResponse(String accessToken, long expiresIn, User user) {
    }

    public record Overview(
            long openIncidents,
            long newIncidents,
            long inProgressIncidents,
            long incidentsLast24Hours,
            Map<String, Long> bySeverity,
            Map<String, Long> byClassification,
            LocalDateTime lastIngestionSuccess,
            boolean elasticsearchAvailable
    ) {
    }

    public record DashboardSummary(
            LocalDateTime from,
            LocalDateTime to,
            long totalIncidents,
            long investigateIncidents,
            long potentialNoiseIncidents,
            long closedIncidents,
            Map<String, Long> bySeverity,
            Map<String, Long> byStatus,
            Map<String, Long> byClassification,
            Map<String, Long> byQueueTier,
            Map<String, Long> byOrigin
    ) {
    }

    public record IncidentQuery(
            int page,
            int size,
            String query,
            String status,
            String severity,
            String classification,
            String scope,
            String sort,
            LocalDateTime from,
            LocalDateTime to,
            String queueTier,
            String origin,
            String targetUserId,
            boolean mine
    ) {
        public IncidentQuery(int page, int size, String query, String status, String severity,
                             String classification, String scope, String sort,
                             LocalDateTime from, LocalDateTime to) {
            this(page, size, query, status, severity, classification, scope, sort,
                    from, to, null, null, null, false);
        }
        public static IncidentQuery openPriority() {
            return new IncidentQuery(0, 50, null, null, null, null,
                    "OPEN", "PRIORITY", null, null);
        }
    }

    public record AssignedAnalyst(String name, String role) { }

    public record Incident(
            String id, String title, String serviceId, String ruleId, String sourceIp,
            LocalDateTime bucketStart, String sourceSeverity, int score, String severity,
            String classification, String classificationReason, boolean missingData,
            String status, String conclusion, String assigneeUserId,
            boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
            LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
            String queueTier, String origin, String targetUserId, String detectorModelVersion, String nature,
            AssignedAnalyst assignedAnalyst
    ) {
        public Incident {
            nature = nature == null || nature.isBlank() ? "UNKNOWN" : nature;
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, String severity,
                        String classification, String classificationReason, boolean missingData,
                        String status, String conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        String queueTier, String origin, String targetUserId, String detectorModelVersion, String nature) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, detectorModelVersion, nature, null);
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, String severity,
                        String classification, String classificationReason, boolean missingData,
                        String status, String conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        String queueTier, String origin, String targetUserId, String detectorModelVersion) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, detectorModelVersion, "UNKNOWN");
        }

        public Incident(String id, String title, String serviceId, String ruleId, String sourceIp,
                        LocalDateTime bucketStart, String sourceSeverity, int score, String severity,
                        String classification, String classificationReason, boolean missingData,
                        String status, String conclusion, String assigneeUserId,
                        boolean manualInvestigateOverride, int alertCount, int distinctRuleCount,
                        LocalDateTime firstSeen, LocalDateTime lastSeen, LocalDateTime updatedAt, long version,
                        String queueTier, String origin, String targetUserId) {
            this(id, title, serviceId, ruleId, sourceIp, bucketStart, sourceSeverity, score, severity,
                    classification, classificationReason, missingData, status, conclusion, assigneeUserId,
                    manualInvestigateOverride, alertCount, distinctRuleCount, firstSeen, lastSeen, updatedAt,
                    version, queueTier, origin, targetUserId, null, "UNKNOWN");
        }
    }

    public record Note(String id, String authorUserId, String content, LocalDateTime createdAt) {
    }

    public record IncidentDetail(Incident incident, List<Note> notes) {
    }

    public record AlertRef(String id, String elasticAlertId, String elasticIndex, String ruleId,
                           String serviceId, String sourceIp, String sourceSeverity,
                           LocalDateTime eventTimestamp) {
    }

    public record Page<T>(List<T> content, int page, int size, long totalElements, int totalPages, boolean hasNext) {
    }

    public record Status(boolean enabled, boolean elasticsearchAvailable, LocalDateTime lastSuccessAt,
                         LocalDateTime lastErrorAt, String lastError) {
    }

    public record UebaStatus(boolean workerAvailable, boolean modelAvailable,
                             String activeModelVersion, String activeModelProvenance, String reason,
                             int featureSchemaVersion, List<String> featureNames,
                             long pendingAggregationEvents, long pendingExportEvents,
                             long pendingScoringWindows) { }

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
        public boolean canActivate() {
            if (!"SUCCEEDED".equals(status) && !"RETIRED".equals(status)) return false;
            if ("LEGACY_RESTORE".equals(qualityGate) && activatedAt != null && featureSchemaVersion == 1) return true;
            return strictQualityReady() && "PASS".equals(evaluationSummary.get("shadow_gate"));
        }
        public boolean canEvaluate() { return "SUCCEEDED".equals(status) && "NOT_RUN".equals(evaluationStatus); }
        public boolean strictPolicy() {
            return evaluationSummary != null && ("STRICT".equals(evaluationSummary.get("catalogue_mode"))
                    || evaluationSummary.get("scopes") instanceof Map<?, ?>);
        }
        public boolean canStartShadow() {
            return "SUCCEEDED".equals(status) && strictQualityReady();
        }
        private boolean strictQualityReady() {
            if ((featureSchemaVersion != 2 && featureSchemaVersion != 3 && featureSchemaVersion != 4) || !strictPolicy() || !"PASS".equals(qualityGate) || !"SUCCEEDED".equals(evaluationStatus)) return false;
            try {
                var scopes = UebaQualityMetrics.from(evaluationSummary);
                return scopes.size() == 2 && scopes.stream().allMatch(scope -> "PASS".equals(scope.qualityGate())
                        && scope.counts().normal() >= 10000000 && scope.counts().positive() >= 10000
                        && scope.counts().precision() != null && scope.counts().precision() >= 0.998
                        && scope.counts().recall() > 0.99 && scope.counts().fpr() < 0.001
                        && scope.precision().available() && scope.precision().lower() >= 0.998
                        && scope.recall().available() && scope.recall().lower() > 0.99
                        && scope.falsePositiveRate().available() && scope.falsePositiveRate().upper() < 0.001);
            } catch (RuntimeException invalid) { return false; }
        }
    }

    public record UebaShadowRun(String id, String modelVersion, String status, String dataProvenance,
                                LocalDateTime createdAt, LocalDateTime updatedAt, long acknowledgedWindows,
                                String lastErrorType, Map<String, Object> state) {
        public double elapsedSeconds() {
            Object value = state == null ? null : state.get("elapsed_monotonic_seconds");
            return value instanceof Number number && Double.isFinite(number.doubleValue()) && number.doubleValue() >= 0 ? number.doubleValue() : 0;
        }
        public long closedWindows() {
            Object value = state == null ? null : state.get("closed_windows");
            return value instanceof Number number && number.longValue() >= 0 ? number.longValue() : 0;
        }
    }

    public record UebaRecipe(String recipeId, String datasetId, String dataProvenance,
                             int featureSchemaVersion, int trainingWindows, int calibrationWindows,
                             LocalDateTime from, LocalDateTime to, int completedSearchFits) { }

    public record AttackSignature(String id, long version, String kind,
                                  String httpMethod, String pathPrefix, String matchValue,
                                  String severity, String status, String action,
                                  String sourceIncidentId, String createdByUserId,
                                  String approvedByUserId, LocalDateTime createdAt,
                                  LocalDateTime updatedAt, LocalDateTime approvedAt) { }

    public record SignatureTestResult(boolean passed, int passedCases,
                                      int totalCases, String definitionHash) { }

    public record IpBlock(String id, String ipAddress, String reason,
                          String sourceType, String incidentId,
                          String createdByUserId, String revokedByUserId,
                          LocalDateTime startedAt, LocalDateTime expiresAt,
                          LocalDateTime revokedAt, long version) { }

    public record IpIntelligence(String ipAddress, String provider, String status,
                                 String countryCode, String asn, String asName,
                                 Boolean anonymousFlag, Boolean hostingFlag,
                                 Integer abuseScore, Integer totalReports,
                                 Integer distinctReporters, LocalDateTime observedAt,
                                 LocalDateTime expiresAt, String dataProvenance) { }

    public record PreventionStatus(long publishedVersion, Long appliedVersion,
                                   int activeSignatures, long activeIpBlocks,
                                   long blockedRequestsLast24h, long pendingLookups,
                                   String gatewayState, String ipinfoState,
                                   String abuseIpDbState) { }

    public record SessionRevocationResult(String id, String incidentId, String targetUserId,
                                          String actorUserId, long newAuthVersion,
                                          LocalDateTime effectiveAt, boolean sessionsInvalidated) { }

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

    public record SecurityEventEvidence(String id, LocalDateTime eventTimestamp,
                                        String eventType, String action, String outcome,
                                        String sourceIp, String routeGroup, Integer httpStatus,
                                        String userAgentFamily, String traceId,
                                        String demoLabel) { }

    public record ElasticDocument(String id, String index, Map<String, Object> source) {
    }

    public record GeoBucket(String countryCode, String countryName, double latitude, double longitude, long count) {
    }

    public record History(String id, String incidentId, String actorUserId, String action,
                          String previousValue, String newValue, String detail, LocalDateTime createdAt) {
    }

    public record TestWindow(String id, String name, String sourceIp, String serviceId,
                             LocalDateTime startsAt, LocalDateTime endsAt, boolean active,
                             String createdByUserId, LocalDateTime createdAt,
                             LocalDateTime updatedAt, long version) {
    }
}
