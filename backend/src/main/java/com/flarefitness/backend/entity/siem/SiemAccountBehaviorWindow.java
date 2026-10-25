package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;
import java.util.List;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Entity
@Table(name = "siem_account_behavior_windows")
public class SiemAccountBehaviorWindow extends BaseEntity {
    private static final ObjectMapper FEATURE_JSON = new ObjectMapper();
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "account_id", nullable = false, length = 64)
    private String accountId;
    @Column(name = "source_ip", length = 64)
    private String sourceIp;
    @Column(name = "user_agent_family", length = 32)
    private String userAgentFamily;
    @Column(name = "demo_label", nullable = false, length = 16)
    private String demoLabel = "REAL";
    @Column(name = "window_start", nullable = false)
    @UtcDateTime
    private LocalDateTime windowStart;
    @Column(name = "window_end", nullable = false)
    @UtcDateTime
    private LocalDateTime windowEnd;
    @Column(name = "feature_schema_version", nullable = false)
    private int featureSchemaVersion;
    @Column(name = "personal_feature_schema_version")
    private Integer personalFeatureSchemaVersion;
    @Column(name = "personal_feature_vector_json", length = 2000)
    private String personalFeatureVectorJson;
    @Column(name = "contextual_feature_schema_version")
    private Integer contextualFeatureSchemaVersion;
    @Column(name = "contextual_feature_vector_json", length = 4000)
    private String contextualFeatureVectorJson;
    @Column(name = "session_endpoint_feature_schema_version")
    private Integer sessionEndpointFeatureSchemaVersion;
    @Column(name = "session_endpoint_feature_vector_json", length = 6000)
    private String sessionEndpointFeatureVectorJson;
    @Column(name = "scored_feature_schema_version")
    private Integer scoredFeatureSchemaVersion;
    @Column(name = "event_count", nullable = false)
    private int eventCount;
    @Column(name = "request_count", nullable = false)
    private int requestCount;
    @Column(name = "http_4xx_count", nullable = false)
    private int http4xxCount;
    @Column(name = "http_5xx_count", nullable = false)
    private int http5xxCount;
    @Column(name = "failed_login_count", nullable = false)
    private int failedLoginCount;
    @Column(name = "successful_login_count", nullable = false)
    private int successfulLoginCount;
    @Column(name = "sensitive_action_count", nullable = false)
    private int sensitiveActionCount;
    @Column(name = "distinct_route_group_count", nullable = false)
    private int distinctRouteGroupCount;
    @Column(name = "distinct_source_ip_count", nullable = false)
    private int distinctSourceIpCount;
    @Column(name = "new_ip_flag", nullable = false)
    private boolean newIpFlag;
    @Column(name = "new_user_agent_flag", nullable = false)
    private boolean newUserAgentFlag;
    @Column(name = "unusual_hour_flag", nullable = false)
    private boolean unusualHourFlag;
    @Column(name = "baseline_established", nullable = false)
    private boolean baselineEstablished;
    @Enumerated(EnumType.STRING)
    @Column(name = "score_status", nullable = false, length = 24)
    private BehaviorScoreStatus scoreStatus = BehaviorScoreStatus.PENDING;
    @Column(name = "model_version", length = 64)
    private String modelVersion;
    @Column(name = "anomaly_percentile")
    private Double anomalyPercentile;
    @Column(name = "risk_score")
    private Integer riskScore;
    @Column(name = "risk_reasons", length = 2000)
    private String riskReasons;
    @Column(name = "scored_at")
    @UtcDateTime
    private LocalDateTime scoredAt;
    @Column(name = "updated_at", nullable = false)
    @UtcDateTime
    private LocalDateTime updatedAt;
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    public void replaceFeatures(AccountBehaviorFeatures.Vector vector, int events, boolean established,
                                String representativeSourceIp, String representativeUserAgent, String sourceLabel,
                                LocalDateTime now) {
        if (vector.featureSchemaVersion() != AccountBehaviorFeatures.SCHEMA_VERSION || events < 0) {
            throw new IllegalArgumentException("Incompatible behavior features.");
        }
        List<Double> values = vector.values();
        boolean changed = !values.equals(featureVector()) || baselineEstablished != established
                || eventCount != events || !java.util.Objects.equals(sourceIp, representativeSourceIp)
                || !java.util.Objects.equals(userAgentFamily, representativeUserAgent)
                || !java.util.Objects.equals(demoLabel, sourceLabel);
        featureSchemaVersion = vector.featureSchemaVersion();
        eventCount = events;
        requestCount = values.get(0).intValue();
        http4xxCount = values.get(1).intValue();
        http5xxCount = values.get(2).intValue();
        failedLoginCount = values.get(3).intValue();
        successfulLoginCount = values.get(4).intValue();
        sensitiveActionCount = values.get(5).intValue();
        distinctRouteGroupCount = values.get(6).intValue();
        distinctSourceIpCount = values.get(7).intValue();
        newIpFlag = values.get(8) == 1.0;
        newUserAgentFlag = values.get(9) == 1.0;
        unusualHourFlag = values.get(10) == 1.0;
        baselineEstablished = established;
        sourceIp = representativeSourceIp;
        userAgentFamily = representativeUserAgent;
        demoLabel = sourceLabel;
        if (changed) {
            personalFeatureVectorJson = null;
            personalFeatureSchemaVersion = null;
            contextualFeatureVectorJson = null;
            contextualFeatureSchemaVersion = null;
            sessionEndpointFeatureVectorJson = null;
            sessionEndpointFeatureSchemaVersion = null;
            scoreStatus = BehaviorScoreStatus.PENDING;
            modelVersion = null;
            anomalyPercentile = null;
            riskScore = null;
            riskReasons = null;
            scoredAt = null;
            scoredFeatureSchemaVersion = null;
        }
        updatedAt = now;
    }

    public void replacePersonalFeatures(AccountBehaviorFeatures.Vector vector, LocalDateTime now) {
        if (vector.featureSchemaVersion() != AccountBehaviorFeatures.PERSONAL_SCHEMA_VERSION
                || !vector.base().values().equals(featureVector())) {
            throw new IllegalArgumentException("Personal snapshot must match this window's raw features.");
        }
        String encoded = vector.values().toString(); // Finite numeric arrays are valid JSON; no identity/PII.
        if (!encoded.equals(personalFeatureVectorJson)) {
            personalFeatureVectorJson = encoded;
            personalFeatureSchemaVersion = AccountBehaviorFeatures.PERSONAL_SCHEMA_VERSION;
            contextualFeatureVectorJson = null;
            contextualFeatureSchemaVersion = null;
            sessionEndpointFeatureVectorJson = null;
            sessionEndpointFeatureSchemaVersion = null;
            scoreStatus = BehaviorScoreStatus.PENDING;
            modelVersion = null;
            anomalyPercentile = null;
            riskScore = null;
            riskReasons = null;
            scoredAt = null;
            scoredFeatureSchemaVersion = null;
        }
        updatedAt = now;
    }

    /** Separate versioned snapshot; adding v3 alone never invalidates a v1/v2 score. */
    public void replaceContextualFeatures(AccountBehaviorFeatures.Vector vector, LocalDateTime now) {
        if (vector.featureSchemaVersion() != AccountBehaviorFeatures.CONTEXTUAL_SCHEMA_VERSION
                || !vector.values().subList(0, 15).equals(modelFeatureVector(2))) {
            throw new IllegalArgumentException("Contextual snapshot must preserve this window's personal prefix.");
        }
        String encoded = vector.values().toString();
        if (!encoded.equals(contextualFeatureVectorJson)) {
            contextualFeatureVectorJson = encoded;
            contextualFeatureSchemaVersion = AccountBehaviorFeatures.CONTEXTUAL_SCHEMA_VERSION;
            sessionEndpointFeatureVectorJson = null;
            sessionEndpointFeatureSchemaVersion = null;
            if (Integer.valueOf(3).equals(scoredFeatureSchemaVersion) || Integer.valueOf(4).equals(scoredFeatureSchemaVersion)) {
                scoreStatus = BehaviorScoreStatus.PENDING; modelVersion = null; anomalyPercentile = null;
                riskScore = null; riskReasons = null; scoredAt = null; scoredFeatureSchemaVersion = null;
            }
        }
        updatedAt = now;
    }

    /** Separate snapshot: adding/changing v4 never invalidates a schema 1-3 score. */
    public void replaceSessionEndpointFeatures(AccountBehaviorFeatures.Vector vector, LocalDateTime now) {
        if (vector.featureSchemaVersion() != AccountBehaviorFeatures.SESSION_ENDPOINT_SCHEMA_VERSION
                || !vector.values().subList(0, AccountBehaviorFeatures.CONTEXTUAL_NAMES.size()).equals(modelFeatureVector(3))) {
            throw new IllegalArgumentException("Session/endpoint snapshot must preserve this window's contextual prefix.");
        }
        String encoded = vector.values().toString();
        if (!encoded.equals(sessionEndpointFeatureVectorJson)) {
            sessionEndpointFeatureVectorJson = encoded;
            sessionEndpointFeatureSchemaVersion = AccountBehaviorFeatures.SESSION_ENDPOINT_SCHEMA_VERSION;
            if (Integer.valueOf(4).equals(scoredFeatureSchemaVersion)) {
                scoreStatus = BehaviorScoreStatus.PENDING; modelVersion = null; anomalyPercentile = null;
                riskScore = null; riskReasons = null; scoredAt = null; scoredFeatureSchemaVersion = null;
            }
        }
        updatedAt = now;
    }

    public void recordAssessment(AccountRiskAssessment assessment, LocalDateTime now) {
        scoreStatus = assessment.modelVersion() == null
                ? BehaviorScoreStatus.SCORED_RULE_ONLY : BehaviorScoreStatus.SCORED_MODEL;
        modelVersion = assessment.modelVersion();
        scoredFeatureSchemaVersion = modelVersion == null ? null : assessment.featureSchemaVersion();
        anomalyPercentile = assessment.anomalyPercentile();
        riskScore = assessment.riskScore();
        riskReasons = assessment.reasons();
        scoredAt = now;
        updatedAt = now;
    }

    public record AccountRiskAssessment(String modelVersion, Double anomalyPercentile,
                                        int riskScore, String reasons, Integer featureSchemaVersion) {
        public AccountRiskAssessment(String modelVersion, Double anomalyPercentile, int riskScore, String reasons) {
            this(modelVersion, anomalyPercentile, riskScore, reasons, modelVersion == null ? null : 1);
        }
    }

    public boolean hasModelFeatures(int schema) {
        return schema == 1 || schema == 2 && personalFeatureVectorJson != null
                && Integer.valueOf(2).equals(personalFeatureSchemaVersion)
                || schema == 3 && contextualFeatureVectorJson != null && Integer.valueOf(3).equals(contextualFeatureSchemaVersion)
                && personalFeatureVectorJson != null && Integer.valueOf(2).equals(personalFeatureSchemaVersion)
                || schema == 4 && sessionEndpointFeatureVectorJson != null && Integer.valueOf(4).equals(sessionEndpointFeatureSchemaVersion)
                && hasModelFeatures(3);
    }

    public List<Double> modelFeatureVector(int schema) {
        if (schema == 1) return featureVector();
        if (!hasModelFeatures(schema)) throw new IllegalArgumentException("Model feature snapshot unavailable.");
        try {
            String encoded = schema == 4 ? sessionEndpointFeatureVectorJson : schema == 3
                    ? contextualFeatureVectorJson : personalFeatureVectorJson;
            List<Double> values = FEATURE_JSON.readValue(encoded, new TypeReference<>() { });
            var vector = new AccountBehaviorFeatures.Vector(schema, values);
            if (!vector.base().values().equals(featureVector())) {
                throw new IllegalArgumentException("Personal snapshot does not match raw features.");
            }
            if (schema == 3 && !vector.values().subList(0, 15).equals(modelFeatureVector(2))) {
                throw new IllegalArgumentException("Contextual snapshot does not match personal prefix.");
            }
            if (schema == 4 && !vector.values().subList(0, AccountBehaviorFeatures.CONTEXTUAL_NAMES.size()).equals(modelFeatureVector(3))) {
                throw new IllegalArgumentException("Session/endpoint snapshot does not match contextual prefix.");
            }
            return vector.values();
        } catch (com.fasterxml.jackson.core.JsonProcessingException exception) {
            throw new IllegalArgumentException("Invalid personal feature snapshot.", exception);
        }
    }

    public List<Double> featureVector() {
        return List.of((double) requestCount, (double) http4xxCount, (double) http5xxCount,
                (double) failedLoginCount, (double) successfulLoginCount, (double) sensitiveActionCount,
                (double) distinctRouteGroupCount, (double) distinctSourceIpCount,
                newIpFlag ? 1.0 : 0.0, newUserAgentFlag ? 1.0 : 0.0, unusualHourFlag ? 1.0 : 0.0);
    }

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getAccountId() { return accountId; }
    public void setAccountId(String value) { accountId = value; }
    public String getSourceIp() { return sourceIp; }
    public String getUserAgentFamily() { return userAgentFamily; }
    public String getDemoLabel() { return demoLabel; }
    public LocalDateTime getWindowStart() { return windowStart; }
    public void setWindowStart(LocalDateTime value) { windowStart = value; }
    public LocalDateTime getWindowEnd() { return windowEnd; }
    public void setWindowEnd(LocalDateTime value) { windowEnd = value; }
    public int getFeatureSchemaVersion() { return featureSchemaVersion; }
    public Integer getPersonalFeatureSchemaVersion() { return personalFeatureSchemaVersion; }
    public Integer getContextualFeatureSchemaVersion() { return contextualFeatureSchemaVersion; }
    public Integer getSessionEndpointFeatureSchemaVersion() { return sessionEndpointFeatureSchemaVersion; }
    public Integer getScoredFeatureSchemaVersion() { return scoredFeatureSchemaVersion; }
    public int getEventCount() { return eventCount; }
    public int getHttp4xxCount() { return http4xxCount; }
    public int getHttp5xxCount() { return http5xxCount; }
    public int getFailedLoginCount() { return failedLoginCount; }
    public int getSensitiveActionCount() { return sensitiveActionCount; }
    public boolean isNewIpFlag() { return newIpFlag; }
    public boolean isNewUserAgentFlag() { return newUserAgentFlag; }
    public boolean isUnusualHourFlag() { return unusualHourFlag; }
    public boolean isBaselineEstablished() { return baselineEstablished; }
    public BehaviorScoreStatus getScoreStatus() { return scoreStatus; }
    public String getModelVersion() { return modelVersion; }
    public Double getAnomalyPercentile() { return anomalyPercentile; }
    public Integer getRiskScore() { return riskScore; }
    public String getRiskReasons() { return riskReasons; }
    public LocalDateTime getScoredAt() { return scoredAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public Long getVersion() { return version; }
}
