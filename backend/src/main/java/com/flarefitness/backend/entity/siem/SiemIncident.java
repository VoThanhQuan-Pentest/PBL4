package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_incidents")
public class SiemIncident extends BaseEntity {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "grouping_key", nullable = false, unique = true, length = 255)
    private String groupingKey;

    @Column(name = "service_id", length = 128)
    private String serviceId;

    @Column(name = "rule_id", length = 128)
    private String ruleId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Enumerated(EnumType.STRING)
    @Column(name = "queue_tier", nullable = false, length = 8)
    private IncidentQueueTier queueTier = IncidentQueueTier.L1;

    @Enumerated(EnumType.STRING)
    @Column(name = "origin", nullable = false, length = 16)
    private IncidentOrigin origin = IncidentOrigin.ELASTIC;

    @Enumerated(EnumType.STRING)
    @Column(name = "incident_nature", nullable = false, length = 32)
    private IncidentNature nature = IncidentNature.UNKNOWN;

    @Column(name = "target_user_id", length = 64)
    private String targetUserId;

    @Column(name = "detector_model_version", length = 64)
    private String detectorModelVersion;

    @Column(name = "bucket_start", nullable = false)
    @UtcDateTime
    private LocalDateTime bucketStart;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "source_severity", nullable = false, length = 32)
    private String sourceSeverity;

    @Column(name = "score", nullable = false)
    private Integer score;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 32)
    private IncidentSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "classification", nullable = false, length = 32)
    private IncidentClassification classification;

    @Column(name = "classification_reason", nullable = false, length = 1000)
    private String classificationReason;

    @Column(name = "missing_data", nullable = false)
    private Boolean missingData = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private IncidentStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "conclusion", nullable = false, length = 32)
    private IncidentConclusion conclusion;

    @Column(name = "assignee_user_id", length = 64)
    private String assigneeUserId;

    @Column(name = "manual_investigate_override", nullable = false)
    private Boolean manualInvestigateOverride = false;

    @Column(name = "alert_count", nullable = false)
    private Integer alertCount = 0;

    @Column(name = "distinct_rule_count", nullable = false)
    private Integer distinctRuleCount = 0;

    @Column(name = "first_seen", nullable = false)
    @UtcDateTime
    private LocalDateTime firstSeen;

    @Column(name = "last_seen", nullable = false)
    @UtcDateTime
    private LocalDateTime lastSeen;

    @Column(name = "updated_at", nullable = false)
    @UtcDateTime
    private LocalDateTime updatedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    @Column(name="response_verified_at")
    private LocalDateTime responseVerifiedAt;
    @Column(name="recovery_verified_at")
    private LocalDateTime recoveryVerifiedAt;
    @Column(name="response_verification_version")
    private Long responseVerificationVersion;
    public LocalDateTime getResponseVerifiedAt(){return responseVerifiedAt;}
    public void setResponseVerifiedAt(LocalDateTime value){responseVerifiedAt=value;}
    public LocalDateTime getRecoveryVerifiedAt(){return recoveryVerifiedAt;}
    public void setRecoveryVerifiedAt(LocalDateTime value){recoveryVerifiedAt=value;}
    public Long getResponseVerificationVersion(){return responseVerificationVersion;}
    public void setResponseVerificationVersion(Long value){responseVerificationVersion=value;}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getGroupingKey() { return groupingKey; }
    public void setGroupingKey(String groupingKey) { this.groupingKey = groupingKey; }
    public String getServiceId() { return serviceId; }
    public void setServiceId(String serviceId) { this.serviceId = serviceId; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public IncidentQueueTier getQueueTier() { return queueTier; }
    public void setQueueTier(IncidentQueueTier queueTier) { this.queueTier = queueTier; }
    public IncidentOrigin getOrigin() { return origin; }
    public void setOrigin(IncidentOrigin origin) { this.origin = origin; }
    public IncidentNature getNature() { return nature; }
    public void setNature(IncidentNature nature) { this.nature = nature == null ? IncidentNature.UNKNOWN : nature; }
    public String getTargetUserId() { return targetUserId; }
    public void setTargetUserId(String targetUserId) { this.targetUserId = targetUserId; }
    public String getDetectorModelVersion() { return detectorModelVersion; }
    public void setDetectorModelVersion(String detectorModelVersion) { this.detectorModelVersion = detectorModelVersion; }
    public LocalDateTime getBucketStart() { return bucketStart; }
    public void setBucketStart(LocalDateTime bucketStart) { this.bucketStart = bucketStart; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getSourceSeverity() { return sourceSeverity; }
    public void setSourceSeverity(String sourceSeverity) { this.sourceSeverity = sourceSeverity; }
    public Integer getScore() { return score; }
    public void setScore(Integer score) { this.score = score; }
    public IncidentSeverity getSeverity() { return severity; }
    public void setSeverity(IncidentSeverity severity) { this.severity = severity; }
    public IncidentClassification getClassification() { return classification; }
    public void setClassification(IncidentClassification classification) { this.classification = classification; }
    public String getClassificationReason() { return classificationReason; }
    public void setClassificationReason(String classificationReason) { this.classificationReason = classificationReason; }
    public Boolean getMissingData() { return missingData; }
    public void setMissingData(Boolean missingData) { this.missingData = missingData; }
    public IncidentStatus getStatus() { return status; }
    public void setStatus(IncidentStatus status) { this.status = status; }
    public IncidentConclusion getConclusion() { return conclusion; }
    public void setConclusion(IncidentConclusion conclusion) { this.conclusion = conclusion; }
    public String getAssigneeUserId() { return assigneeUserId; }
    public void setAssigneeUserId(String assigneeUserId) { this.assigneeUserId = assigneeUserId; }
    public Boolean getManualInvestigateOverride() { return manualInvestigateOverride; }
    public void setManualInvestigateOverride(Boolean value) { this.manualInvestigateOverride = value; }
    public Integer getAlertCount() { return alertCount; }
    public void setAlertCount(Integer alertCount) { this.alertCount = alertCount; }
    public Integer getDistinctRuleCount() { return distinctRuleCount; }
    public void setDistinctRuleCount(Integer distinctRuleCount) { this.distinctRuleCount = distinctRuleCount; }
    public LocalDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(LocalDateTime firstSeen) { this.firstSeen = firstSeen; }
    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    public Long getVersion() { return version; }
    public void setVersion(Long version) { this.version = version; }
}
