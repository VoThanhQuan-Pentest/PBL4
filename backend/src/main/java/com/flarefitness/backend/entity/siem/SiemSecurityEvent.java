package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_security_events")
public class SiemSecurityEvent extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "event_timestamp", nullable = false)
    @UtcDateTime
    private LocalDateTime eventTimestamp;
    @Column(name = "actor_user_id", length = 64)
    private String actorUserId;
    @Column(name = "target_user_id", length = 64)
    private String targetUserId;
    @Column(name = "source_ip", length = 64)
    private String sourceIp;
    @Column(name = "event_type", nullable = false, length = 48)
    private String eventType;
    @Column(name = "action", nullable = false, length = 80)
    private String action;
    @Column(name = "outcome", nullable = false, length = 16)
    private String outcome;
    @Column(name = "route_group", length = 64)
    private String routeGroup;
    @Column(name = "http_method", length = 8)
    private String httpMethod;
    @Column(name = "http_status")
    private Integer httpStatus;
    @Column(name = "user_agent_family", length = 32)
    private String userAgentFamily;
    @Column(name = "trace_id", length = 64)
    private String traceId;
    @Column(name = "exported_at")
    @UtcDateTime
    private LocalDateTime exportedAt;
    @Column(name = "aggregated_at")
    @UtcDateTime
    private LocalDateTime aggregatedAt;
    @Column(name = "demo_label", length = 16)
    private String demoLabel;
    @Column(name = "telemetry_contract_version")
    private Integer telemetryContractVersion;
    @Column(name = "endpoint_category", length = 32)
    private String endpointCategory;
    @Column(name = "session_pseudonym", length = 64)
    private String sessionPseudonym;
    @Column(name = "session_issued_at")
    @UtcDateTime
    private LocalDateTime sessionIssuedAt;

    @jakarta.persistence.Column(name="actor_username",length=100)
    private String actorUsername;
    public String getActorUsername() { return actorUsername; }
    public void setActorUsername(String value) { actorUsername=value; }

    @Column(name="auth_request_id",length=36)
    private String authRequestId;
    public String getAuthRequestId() {return authRequestId;}
    public void setAuthRequestId(String value) {authRequestId=value;}
    @Column(name="auth_target_fingerprint",length=64)
    private String authTargetFingerprint;
    public String getAuthTargetFingerprint() {return authTargetFingerprint;}
    public void setAuthTargetFingerprint(String value) {authTargetFingerprint=value;}
    @Column(name="fingerprint_key_id",length=16)
    private String fingerprintKeyId;
    public String getFingerprintKeyId() {return fingerprintKeyId;}
    public void setFingerprintKeyId(String value) {fingerprintKeyId=value;}
    @Column(name="denial_reason",length=48)
    private String denialReason;
    public String getDenialReason() {return denialReason;}
    public void setDenialReason(String value) {denialReason=value;}
    @Column(name="challenge_reference",length=64)
    private String challengeReference;
    public String getChallengeReference() {return challengeReference;}
    public void setChallengeReference(String value) {challengeReference=value;}
    @Column(name="revocation_reference",length=128)
    private String revocationReference;
    public String getRevocationReference() {return revocationReference;}
    public void setRevocationReference(String value) {revocationReference=value;}
    @Column(name="execution_request_id",length=36)
    private String executionRequestId;
    public String getExecutionRequestId(){return executionRequestId;}
    public void setExecutionRequestId(String value){executionRequestId=value;}
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public LocalDateTime getEventTimestamp() { return eventTimestamp; }
    public void setEventTimestamp(LocalDateTime value) { this.eventTimestamp = value; }
    public String getActorUserId() { return actorUserId; }
    public void setActorUserId(String value) { this.actorUserId = value; }
    public String getTargetUserId() { return targetUserId; }
    public void setTargetUserId(String value) { this.targetUserId = value; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String value) { this.sourceIp = value; }
    public String getEventType() { return eventType; }
    public void setEventType(String value) { this.eventType = value; }
    public String getAction() { return action; }
    public void setAction(String value) { this.action = value; }
    public String getOutcome() { return outcome; }
    public void setOutcome(String value) { this.outcome = value; }
    public String getRouteGroup() { return routeGroup; }
    public void setRouteGroup(String value) { this.routeGroup = value; }
    public String getHttpMethod() { return httpMethod; }
    public void setHttpMethod(String value) { this.httpMethod = value; }
    public Integer getHttpStatus() { return httpStatus; }
    public void setHttpStatus(Integer value) { this.httpStatus = value; }
    public String getUserAgentFamily() { return userAgentFamily; }
    public void setUserAgentFamily(String value) { this.userAgentFamily = value; }
    public String getTraceId() { return traceId; }
    public void setTraceId(String value) { this.traceId = value; }
    public LocalDateTime getExportedAt() { return exportedAt; }
    public void setExportedAt(LocalDateTime value) { this.exportedAt = value; }
    public LocalDateTime getAggregatedAt() { return aggregatedAt; }
    public void setAggregatedAt(LocalDateTime value) { this.aggregatedAt = value; }
    public String getDemoLabel() { return demoLabel; }
    public void setDemoLabel(String value) { demoLabel = value; }
    public Integer getTelemetryContractVersion() { return telemetryContractVersion; }
    public void setTelemetryContractVersion(Integer value) { telemetryContractVersion = value; }
    public String getEndpointCategory() { return endpointCategory; }
    public void setEndpointCategory(String value) { endpointCategory = value; }
    public String getSessionPseudonym() { return sessionPseudonym; }
    public void setSessionPseudonym(String value) { sessionPseudonym = value; }
    public LocalDateTime getSessionIssuedAt() { return sessionIssuedAt; }
    public void setSessionIssuedAt(LocalDateTime value) { sessionIssuedAt = value; }
}
