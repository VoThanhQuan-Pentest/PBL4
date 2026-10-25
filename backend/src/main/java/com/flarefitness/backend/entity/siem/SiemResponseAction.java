package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "siem_response_actions")
public class SiemResponseAction extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "request_id", nullable = false, unique = true, length = 64)
    private String requestId;
    @Column(name = "incident_id", nullable = false, length = 64)
    private String incidentId;
    @Column(name = "target_user_id", nullable = false, length = 64)
    private String targetUserId;
    @Column(name = "actor_user_id", nullable = false, length = 64)
    private String actorUserId;
    @Column(name = "action_type", nullable = false, length = 32)
    private String actionType;
    @Column(name = "reason", nullable = false, length = 2000)
    private String reason;
    @Column(name = "previous_auth_version", nullable = false)
    private Long previousAuthVersion;
    @Column(name = "new_auth_version", nullable = false)
    private Long newAuthVersion;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getTargetUserId() { return targetUserId; }
    public void setTargetUserId(String targetUserId) { this.targetUserId = targetUserId; }
    public String getActorUserId() { return actorUserId; }
    public void setActorUserId(String actorUserId) { this.actorUserId = actorUserId; }
    public String getActionType() { return actionType; }
    public void setActionType(String actionType) { this.actionType = actionType; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public Long getPreviousAuthVersion() { return previousAuthVersion; }
    public void setPreviousAuthVersion(Long value) { this.previousAuthVersion = value; }
    public Long getNewAuthVersion() { return newAuthVersion; }
    public void setNewAuthVersion(Long value) { this.newAuthVersion = value; }
}
