package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "siem_incident_history")
public class SiemIncidentHistory extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "incident_id", nullable = false, length = 64)
    private String incidentId;
    @Column(name = "actor_user_id", length = 64)
    private String actorUserId;
    @Column(name = "action", nullable = false, length = 64)
    private String action;
    @Column(name = "previous_value", length = 1000)
    private String previousValue;
    @Column(name = "new_value", length = 1000)
    private String newValue;
    @Column(name = "detail", length = 2000)
    private String detail;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getActorUserId() { return actorUserId; }
    public void setActorUserId(String actorUserId) { this.actorUserId = actorUserId; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getPreviousValue() { return previousValue; }
    public void setPreviousValue(String previousValue) { this.previousValue = previousValue; }
    public String getNewValue() { return newValue; }
    public void setNewValue(String newValue) { this.newValue = newValue; }
    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
}
