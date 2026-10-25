package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "siem_incident_notes")
public class SiemIncidentNote extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "incident_id", nullable = false, length = 64)
    private String incidentId;
    @Column(name = "author_user_id", nullable = false, length = 64)
    private String authorUserId;
    @Column(name = "content", nullable = false, length = 2000)
    private String content;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getAuthorUserId() { return authorUserId; }
    public void setAuthorUserId(String authorUserId) { this.authorUserId = authorUserId; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}
