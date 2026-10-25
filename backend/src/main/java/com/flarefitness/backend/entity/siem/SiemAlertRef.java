package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_alert_refs")
public class SiemAlertRef extends BaseEntity {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "elastic_alert_id", nullable = false, unique = true, length = 255)
    private String elasticAlertId;
    @Column(name = "elastic_index", nullable = false, length = 255)
    private String elasticIndex;
    @Column(name = "incident_id", nullable = false, length = 64)
    private String incidentId;
    @Column(name = "rule_id", length = 128)
    private String ruleId;
    @Column(name = "service_id", length = 128)
    private String serviceId;
    @Column(name = "source_ip", length = 64)
    private String sourceIp;
    @Column(name = "source_severity", length = 32)
    private String sourceSeverity;
    @Column(name = "event_timestamp", nullable = false)
    @UtcDateTime
    private LocalDateTime eventTimestamp;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getElasticAlertId() { return elasticAlertId; }
    public void setElasticAlertId(String elasticAlertId) { this.elasticAlertId = elasticAlertId; }
    public String getElasticIndex() { return elasticIndex; }
    public void setElasticIndex(String elasticIndex) { this.elasticIndex = elasticIndex; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    public String getServiceId() { return serviceId; }
    public void setServiceId(String serviceId) { this.serviceId = serviceId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getSourceSeverity() { return sourceSeverity; }
    public void setSourceSeverity(String sourceSeverity) { this.sourceSeverity = sourceSeverity; }
    public LocalDateTime getEventTimestamp() { return eventTimestamp; }
    public void setEventTimestamp(LocalDateTime eventTimestamp) { this.eventTimestamp = eventTimestamp; }
}
