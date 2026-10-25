package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_ueba_shadow_runs")
public class SiemUebaShadowRun extends BaseEntity {
    @Id @Column(length = 32, nullable = false) private String id;
    @Column(name = "model_version", length = 64, nullable = false) private String modelVersion;
    @Column(name = "requested_by_user_id", length = 64, nullable = false) private String requestedByUserId;
    @Column(length = 24, nullable = false) private String status;
    @Column(name = "state_json", columnDefinition = "TEXT") private String stateJson;
    @Column(name = "last_error_type", length = 64) private String lastErrorType;
    @Column(name = "lease_until") @UtcDateTime private LocalDateTime leaseUntil;
    @Column(name = "updated_at", nullable = false) @UtcDateTime private LocalDateTime updatedAt;
    @Version @Column(nullable = false) private Long version;

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String value) { modelVersion = value; }
    public String getRequestedByUserId() { return requestedByUserId; }
    public void setRequestedByUserId(String value) { requestedByUserId = value; }
    public String getStatus() { return status; }
    public void setStatus(String value) { status = value; }
    public String getStateJson() { return stateJson; }
    public void setStateJson(String value) { stateJson = value; }
    public String getLastErrorType() { return lastErrorType; }
    public void setLastErrorType(String value) { lastErrorType = value; }
    public LocalDateTime getLeaseUntil() { return leaseUntil; }
    public void setLeaseUntil(LocalDateTime value) { leaseUntil = value; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime value) { updatedAt = value; }
}
