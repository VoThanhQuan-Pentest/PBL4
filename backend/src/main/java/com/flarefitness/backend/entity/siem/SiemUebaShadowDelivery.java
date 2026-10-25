package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

/** Persisted before HTTP submission; retries use the same immutable numeric snapshot. */
@Entity
@Table(name = "siem_ueba_shadow_deliveries")
public class SiemUebaShadowDelivery extends BaseEntity {
    @Id @Column(length = 64, nullable = false) private String id;
    @Column(name = "run_id", length = 32, nullable = false) private String runId;
    @Column(name = "window_id", length = 64, nullable = false) private String windowId;
    @Column(name = "payload_json", columnDefinition = "TEXT", nullable = false) private String payloadJson;
    @Column(nullable = false) private boolean acknowledged;
    @Column(name = "updated_at", nullable = false) @UtcDateTime private LocalDateTime updatedAt;
    @Version @Column(nullable = false) private Long version;

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getRunId() { return runId; }
    public void setRunId(String value) { runId = value; }
    public String getWindowId() { return windowId; }
    public void setWindowId(String value) { windowId = value; }
    public String getPayloadJson() { return payloadJson; }
    public void setPayloadJson(String value) { payloadJson = value; }
    public boolean isAcknowledged() { return acknowledged; }
    public void setAcknowledged(boolean value) { acknowledged = value; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime value) { updatedAt = value; }
}
