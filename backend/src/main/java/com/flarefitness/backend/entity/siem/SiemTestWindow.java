package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_test_windows")
public class SiemTestWindow extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "name", nullable = false, length = 150)
    private String name;
    @Column(name = "source_ip", length = 64)
    private String sourceIp;
    @Column(name = "service_id", length = 128)
    private String serviceId;
    @Column(name = "starts_at", nullable = false)
    @UtcDateTime
    private LocalDateTime startsAt;
    @Column(name = "ends_at", nullable = false)
    @UtcDateTime
    private LocalDateTime endsAt;
    @Column(name = "active", nullable = false)
    private Boolean active = true;
    @Column(name = "created_by_user_id", nullable = false, length = 64)
    private String createdByUserId;
    @Column(name = "updated_at", nullable = false)
    @UtcDateTime
    private LocalDateTime updatedAt;
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getServiceId() { return serviceId; }
    public void setServiceId(String serviceId) { this.serviceId = serviceId; }
    public LocalDateTime getStartsAt() { return startsAt; }
    public void setStartsAt(LocalDateTime startsAt) { this.startsAt = startsAt; }
    public LocalDateTime getEndsAt() { return endsAt; }
    public void setEndsAt(LocalDateTime endsAt) { this.endsAt = endsAt; }
    public Boolean getActive() { return active; }
    public void setActive(Boolean active) { this.active = active; }
    public String getCreatedByUserId() { return createdByUserId; }
    public void setCreatedByUserId(String value) { this.createdByUserId = value; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    public Long getVersion() { return version; }
    public void setVersion(Long version) { this.version = version; }
}
