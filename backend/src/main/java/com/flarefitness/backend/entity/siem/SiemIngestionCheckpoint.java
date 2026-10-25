package com.flarefitness.backend.entity.siem;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_ingestion_checkpoint")
public class SiemIngestionCheckpoint {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "stream_name", nullable = false, unique = true, length = 100)
    private String streamName;
    @Column(name = "last_event_timestamp")
    @UtcDateTime
    private LocalDateTime lastEventTimestamp;
    @Column(name = "last_sort_value", length = 512)
    private String lastSortValue;
    @Column(name = "last_success_at")
    @UtcDateTime
    private LocalDateTime lastSuccessAt;
    @Column(name = "last_error_at")
    @UtcDateTime
    private LocalDateTime lastErrorAt;
    @Column(name = "last_error", length = 1000)
    private String lastError;
    @Column(name = "updated_at", nullable = false)
    @UtcDateTime
    private LocalDateTime updatedAt;
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getStreamName() { return streamName; }
    public void setStreamName(String streamName) { this.streamName = streamName; }
    public LocalDateTime getLastEventTimestamp() { return lastEventTimestamp; }
    public void setLastEventTimestamp(LocalDateTime value) { this.lastEventTimestamp = value; }
    public String getLastSortValue() { return lastSortValue; }
    public void setLastSortValue(String lastSortValue) { this.lastSortValue = lastSortValue; }
    public LocalDateTime getLastSuccessAt() { return lastSuccessAt; }
    public void setLastSuccessAt(LocalDateTime lastSuccessAt) { this.lastSuccessAt = lastSuccessAt; }
    public LocalDateTime getLastErrorAt() { return lastErrorAt; }
    public void setLastErrorAt(LocalDateTime lastErrorAt) { this.lastErrorAt = lastErrorAt; }
    public String getLastError() { return lastError; }
    public void setLastError(String lastError) { this.lastError = lastError; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    public Long getVersion() { return version; }
}
