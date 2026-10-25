CREATE TABLE siem_incidents (
    id VARCHAR(64) NOT NULL,
    grouping_key VARCHAR(255) NOT NULL,
    service_id VARCHAR(128) NULL,
    rule_id VARCHAR(128) NULL,
    source_ip VARCHAR(64) NULL,
    bucket_start DATETIME(6) NOT NULL,
    title VARCHAR(255) NOT NULL,
    source_severity VARCHAR(32) NOT NULL,
    score INT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    classification VARCHAR(32) NOT NULL,
    classification_reason VARCHAR(1000) NOT NULL,
    missing_data BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL,
    conclusion VARCHAR(32) NOT NULL,
    assignee_user_id VARCHAR(64) NULL,
    manual_investigate_override BOOLEAN NOT NULL DEFAULT FALSE,
    alert_count INT NOT NULL DEFAULT 0,
    distinct_rule_count INT NOT NULL DEFAULT 0,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uk_siem_incident_grouping_key UNIQUE (grouping_key),
    INDEX idx_siem_incident_status_updated (status, updated_at),
    INDEX idx_siem_incident_source_time (source_ip, last_seen),
    INDEX idx_siem_incident_severity_time (severity, last_seen)
) ENGINE=InnoDB;

CREATE TABLE siem_alert_refs (
    id VARCHAR(64) NOT NULL,
    elastic_alert_id VARCHAR(255) NOT NULL,
    elastic_index VARCHAR(255) NOT NULL,
    incident_id VARCHAR(64) NOT NULL,
    rule_id VARCHAR(128) NULL,
    service_id VARCHAR(128) NULL,
    source_ip VARCHAR(64) NULL,
    source_severity VARCHAR(32) NULL,
    event_timestamp DATETIME(6) NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_siem_alert_elastic_id UNIQUE (elastic_alert_id),
    CONSTRAINT fk_siem_alert_incident FOREIGN KEY (incident_id)
        REFERENCES siem_incidents (id) ON DELETE CASCADE,
    INDEX idx_siem_alert_incident_time (incident_id, event_timestamp),
    INDEX idx_siem_alert_source_time (source_ip, event_timestamp)
) ENGINE=InnoDB;

CREATE TABLE siem_incident_notes (
    id VARCHAR(64) NOT NULL,
    incident_id VARCHAR(64) NOT NULL,
    author_user_id VARCHAR(64) NOT NULL,
    content VARCHAR(2000) NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_siem_note_incident FOREIGN KEY (incident_id)
        REFERENCES siem_incidents (id) ON DELETE CASCADE,
    INDEX idx_siem_note_incident_time (incident_id, ngay_tao)
) ENGINE=InnoDB;

CREATE TABLE siem_incident_history (
    id VARCHAR(64) NOT NULL,
    incident_id VARCHAR(64) NOT NULL,
    actor_user_id VARCHAR(64) NULL,
    action VARCHAR(64) NOT NULL,
    previous_value VARCHAR(1000) NULL,
    new_value VARCHAR(1000) NULL,
    detail VARCHAR(2000) NULL,
    ngay_tao DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT fk_siem_history_incident FOREIGN KEY (incident_id)
        REFERENCES siem_incidents (id) ON DELETE CASCADE,
    INDEX idx_siem_history_incident_time (incident_id, ngay_tao),
    INDEX idx_siem_history_time (ngay_tao)
) ENGINE=InnoDB;

CREATE TABLE siem_test_windows (
    id VARCHAR(64) NOT NULL,
    name VARCHAR(150) NOT NULL,
    source_ip VARCHAR(64) NULL,
    service_id VARCHAR(128) NULL,
    starts_at DATETIME(6) NOT NULL,
    ends_at DATETIME(6) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by_user_id VARCHAR(64) NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    INDEX idx_siem_test_window_active_time (active, starts_at, ends_at)
) ENGINE=InnoDB;

CREATE TABLE siem_ingestion_checkpoint (
    id VARCHAR(64) NOT NULL,
    stream_name VARCHAR(100) NOT NULL,
    last_event_timestamp DATETIME(6) NULL,
    last_sort_value VARCHAR(512) NULL,
    last_success_at DATETIME(6) NULL,
    last_error_at DATETIME(6) NULL,
    last_error VARCHAR(1000) NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uk_siem_checkpoint_stream UNIQUE (stream_name)
) ENGINE=InnoDB;
