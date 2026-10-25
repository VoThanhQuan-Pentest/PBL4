CREATE TABLE siem_attack_signatures (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    version BIGINT NOT NULL DEFAULT 0,
    kind VARCHAR(32) NOT NULL,
    http_method VARCHAR(8) NULL,
    path_prefix VARCHAR(160) NULL,
    match_value VARCHAR(160) NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    action VARCHAR(16) NOT NULL,
    source_incident_id VARCHAR(64) NULL,
    created_by_user_id VARCHAR(64) NOT NULL,
    approved_by_user_id VARCHAR(64) NULL,
    tested_definition_hash CHAR(64) NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    approved_at DATETIME(6) NULL,
    INDEX idx_signature_status_updated (status, updated_at),
    INDEX idx_signature_incident (source_incident_id)
) ENGINE=InnoDB;

CREATE TABLE siem_signature_test_cases (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    signature_id VARCHAR(64) NOT NULL,
    http_method VARCHAR(8) NOT NULL,
    request_path VARCHAR(255) NOT NULL,
    request_body_sha256 CHAR(64) NULL,
    expected_match BOOLEAN NOT NULL,
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT fk_signature_test_signature FOREIGN KEY (signature_id)
        REFERENCES siem_attack_signatures (id),
    INDEX idx_signature_test_signature (signature_id)
) ENGINE=InnoDB;

CREATE TABLE siem_prevention_policies (
    version BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    checksum CHAR(64) NOT NULL,
    policy_json TEXT NOT NULL,
    published_at DATETIME(6) NOT NULL,
    acknowledged_at DATETIME(6) NULL,
    INDEX idx_prevention_policy_checksum (checksum),
    CONSTRAINT ck_prevention_policy_json CHECK (JSON_VALID(policy_json))
) ENGINE=InnoDB;

CREATE TABLE siem_prevention_policy_lock (
    id TINYINT NOT NULL PRIMARY KEY
) ENGINE=InnoDB;
INSERT INTO siem_prevention_policy_lock (id) VALUES (1);

CREATE TABLE siem_ip_blocks (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    source_type VARCHAR(24) NOT NULL,
    incident_id VARCHAR(64) NULL,
    created_by_user_id VARCHAR(64) NULL,
    revoked_by_user_id VARCHAR(64) NULL,
    started_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    INDEX idx_ip_block_lookup (ip_address, expires_at),
    INDEX idx_ip_block_active (revoked_at, expires_at)
) ENGINE=InnoDB;

CREATE TABLE siem_ip_intelligence (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL,
    country_code VARCHAR(8) NULL,
    asn VARCHAR(32) NULL,
    as_name VARCHAR(160) NULL,
    anonymous_flag BOOLEAN NULL,
    hosting_flag BOOLEAN NULL,
    abuse_score INT NULL,
    total_reports INT NULL,
    distinct_reporters INT NULL,
    observed_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    UNIQUE KEY uk_ip_intelligence_provider (ip_address, provider),
    INDEX idx_ip_intelligence_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE siem_ip_lookup_requests (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(80) NOT NULL,
    requested_by_user_id VARCHAR(64) NULL,
    status VARCHAR(20) NOT NULL,
    requested_at DATETIME(6) NOT NULL,
    completed_at DATETIME(6) NULL,
    INDEX idx_ip_lookup_pending (status, requested_at),
    INDEX idx_ip_lookup_ip_time (ip_address, requested_at)
) ENGINE=InnoDB;

CREATE TABLE siem_ip_provider_attempts (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    provider VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL,
    attempted_at DATETIME(6) NOT NULL,
    INDEX idx_ip_provider_daily (provider, attempted_at)
) ENGINE=InnoDB;

CREATE TABLE siem_prevention_events (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    trace_id VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    rule_id VARCHAR(64) NULL,
    policy_version BIGINT NULL,
    action VARCHAR(20) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    processed_at DATETIME(6) NULL,
    UNIQUE KEY uk_prevention_event_trace_type (trace_id, event_type, rule_id),
    INDEX idx_prevention_event_ip_time (ip_address, occurred_at)
) ENGINE=InnoDB;

CREATE INDEX idx_siem_event_auth_source_time
    ON siem_security_events (event_type, outcome, event_timestamp, source_ip);
