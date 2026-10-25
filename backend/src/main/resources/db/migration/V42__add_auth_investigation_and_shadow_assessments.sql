-- Additive investigation metadata. Existing authentication, model policy and signature ledger are unchanged.
ALTER TABLE siem_security_events
    ADD COLUMN auth_request_id CHAR(36) NULL,
    ADD COLUMN execution_request_id CHAR(36) NULL,
    ADD COLUMN auth_target_fingerprint CHAR(64) NULL,
    ADD COLUMN fingerprint_key_id VARCHAR(16) NULL,
    ADD COLUMN denial_reason VARCHAR(48) NULL,
    ADD COLUMN challenge_reference VARCHAR(64) NULL,
    ADD COLUMN revocation_reference VARCHAR(128) NULL,
    ADD UNIQUE KEY uk_security_auth_request (auth_request_id,event_type,action),
    ADD INDEX idx_security_auth_source (source_ip,event_timestamp),
    ADD INDEX idx_security_auth_target (auth_target_fingerprint,event_timestamp);

CREATE TABLE siem_auth_correlation_policy (
    id TINYINT NOT NULL PRIMARY KEY,
    mode VARCHAR(16) NOT NULL,
    definition_version VARCHAR(40) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT ck_auth_correlation_mode CHECK (mode IN ('OFF','OBSERVE','ALERT'))
) ENGINE=InnoDB;
INSERT INTO siem_auth_correlation_policy (id,mode,definition_version,updated_at)
    VALUES (1,'OFF','AUTH_INVESTIGATION_V1',UTC_TIMESTAMP(6));

CREATE TABLE siem_auth_policy_requests (
    request_id VARCHAR(64) NOT NULL PRIMARY KEY,
    actor_user_id VARCHAR(64) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    reason VARCHAR(1000) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    resulting_version BIGINT NOT NULL,
    created_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE siem_auth_processed_events (
    event_id VARCHAR(64) NOT NULL PRIMARY KEY,
    processed_at DATETIME(6) NOT NULL,
    INDEX idx_auth_processed_age (processed_at)
) ENGINE=InnoDB;
CREATE TABLE siem_auth_findings (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    grouping_hash CHAR(64) NOT NULL,
    rule_id VARCHAR(48) NOT NULL,
    policy_version BIGINT NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    incident_id VARCHAR(64) NULL,
    severity VARCHAR(16) NOT NULL,
    evidence_count INT NOT NULL,
    INDEX idx_auth_finding_group (grouping_hash,last_seen),
    INDEX idx_auth_finding_incident (incident_id)
) ENGINE=InnoDB;
CREATE TABLE siem_auth_finding_events (
    finding_id VARCHAR(64) NOT NULL,
    event_id VARCHAR(64) NOT NULL,
    request_id CHAR(36) NOT NULL,
    PRIMARY KEY (finding_id,event_id),
    CONSTRAINT fk_auth_finding_event FOREIGN KEY (finding_id) REFERENCES siem_auth_findings(id)
) ENGINE=InnoDB;
CREATE TABLE siem_shadow_assessments (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    snapshot_id VARCHAR(128) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    incident_id VARCHAR(64) NULL,
    model_manifest_sha256 CHAR(64) NOT NULL,
    feature_schema_version INT NOT NULL,
    status VARCHAR(24) NOT NULL,
    recommendation VARCHAR(24) NULL,
    context_class VARCHAR(48) NULL,
    raw_score DOUBLE NULL,
    features_json MEDIUMTEXT NOT NULL,
    coverage_json TEXT NOT NULL,
    result_json TEXT NULL,
    as_of DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT uk_shadow_snapshot_model UNIQUE(snapshot_id,model_manifest_sha256),
    CONSTRAINT ck_shadow_schema CHECK(feature_schema_version=7),
    CONSTRAINT ck_shadow_recommendation CHECK(recommendation IS NULL OR recommendation IN ('ROUTINE','REVIEW','OPS','UNDETERMINED')),
    INDEX idx_shadow_status (status,created_at),
    INDEX idx_shadow_incident (incident_id,as_of)
) ENGINE=InnoDB;

-- Evidence of explicit logout/revoke only; this registry never authorizes or rejects a request.
CREATE TABLE siem_session_revocation_evidence (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    session_reference CHAR(64) NULL,
    fingerprint_key_id VARCHAR(16) NULL,
    revoked_before DATETIME(6) NULL,
    reason VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_session_revoke_reference (user_id,session_reference,fingerprint_key_id),
    INDEX idx_session_revoke_time (user_id,revoked_before,expires_at)
) ENGINE=InnoDB;

ALTER TABLE siem_postlogin_decisions ADD COLUMN execution_event_id VARCHAR(64) NULL;
