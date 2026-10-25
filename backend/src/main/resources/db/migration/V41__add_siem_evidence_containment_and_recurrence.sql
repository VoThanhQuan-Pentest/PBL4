-- Additive upgrade; existing credentials, events, model artifacts and fixtures are untouched.
ALTER TABLE tbl_nguoi_dung
    ADD COLUMN soc_isolated BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN soc_isolated_until DATETIME(6) NULL;
ALTER TABLE siem_ip_blocks
    MODIFY expires_at DATETIME(6) NULL,
    ADD COLUMN duration_type VARCHAR(20) NOT NULL DEFAULT 'TEMPORARY',
    ADD COLUMN published_policy_version BIGINT NULL,
    ADD COLUMN revoke_policy_version BIGINT NULL,
    ADD COLUMN revoke_reason VARCHAR(500) NULL,
    ADD CONSTRAINT ck_ip_block_duration CHECK (
        (duration_type='TEMPORARY' AND expires_at IS NOT NULL) OR
        (duration_type='UNTIL_REVOKED' AND expires_at IS NULL));
CREATE TABLE siem_evidence_refs (
    incident_id VARCHAR(64) NOT NULL,
    elastic_index VARCHAR(255) NOT NULL,
    elastic_id VARCHAR(256) NOT NULL,
    trace_id VARCHAR(128) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (incident_id,elastic_index,elastic_id),
    CONSTRAINT fk_evidence_incident FOREIGN KEY (incident_id) REFERENCES siem_incidents(id)
) ENGINE=InnoDB;
CREATE TABLE siem_containment_actions (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    incident_id VARCHAR(64) NOT NULL,
    target_user_id VARCHAR(64) NOT NULL,
    actor_user_id VARCHAR(64) NOT NULL,
    reason VARCHAR(2000) NOT NULL,
    duration_type VARCHAR(20) NOT NULL,
    expires_at DATETIME(6) NULL,
    status VARCHAR(20) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    released_at DATETIME(6) NULL,
    release_request_id VARCHAR(64) NULL UNIQUE,
    release_reason VARCHAR(2000) NULL,
    release_actor_user_id VARCHAR(64) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    INDEX idx_containment_target (target_user_id,status,expires_at),
    CONSTRAINT fk_containment_incident FOREIGN KEY (incident_id) REFERENCES siem_incidents(id)
) ENGINE=InnoDB;
CREATE TABLE siem_signature_requests (
    ip_address VARCHAR(45) NOT NULL,
    request_id VARCHAR(128) NOT NULL,
    source_event_id VARCHAR(64) NOT NULL,
    signature_id VARCHAR(64) NOT NULL,
    signature_version BIGINT NOT NULL,
    definition_hash CHAR(64) NOT NULL,
    policy_version BIGINT NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    episode_id VARCHAR(64) NULL,
    PRIMARY KEY (ip_address,request_id),
    INDEX idx_signature_request_window (ip_address,occurred_at)
) ENGINE=InnoDB;
CREATE TABLE siem_recurrence_episodes (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    block_id VARCHAR(64) NOT NULL UNIQUE,
    incident_id VARCHAR(64) NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    policy_version BIGINT NOT NULL,
    strike_number INT NOT NULL,
    provenance VARCHAR(40) NOT NULL,
    invalidated_at DATETIME(6) NULL,
    invalidated_by_user_id VARCHAR(64) NULL,
    invalidation_reason VARCHAR(500) NULL,
    INDEX idx_recurrence_window (ip_address,last_seen,invalidated_at)
) ENGINE=InnoDB;
CREATE TABLE siem_response_requests (
    request_id VARCHAR(64) NOT NULL PRIMARY KEY,
    actor_user_id VARCHAR(64) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    created_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;

ALTER TABLE siem_security_events ADD COLUMN actor_username VARCHAR(100) NULL;

ALTER TABLE siem_incidents
    ADD COLUMN response_verified_at DATETIME(6) NULL,
    ADD COLUMN recovery_verified_at DATETIME(6) NULL,
    ADD COLUMN response_verification_version BIGINT NULL;
