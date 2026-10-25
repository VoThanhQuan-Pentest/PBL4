-- Additive PROJECT_LIMITED policy. No model activation or customer mutation.
CREATE TABLE siem_postlogin_policy (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    mode VARCHAR(24) NOT NULL,
    account_allowlist_json TEXT NOT NULL,
    model_version VARCHAR(64) NOT NULL,
    model_manifest_sha256 CHAR(64) NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB;

INSERT INTO siem_postlogin_policy
    (id,mode,account_allowlist_json,model_version,updated_at)
VALUES ('postlogin-project-limited-v1','OFF','[]','postlogin-legacy-f3-project-v1',UTC_TIMESTAMP(6));

ALTER TABLE sensitive_action_confirmations
    ADD COLUMN observed_attempt_id VARCHAR(64) NULL;

CREATE TABLE siem_postlogin_decisions (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    request_id CHAR(36) NOT NULL,
    challenge_id CHAR(36) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    session_pseudonym CHAR(64) NOT NULL,
    auth_version BIGINT NOT NULL,
    operation VARCHAR(32) NOT NULL,
    snapshot_id VARCHAR(128) NOT NULL,
    mode VARCHAR(24) NOT NULL,
    decision VARCHAR(24) NOT NULL,
    context_class VARCHAR(40) NULL,
    raw_score DOUBLE NULL,
    normal_percentile DOUBLE NULL,
    model_version VARCHAR(64) NOT NULL,
    model_sha256 CHAR(64) NULL,
    model_manifest_sha256 CHAR(64) NULL,
    policy_id VARCHAR(64) NOT NULL,
    policy_version BIGINT NOT NULL,
    reasons_json TEXT NOT NULL,
    ip_evidence_json TEXT NOT NULL,
    feature_snapshot_json TEXT NOT NULL,
    baseline_established BOOLEAN NOT NULL,
    trusted_window_count INT NOT NULL,
    hold_key CHAR(64) NOT NULL,
    hold_expires_at DATETIME(6) NULL,
    outcome VARCHAR(32) NOT NULL,
    incident_id VARCHAR(64) NULL,
    as_of DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_postlogin_request UNIQUE (user_id,session_pseudonym,challenge_id,request_id),
    INDEX idx_postlogin_user_time (user_id,created_at),
    INDEX idx_postlogin_otp_failures (user_id,session_pseudonym,operation,policy_version,mode,outcome,created_at),
    INDEX idx_postlogin_incident (incident_id,created_at)
) ENGINE=InnoDB;

CREATE TABLE siem_postlogin_holds (
    hold_key CHAR(64) NOT NULL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    session_pseudonym CHAR(64) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    policy_id VARCHAR(64) NOT NULL,
    policy_version BIGINT NOT NULL,
    decision_id VARCHAR(64) NOT NULL,
    starts_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    released_at DATETIME(6) NULL,
    released_by VARCHAR(64) NULL,
    release_reason VARCHAR(1000) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    INDEX idx_postlogin_hold_expiry (expires_at,released_at)
) ENGINE=InnoDB;

CREATE TABLE siem_postlogin_reviews (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL,
    actor_user_id VARCHAR(64) NOT NULL,
    verdict VARCHAR(24) NOT NULL,
    reason VARCHAR(1000) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    INDEX idx_postlogin_review_decision (decision_id,created_at)
) ENGINE=InnoDB;
