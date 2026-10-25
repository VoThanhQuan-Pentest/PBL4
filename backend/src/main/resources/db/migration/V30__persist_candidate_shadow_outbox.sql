-- Shadow bookkeeping is separate from assessments, incidents and response actions.
CREATE INDEX ix_behavior_shadow_closed ON siem_account_behavior_windows
    (personal_feature_schema_version, window_end, id);

CREATE TABLE siem_ueba_shadow_runs (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    model_version VARCHAR(64) NOT NULL,
    requested_by_user_id VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL,
    state_json TEXT NULL,
    last_error_type VARCHAR(64) NULL,
    lease_until DATETIME(6) NULL,
    ngay_tao DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    INDEX ix_shadow_runs_status (status, updated_at),
    INDEX ix_shadow_runs_model (model_version, ngay_tao)
) ENGINE=InnoDB;

CREATE TABLE siem_ueba_shadow_deliveries (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    run_id VARCHAR(32) NOT NULL,
    window_id VARCHAR(64) NOT NULL,
    payload_json TEXT NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ngay_tao DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    UNIQUE KEY ux_shadow_delivery_window (run_id, window_id),
    INDEX ix_shadow_delivery_pending (run_id, acknowledged, ngay_tao),
    CONSTRAINT fk_shadow_delivery_run FOREIGN KEY (run_id) REFERENCES siem_ueba_shadow_runs(id)
) ENGINE=InnoDB;
