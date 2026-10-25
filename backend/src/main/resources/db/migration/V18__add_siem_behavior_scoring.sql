ALTER TABLE siem_account_behavior_windows
    ADD COLUMN source_ip VARCHAR(64) NULL,
    ADD COLUMN score_status VARCHAR(24) NOT NULL DEFAULT 'PENDING',
    ADD COLUMN model_version VARCHAR(64) NULL,
    ADD COLUMN anomaly_percentile DOUBLE NULL,
    ADD COLUMN risk_score INT NULL,
    ADD COLUMN risk_reasons VARCHAR(2000) NULL,
    ADD COLUMN scored_at DATETIME(6) NULL,
    ADD INDEX idx_siem_behavior_scoring (score_status, window_start);
