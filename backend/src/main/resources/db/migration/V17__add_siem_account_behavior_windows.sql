ALTER TABLE siem_security_events
    ADD COLUMN aggregated_at DATETIME(6) NULL,
    ADD INDEX idx_siem_event_aggregation (aggregated_at, event_timestamp);

CREATE TABLE siem_account_behavior_windows (
    id VARCHAR(64) NOT NULL,
    account_id VARCHAR(64) NOT NULL,
    window_start DATETIME(6) NOT NULL,
    window_end DATETIME(6) NOT NULL,
    feature_schema_version INT NOT NULL,
    event_count INT NOT NULL,
    request_count INT NOT NULL,
    http_4xx_count INT NOT NULL,
    http_5xx_count INT NOT NULL,
    failed_login_count INT NOT NULL,
    successful_login_count INT NOT NULL,
    sensitive_action_count INT NOT NULL,
    distinct_route_group_count INT NOT NULL,
    distinct_source_ip_count INT NOT NULL,
    new_ip_flag BOOLEAN NOT NULL,
    new_user_agent_flag BOOLEAN NOT NULL,
    unusual_hour_flag BOOLEAN NOT NULL,
    baseline_established BOOLEAN NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT uk_siem_behavior_account_window UNIQUE (account_id, window_start, feature_schema_version),
    INDEX idx_siem_behavior_window_time (window_start),
    INDEX idx_siem_behavior_account_time (account_id, window_start)
) ENGINE=InnoDB;
