ALTER TABLE siem_security_events
    ADD INDEX idx_siem_event_retention (event_timestamp, exported_at, aggregated_at);

ALTER TABLE siem_account_behavior_windows
    ADD INDEX idx_siem_behavior_retention (window_start, score_status);
