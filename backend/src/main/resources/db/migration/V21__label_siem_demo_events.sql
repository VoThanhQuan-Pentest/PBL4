ALTER TABLE siem_security_events
    ADD COLUMN demo_label VARCHAR(16) NULL;

ALTER TABLE siem_account_behavior_windows
    ADD COLUMN demo_label VARCHAR(16) NOT NULL DEFAULT 'REAL';
