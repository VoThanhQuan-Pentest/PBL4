ALTER TABLE siem_incidents
    ADD COLUMN queue_tier VARCHAR(8) NOT NULL DEFAULT 'L1',
    ADD COLUMN origin VARCHAR(16) NOT NULL DEFAULT 'ELASTIC',
    ADD COLUMN target_user_id VARCHAR(64) NULL,
    ADD INDEX idx_siem_incident_tier_status (queue_tier, status, last_seen),
    ADD INDEX idx_siem_incident_target_time (target_user_id, last_seen);

ALTER TABLE tbl_nguoi_dung
    ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 0;
