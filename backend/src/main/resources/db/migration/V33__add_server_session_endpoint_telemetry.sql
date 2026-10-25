-- Additive, nullable telemetry. Existing events retain NULL coverage; no rows are rewritten.
ALTER TABLE siem_security_events
    ADD COLUMN telemetry_contract_version INT NULL,
    ADD COLUMN endpoint_category VARCHAR(32) NULL,
    ADD COLUMN session_pseudonym VARCHAR(64) NULL,
    ADD COLUMN session_issued_at DATETIME(6) NULL;
