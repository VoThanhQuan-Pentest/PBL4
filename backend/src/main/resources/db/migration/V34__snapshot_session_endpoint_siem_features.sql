ALTER TABLE siem_account_behavior_windows
    ADD COLUMN session_endpoint_feature_schema_version INT NULL,
    ADD COLUMN session_endpoint_feature_vector_json VARCHAR(6000) NULL;

-- No backfill from labels or legacy route guesses. Schema 4 is rebuilt only
-- from actual source events; existing schema 1-3 snapshots/scores remain intact.
