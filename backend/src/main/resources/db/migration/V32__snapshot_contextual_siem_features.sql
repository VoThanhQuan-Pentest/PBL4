ALTER TABLE siem_account_behavior_windows
    ADD COLUMN contextual_feature_schema_version INT NULL,
    ADD COLUMN contextual_feature_vector_json VARCHAR(4000) NULL;

-- No fabricated backfill: old rows keep NULL until rebuilt from actual source
-- events. Existing v1/v2 vectors, scores and active model records are retained.
