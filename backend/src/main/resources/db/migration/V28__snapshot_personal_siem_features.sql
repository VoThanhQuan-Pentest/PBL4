-- Preserve the original schema-v1 counts/window identity and all historical scores.
-- Personal vectors are separately versioned snapshots, never reconstructed from future history.
ALTER TABLE siem_account_behavior_windows
    ADD COLUMN personal_feature_schema_version INT NULL,
    ADD COLUMN personal_feature_vector_json VARCHAR(2000) NULL,
    ADD COLUMN scored_feature_schema_version INT NULL,
    ADD CONSTRAINT ck_siem_personal_vector_json
        CHECK (personal_feature_vector_json IS NULL OR JSON_VALID(personal_feature_vector_json)),
    ADD CONSTRAINT ck_siem_personal_vector_schema
        CHECK ((personal_feature_vector_json IS NULL AND personal_feature_schema_version IS NULL)
            OR (personal_feature_vector_json IS NOT NULL AND personal_feature_schema_version = 2));
