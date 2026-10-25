ALTER TABLE siem_ueba_model_jobs
    ADD COLUMN feature_schema_version INT NOT NULL DEFAULT 1,
    ADD COLUMN recipe_id VARCHAR(96) NOT NULL DEFAULT 'legacy-v1',
    ADD COLUMN dataset_id VARCHAR(64) NULL,
    ADD COLUMN dataset_manifest_sha256 VARCHAR(64) NULL,
    ADD COLUMN model_sha256 VARCHAR(64) NULL,
    ADD COLUMN evaluation_worker_job_id VARCHAR(64) NULL,
    ADD COLUMN evaluation_dataset_id VARCHAR(64) NULL,
    ADD COLUMN evaluation_dataset_sha256 VARCHAR(64) NULL,
    ADD COLUMN evaluation_status VARCHAR(24) NOT NULL DEFAULT 'NOT_RUN',
    ADD COLUMN quality_gate VARCHAR(24) NOT NULL DEFAULT 'NOT_RUN',
    ADD COLUMN evaluation_summary_json TEXT NULL;

-- Previously approved models can be restored by Admin, without pretending they
-- passed the new gate. New fitting jobs cannot receive this grandfathered state.
UPDATE siem_ueba_model_jobs
SET quality_gate = 'LEGACY_RESTORE'
WHERE activated_at IS NOT NULL AND status IN ('ACTIVE', 'RETIRED');
