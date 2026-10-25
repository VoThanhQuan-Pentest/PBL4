ALTER TABLE siem_ueba_model_jobs
    ADD COLUMN activation_worker_job_id VARCHAR(32) NULL,
    ADD COLUMN activation_status VARCHAR(24) NOT NULL DEFAULT 'NOT_RUN',
    ADD COLUMN activation_requested_by_user_id VARCHAR(64) NULL;
CREATE INDEX ix_ueba_activation_jobs ON siem_ueba_model_jobs (activation_status, updated_at);
