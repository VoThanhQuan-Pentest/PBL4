ALTER TABLE siem_ueba_model_jobs
    ADD COLUMN data_provenance VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN';
