ALTER TABLE siem_prevention_events
    ADD COLUMN signal_count INT NOT NULL DEFAULT 1;
