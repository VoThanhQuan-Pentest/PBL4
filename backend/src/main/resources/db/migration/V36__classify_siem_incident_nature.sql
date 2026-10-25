ALTER TABLE siem_incidents
    ADD COLUMN incident_nature VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN' AFTER origin;
