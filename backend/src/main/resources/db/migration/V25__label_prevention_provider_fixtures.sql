ALTER TABLE siem_ip_intelligence
    ADD COLUMN data_provenance VARCHAR(16) NOT NULL DEFAULT 'REAL';

ALTER TABLE siem_attack_signatures
    ADD UNIQUE KEY uk_signature_source_incident (source_incident_id);
