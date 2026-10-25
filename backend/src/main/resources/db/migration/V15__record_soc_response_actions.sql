CREATE TABLE siem_response_actions (
    id VARCHAR(64) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    incident_id VARCHAR(64) NOT NULL,
    target_user_id VARCHAR(64) COLLATE utf8mb4_unicode_ci NOT NULL,
    actor_user_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(32) NOT NULL,
    reason VARCHAR(2000) NOT NULL,
    previous_auth_version BIGINT NOT NULL,
    new_auth_version BIGINT NOT NULL,
    ngay_tao DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_siem_response_request UNIQUE (request_id),
    CONSTRAINT fk_siem_response_incident FOREIGN KEY (incident_id) REFERENCES siem_incidents (id),
    CONSTRAINT fk_siem_response_target FOREIGN KEY (target_user_id) REFERENCES tbl_nguoi_dung (id),
    INDEX idx_siem_response_target_time (target_user_id, ngay_tao)
) ENGINE=InnoDB;
