UPDATE siem_ip_intelligence
SET data_provenance = 'UNAVAILABLE'
WHERE status IN ('NOT_CONFIGURED', 'RATE_LIMITED', 'ERROR')
  AND data_provenance = 'REAL';
