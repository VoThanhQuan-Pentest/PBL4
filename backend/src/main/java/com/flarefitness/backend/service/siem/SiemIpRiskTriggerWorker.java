package com.flarefitness.backend.service.siem;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Schedules external enrichment from server-authored events, never inline with login. */
@Component
public class SiemIpRiskTriggerWorker {
    private final JdbcTemplate jdbc;
    private final SiemPreventionService prevention;
    private final boolean enabled;

    public SiemIpRiskTriggerWorker(JdbcTemplate jdbc, SiemPreventionService prevention,
            @Value("${siem.prevention.enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.prevention = prevention;
        this.enabled = enabled;
    }

    @Scheduled(fixedDelayString = "${siem.prevention.trigger-interval-ms:10000}")
    public void scheduleSuspiciousIps() {
        if (!enabled) return;
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        List<String> failures = jdbc.query("""
                SELECT source_ip FROM siem_security_events
                WHERE event_type='AUTH' AND outcome='FAILURE'
                  AND event_timestamp>=? AND source_ip IS NOT NULL
                GROUP BY source_ip HAVING COUNT(*)>=5 LIMIT 100
                """, (row, ignored) -> row.getString(1), now.minusMinutes(5));
        failures.forEach(ip -> prevention.requestLookupForSignal(ip, "FAILED_LOGIN_BURST"));
        List<String> anomalous = jdbc.query("""
                SELECT DISTINCT source_ip FROM siem_incidents
                WHERE origin='UEBA' AND score>=60 AND last_seen>=?
                  AND source_ip IS NOT NULL LIMIT 100
                """, (row, ignored) -> row.getString(1), now.minusMinutes(20));
        anomalous.forEach(ip -> prevention.requestLookupForSignal(ip, "UEBA_ACCOUNT_ANOMALY"));
    }

    @Scheduled(fixedDelayString = "${siem.prevention.trigger-interval-ms:10000}")
    public void evaluateCorroboratedScans() {
        if (!enabled) return;
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        List<String> candidates = jdbc.query("""
                SELECT DISTINCT e.ip_address FROM siem_prevention_events e
                JOIN siem_ip_intelligence intel ON intel.ip_address=e.ip_address
                WHERE e.event_type='SCAN_SIGNAL' AND e.occurred_at>=?
                  AND intel.provider='ABUSEIPDB' AND intel.status='FRESH'
                  AND intel.data_provenance='REAL' AND intel.expires_at>?
                  AND intel.abuse_score>=80 AND intel.total_reports>=3
                  AND intel.distinct_reporters>=2 LIMIT 100
                """, (row, ignored) -> row.getString(1), now.minusMinutes(10), now);
        for (String ip : candidates) {
            List<String> incidents = jdbc.query("""
                    SELECT id FROM siem_incidents WHERE origin='PREVENTION'
                      AND rule_id='FLARE_PREVENTION_ENDPOINT_SCAN' AND source_ip=?
                    ORDER BY ngay_tao DESC LIMIT 1
                    """, (row, ignored) -> row.getString(1), ip);
            prevention.blockForSignal(ip, "SCAN",
                    "Endpoint scan corroborated by recent independent abuse reports",
                    incidents.isEmpty() ? null : incidents.getFirst(), 10);
        }
    }
}
