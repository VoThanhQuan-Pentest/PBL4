package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentNature;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Idempotent projection from allowlisted Elasticsearch gateway events. */
@Service
public class SiemPreventionEventIngestionService {
    private final JdbcTemplate jdbc;
    private final SiemIncidentRepository incidents;
    private final SiemIncidentHistoryRepository history;
    private final SiemPreventionService prevention;

    public SiemPreventionEventIngestionService(JdbcTemplate jdbc,
            SiemIncidentRepository incidents, SiemIncidentHistoryRepository history,
            SiemPreventionService prevention) {
        this.jdbc = jdbc;
        this.incidents = incidents;
        this.history = history;
        this.prevention = prevention;
    }

    @Transactional(readOnly = true)
    public LocalDateTime checkpoint() {
        LocalDateTime latest = jdbc.query("""
                SELECT MAX(occurred_at) FROM siem_prevention_events
                """, row -> row.next() && row.getTimestamp(1) != null
                ? row.getTimestamp(1).toLocalDateTime() : null);
        return latest == null ? LocalDateTime.now(ZoneOffset.UTC).minusDays(7)
                : latest.minusMinutes(2);
    }

    @Transactional
    public int ingest(List<SiemElasticGateway.PreventionEvent> events) {
        jdbc.update("UPDATE siem_prevention_policy_lock SET id=id WHERE id=1");
        int accepted = 0;
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        for (var event : events) {
            if (event.id() == null || !event.id().matches("[a-f0-9]{32}")
                    || event.traceId() == null || !event.traceId().matches("[a-f0-9]{32}")
                    || event.sourceIp() == null || event.sourceIp().length() > 45
                    || event.occurredAt() == null || event.occurredAt().isAfter(now.plusMinutes(2))) {
                continue;
            }
            int inserted = jdbc.update("""
                    INSERT IGNORE INTO siem_prevention_events
                        (id,trace_id,ip_address,event_type,rule_id,policy_version,
                         action,occurred_at,processed_at,signal_count)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """, event.id(), event.traceId(), event.sourceIp(),
                    event.type(), event.ruleId(), event.policyVersion(),
                    event.action(), event.occurredAt(), now,
                    Math.max(1, Math.min(event.count(), 1000000)));
            if (inserted == 0) continue;
            accepted++;
            if (event.occurredAt().isBefore(now.minusMinutes(
                    "AUTO_BLOCK".equals(event.type()) ? 15 : 5))) continue;
            if ("SIGNATURE_MATCH".equals(event.type()) && "DENY".equals(event.action())) {
                SiemIncident incident = upsert(event, now, signatureTitle(event.ruleId()),
                        "FLARE_PREVENTION_SIGNATURE", 85, IncidentSeverity.URGENT);
                if (prevention.qualifySignatureEpisode(event,incident.getId())) continue;
                Long matches = jdbc.queryForObject("""
                        SELECT COUNT(*) FROM siem_prevention_events
                        WHERE ip_address=? AND event_type='SIGNATURE_MATCH'
                          AND occurred_at>=?
                        """, Long.class, event.sourceIp(), now.minusMinutes(1));
                if (matches != null && matches >= 3) {
                    prevention.requestLookupForSignal(event.sourceIp(), "REPEATED_SIGNATURE");
                    prevention.blockForSignal(event.sourceIp(), "SIGNATURE",
                            "Three or more approved signature matches in one minute",
                            incident.getId(), 15);
                }
            } else if ("AUTO_BLOCK".equals(event.type())) {
                SiemIncident incident = upsert(event, now, "Repeated approved signature matches",
                        "FLARE_PREVENTION_SIGNATURE", 90, IncidentSeverity.URGENT);
                prevention.requestLookupForSignal(event.sourceIp(), "REPEATED_SIGNATURE");
                int remaining = Math.max(1, 15 - (int) java.time.Duration.between(
                        event.occurredAt(), now).toMinutes());
                prevention.blockForSignal(event.sourceIp(), "SIGNATURE",
                        "Three or more approved signature matches in one minute",
                        incident.getId(), remaining);
            } else if ("RATE_LIMIT".equals(event.type())) {
                Long current = jdbc.queryForObject("""
                        SELECT COALESCE(SUM(signal_count),0) FROM siem_prevention_events
                        WHERE ip_address=? AND event_type='RATE_LIMIT'
                          AND occurred_at>=? AND occurred_at<?
                        """, Long.class, event.sourceIp(), now.minusMinutes(1), now);
                Long previous = jdbc.queryForObject("""
                        SELECT COALESCE(SUM(signal_count),0) FROM siem_prevention_events
                        WHERE ip_address=? AND event_type='RATE_LIMIT'
                          AND occurred_at>=? AND occurred_at<?
                        """, Long.class, event.sourceIp(), now.minusMinutes(2), now.minusMinutes(1));
                if (current != null && current >= 100 && previous != null && previous >= 100) {
                    SiemIncident incident = upsert(event, now, "Repeated HTTP flood",
                            "FLARE_PREVENTION_HTTP_FLOOD", 80, IncidentSeverity.HIGH);
                    prevention.requestLookupForSignal(event.sourceIp(), "REPEATED_HTTP_FLOOD");
                    prevention.blockForSignal(event.sourceIp(), "HTTP_FLOOD",
                            "At least 100 throttled requests in two consecutive minutes",
                            incident.getId(), 10);
                }
            }
        }
        return accepted;
    }

    private String signatureTitle(String signatureId) {
        if (signatureId == null || signatureId.isBlank()) return "Confirmed attack signature blocked";
        List<String> kinds = jdbc.query("SELECT kind FROM siem_attack_signatures WHERE id=?",
                (row, ignored) -> row.getString(1), signatureId);
        if (kinds.isEmpty()) return "Confirmed attack signature blocked";
        return switch (kinds.getFirst()) {
            case "SQLI" -> "Confirmed SQLi attack signature blocked";
            case "XSS" -> "Confirmed XSS attack signature blocked";
            case "TRAVERSAL" -> "Confirmed path traversal signature blocked";
            default -> "Confirmed " + kinds.getFirst() + " attack signature blocked";
        };
    }

    @Transactional
    public void ingestScanCandidate(SiemElasticGateway.IpScanCandidate candidate,
                                    LocalDateTime observedAt) {
        if (candidate == null || candidate.sourceIp() == null
                || candidate.sourceIp().length() > 45
                || candidate.distinctPaths() < 20 || candidate.errors() < 10) return;
        LocalDateTime minute = observedAt.truncatedTo(ChronoUnit.MINUTES);
        String marker = sha256(candidate.sourceIp() + ":" + minute).substring(0, 32);
        int added = jdbc.update("""
                INSERT IGNORE INTO siem_prevention_events
                    (id,trace_id,ip_address,event_type,rule_id,policy_version,
                     action,occurred_at,processed_at,signal_count)
                VALUES (?,?,?,'SCAN_SIGNAL','FLARE_PREVENTION_ENDPOINT_SCAN',NULL,
                        'OBSERVE',?,?,?)
                """, marker, marker, candidate.sourceIp(), minute, observedAt,
                Math.max(candidate.distinctPaths(), candidate.errors()));
        if (added == 0) return;
        SiemElasticGateway.PreventionEvent signal = new SiemElasticGateway.PreventionEvent(
                marker, marker, candidate.sourceIp(), "SCAN_SIGNAL",
                "FLARE_PREVENTION_ENDPOINT_SCAN", 0, "OBSERVE", 1, observedAt);
        SiemIncident incident = upsert(signal, observedAt, "Possible endpoint enumeration",
                "FLARE_PREVENTION_ENDPOINT_SCAN", 70, IncidentSeverity.HIGH);
        prevention.requestLookupForSignal(candidate.sourceIp(), "ENDPOINT_ENUMERATION");
        Long previous = jdbc.queryForObject("""
                SELECT COUNT(*) FROM siem_prevention_events
                WHERE ip_address=? AND event_type='SCAN_SIGNAL'
                  AND occurred_at>=? AND occurred_at<?
                """, Long.class, candidate.sourceIp(), minute.minusMinutes(1), minute);
        if (previous != null && previous > 0) {
            prevention.blockForSignal(candidate.sourceIp(), "SCAN",
                    "Endpoint enumeration repeated in separate minute windows",
                    incident.getId(), 10);
        }
    }

    private static String sha256(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private SiemIncident upsert(SiemElasticGateway.PreventionEvent event, LocalDateTime now,
                                String title, String ruleId, int score, IncidentSeverity severity) {
        String key = "prevention:" + ruleId + ":" + event.sourceIp() + ":"
                + event.occurredAt().truncatedTo(ChronoUnit.HOURS);
        SiemIncident existing = incidents.findByGroupingKey(key).orElse(null);
        if (existing != null) {
            existing.setNature(IncidentNatureClassifier.merge(existing.getNature(), IncidentNature.SECURITY_DETECTION));
            if (event.occurredAt().isAfter(existing.getLastSeen())) existing.setLastSeen(event.occurredAt());
            existing.setAlertCount(existing.getAlertCount() + 1);
            existing.setUpdatedAt(now);
            return incidents.save(existing);
        }
        SiemIncident created = new SiemIncident();
        created.setId("siem-incident-" + UUID.randomUUID());
        created.setGroupingKey(key);
        created.setServiceId("flare-web");
        created.setRuleId(ruleId);
        created.setSourceIp(event.sourceIp());
        created.setQueueTier(IncidentQueueTier.L1);
        created.setOrigin(IncidentOrigin.PREVENTION);
        created.setNature(IncidentNature.SECURITY_DETECTION);
        created.setBucketStart(event.occurredAt().truncatedTo(ChronoUnit.HOURS));
        created.setTitle(title);
        created.setSourceSeverity(severity == IncidentSeverity.URGENT ? "critical" : "high");
        created.setScore(score);
        created.setSeverity(severity);
        created.setClassification(IncidentClassification.INVESTIGATE);
        created.setClassificationReason("Gateway decision " + event.type()
                + (event.ruleId() == null ? "" : " by " + event.ruleId()));
        created.setMissingData(false);
        created.setStatus(IncidentStatus.NEW);
        created.setConclusion(IncidentConclusion.UNREVIEWED);
        created.setAssigneeUserId(null);
        created.setManualInvestigateOverride(false);
        created.setAlertCount(1);
        created.setDistinctRuleCount(1);
        created.setFirstSeen(event.occurredAt());
        created.setLastSeen(event.occurredAt());
        created.setCreatedAt(now);
        created.setUpdatedAt(now);
        incidents.saveAndFlush(created);
        SiemIncidentHistory detected = new SiemIncidentHistory();
        detected.setId("siem-history-" + UUID.randomUUID());
        detected.setIncidentId(created.getId());
        detected.setAction("PREVENTION_DETECTED");
        detected.setDetail("Gateway decision linked by trace ID; request payload was not retained.");
        detected.setCreatedAt(now);
        history.save(detected);
        return created;
    }
}
