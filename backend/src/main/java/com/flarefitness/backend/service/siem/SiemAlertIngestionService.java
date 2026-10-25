package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.SiemAlertRef;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import com.flarefitness.backend.entity.siem.SiemIngestionCheckpoint;
import com.flarefitness.backend.entity.siem.SiemTestWindow;
import com.flarefitness.backend.repository.siem.SiemAlertRefRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemIngestionCheckpointRepository;
import com.flarefitness.backend.repository.siem.SiemTestWindowRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SiemAlertIngestionService {
    private final SiemIncidentRepository incidentRepository;
    private final SiemAlertRefRepository alertRefRepository;
    private final SiemIncidentHistoryRepository historyRepository;
    private final SiemTestWindowRepository testWindowRepository;
    private final SiemIngestionCheckpointRepository checkpointRepository;
    private final SiemClassificationEngine classificationEngine;

    public SiemAlertIngestionService(
            SiemIncidentRepository incidentRepository,
            SiemAlertRefRepository alertRefRepository,
            SiemIncidentHistoryRepository historyRepository,
            SiemTestWindowRepository testWindowRepository,
            SiemIngestionCheckpointRepository checkpointRepository,
            SiemClassificationEngine classificationEngine
    ) {
        this.incidentRepository = incidentRepository;
        this.alertRefRepository = alertRefRepository;
        this.historyRepository = historyRepository;
        this.testWindowRepository = testWindowRepository;
        this.checkpointRepository = checkpointRepository;
        this.classificationEngine = classificationEngine;
    }

    @Transactional
    public IngestionResult ingest(List<SiemElasticGateway.ElasticAlert> alerts) {
        int created = 0;
        int duplicates = 0;
        LocalDateTime latest = null;
        for (SiemElasticGateway.ElasticAlert alert : alerts) {
            if (alertRefRepository.existsByElasticAlertId(alert.id())) {
                duplicates++;
                repairIncompleteIncident(alert);
                continue;
            }
            LocalDateTime eventTime = parseTimestamp(alert.timestamp());
            latest = latest == null || eventTime.isAfter(latest) ? eventTime : latest;
            String sourceIp = alert.sourceIps().size() == 1 ? alert.sourceIps().getFirst() : null;
            boolean missingData = blank(alert.timestamp()) || blank(alert.ruleId())
                    || blank(alert.serviceId()) || sourceIp == null;
            String groupingKey = groupingKey(alert, sourceIp, eventTime, missingData || alert.sourceIps().size() != 1);
            var existingIncident = incidentRepository.findByGroupingKey(groupingKey);
            SiemIncident incident = existingIncident
                    .orElseGet(() -> newIncident(alert, sourceIp, eventTime, groupingKey, missingData));

            if (incident.getId() == null) {
                throw new IllegalStateException("Incident ID must be assigned before alert reference");
            }
            if (existingIncident.isEmpty()) {
                incidentRepository.saveAndFlush(incident);
                created++;
            }

            SiemAlertRef ref = new SiemAlertRef();
            ref.setId("siem-alert-" + UUID.randomUUID());
            ref.setElasticAlertId(alert.id());
            ref.setElasticIndex(alert.index());
            ref.setIncidentId(incident.getId());
            ref.setRuleId(alert.ruleId());
            ref.setServiceId(alert.serviceId());
            ref.setSourceIp(sourceIp);
            ref.setSourceSeverity(normalizeSeverity(alert.severity()));
            ref.setEventTimestamp(eventTime);
            ref.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
            alertRefRepository.saveAndFlush(ref);

            refreshIncident(incident, alert, sourceIp, eventTime, missingData);
        }
        return new IngestionResult(created, duplicates, latest);
    }

    @Transactional(readOnly = true)
    public LocalDateTime checkpointTime() {
        return checkpointRepository.findByStreamName(SiemStatusService.ALERT_STREAM)
                .map(SiemIngestionCheckpoint::getLastEventTimestamp)
                .orElse(null);
    }

    @Transactional
    public void checkpointSuccess(LocalDateTime lastEventTimestamp, String lastSortValue) {
        SiemIngestionCheckpoint checkpoint = checkpoint();
        if (lastEventTimestamp != null && (checkpoint.getLastEventTimestamp() == null
                || lastEventTimestamp.isAfter(checkpoint.getLastEventTimestamp()))) {
            checkpoint.setLastEventTimestamp(lastEventTimestamp);
        }
        checkpoint.setLastSortValue(lastSortValue);
        checkpoint.setLastSuccessAt(LocalDateTime.now(ZoneOffset.UTC));
        checkpoint.setLastError(null);
        checkpoint.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        checkpointRepository.save(checkpoint);
    }

    @Transactional
    public void checkpointFailure(String message) {
        SiemIngestionCheckpoint checkpoint = checkpoint();
        checkpoint.setLastErrorAt(LocalDateTime.now(ZoneOffset.UTC));
        checkpoint.setLastError(message == null ? "Unknown error" : message.substring(0, Math.min(1000, message.length())));
        checkpoint.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        checkpointRepository.save(checkpoint);
    }

    private void refreshIncident(
            SiemIncident incident,
            SiemElasticGateway.ElasticAlert alert,
            String sourceIp,
            LocalDateTime eventTime,
            boolean missingData
    ) {
        incident.setFirstSeen(incident.getFirstSeen().isBefore(eventTime) ? incident.getFirstSeen() : eventTime);
        incident.setLastSeen(incident.getLastSeen().isAfter(eventTime) ? incident.getLastSeen() : eventTime);
        incident.setSourceSeverity(higherSeverity(incident.getSourceSeverity(), alert.severity()));
        incident.setNature(IncidentNatureClassifier.merge(incident.getNature(),
                IncidentNatureClassifier.fromElasticRule(alert.ruleId())));
        incident.setAlertCount((int) alertRefRepository.countByIncidentId(incident.getId()));

        Set<String> distinctRules = new HashSet<>();
        if (sourceIp != null && !blank(alert.serviceId())) {
            alertRefRepository.findBySourceIpAndServiceIdAndEventTimestampBetween(
                            sourceIp, alert.serviceId(), eventTime.minusMinutes(10), eventTime.plusMinutes(10))
                    .stream().map(SiemAlertRef::getRuleId).filter(value -> !blank(value)).forEach(distinctRules::add);
        } else if (!blank(alert.ruleId())) {
            distinctRules.add(alert.ruleId());
        }
        incident.setDistinctRuleCount(distinctRules.size());
        boolean inTestWindow = inTestWindow(sourceIp, alert.serviceId(), eventTime);
        var result = classificationEngine.classify(new SiemClassificationEngine.ClassificationInput(
                incident.getSourceSeverity(),
                distinctRules.size(),
                incident.getAlertCount(),
                inTestWindow,
                missingData || Boolean.TRUE.equals(incident.getMissingData()),
                Boolean.TRUE.equals(incident.getManualInvestigateOverride())));
        incident.setScore(result.score());
        incident.setSeverity(result.severity());
        incident.setClassification(result.classification());
        incident.setClassificationReason(String.join("; ", result.reasons()));
        incident.setMissingData(result.missingData());
        incident.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));

        if (incident.getStatus() == IncidentStatus.CLOSED) {
            incident.setStatus(IncidentStatus.NEW);
            incident.setConclusion(IncidentConclusion.UNREVIEWED);
            incident.setAssigneeUserId(null);
            historyRepository.save(history(incident.getId(), "NEW_ALERT_REOPENED",
                    "CLOSED", "NEW", "A new source alert reopened this incident"));
        }
        incidentRepository.save(incident);
    }

    private SiemIncident newIncident(
            SiemElasticGateway.ElasticAlert alert,
            String sourceIp,
            LocalDateTime eventTime,
            String groupingKey,
            boolean missingData
    ) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemIncident incident = new SiemIncident();
        incident.setId("siem-incident-" + UUID.randomUUID());
        incident.setGroupingKey(groupingKey);
        incident.setServiceId(alert.serviceId());
        incident.setRuleId(alert.ruleId());
        incident.setSourceIp(sourceIp);
        incident.setBucketStart(bucketStart(eventTime));
        incident.setTitle(safeTitle(alert.title()));
        incident.setNature(IncidentNatureClassifier.fromElasticRule(alert.ruleId()));
        incident.setSourceSeverity(normalizeSeverity(alert.severity()));
        incident.setScore(50);
        incident.setSeverity(com.flarefitness.backend.entity.siem.IncidentSeverity.MEDIUM);
        incident.setClassification(com.flarefitness.backend.entity.siem.IncidentClassification.INVESTIGATE);
        incident.setClassificationReason("Pending classification");
        incident.setMissingData(missingData);
        incident.setStatus(IncidentStatus.NEW);
        incident.setConclusion(IncidentConclusion.UNREVIEWED);
        incident.setManualInvestigateOverride(false);
        incident.setAlertCount(0);
        incident.setDistinctRuleCount(0);
        incident.setFirstSeen(eventTime);
        incident.setLastSeen(eventTime);
        incident.setCreatedAt(now);
        incident.setUpdatedAt(now);
        return incident;
    }

    private boolean inTestWindow(String sourceIp, String serviceId, LocalDateTime eventTime) {
        return testWindowRepository
                .findByActiveTrueAndStartsAtLessThanEqualAndEndsAtGreaterThanEqual(eventTime, eventTime)
                .stream()
                .anyMatch(window -> matches(window.getSourceIp(), sourceIp)
                        && matches(window.getServiceId(), serviceId));
    }

    private void repairIncompleteIncident(SiemElasticGateway.ElasticAlert alert) {
        SiemAlertRef ref = alertRefRepository.findByElasticAlertId(alert.id()).orElse(null);
        if (ref == null) return;
        SiemIncident incident = incidentRepository.findById(ref.getIncidentId()).orElse(null);
        if (incident == null || !Boolean.TRUE.equals(incident.getMissingData())) return;

        LocalDateTime eventTime = parseTimestamp(alert.timestamp());
        String sourceIp = alert.sourceIps().size() == 1 ? alert.sourceIps().getFirst() : null;
        boolean missingData = blank(alert.timestamp()) || blank(alert.ruleId())
                || blank(alert.serviceId()) || sourceIp == null;
        ref.setRuleId(alert.ruleId());
        ref.setServiceId(alert.serviceId());
        ref.setSourceIp(sourceIp);
        ref.setSourceSeverity(normalizeSeverity(alert.severity()));
        ref.setEventTimestamp(eventTime);
        alertRefRepository.saveAndFlush(ref);

        incident.setRuleId(alert.ruleId());
        incident.setServiceId(alert.serviceId());
        incident.setSourceIp(sourceIp);
        incident.setTitle(safeTitle(alert.title()));
        incident.setSourceSeverity(higherSeverity(incident.getSourceSeverity(), alert.severity()));
        incident.setMissingData(missingData);
        refreshIncident(incident, alert, sourceIp, eventTime, missingData);
    }

    private String safeTitle(String value) {
        String title = blank(value) ? "Security alert" : value.trim();
        return title.substring(0, Math.min(255, title.length()));
    }

    private boolean matches(String expected, String actual) {
        return expected == null || expected.isBlank() || expected.equals(actual);
    }

    private String groupingKey(
            SiemElasticGateway.ElasticAlert alert,
            String sourceIp,
            LocalDateTime eventTime,
            boolean separate
    ) {
        if (separate) return "alert:" + sha256(alert.id());
        String raw = alert.serviceId() + "|" + alert.ruleId() + "|" + sourceIp + "|" + bucketStart(eventTime);
        return "group:" + sha256(raw);
    }

    private String sha256(String raw) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private LocalDateTime bucketStart(LocalDateTime time) {
        LocalDateTime minute = time.truncatedTo(ChronoUnit.MINUTES);
        return minute.minusMinutes(minute.getMinute() % 5L);
    }

    private LocalDateTime parseTimestamp(String value) {
        try {
            return OffsetDateTime.parse(value).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();
        } catch (Exception exception) {
            return LocalDateTime.now(ZoneOffset.UTC);
        }
    }

    private String normalizeSeverity(String value) {
        String normalized = blank(value) ? "unknown" : value.trim().toLowerCase(Locale.ROOT);
        return Set.of("low", "medium", "high", "critical").contains(normalized) ? normalized : "unknown";
    }

    private String higherSeverity(String left, String right) {
        return List.of(left, normalizeSeverity(right)).stream()
                .filter(value -> value != null)
                .max(Comparator.comparingInt(this::severityRank)).orElse("unknown");
    }

    private int severityRank(String value) {
        return switch (normalizeSeverity(value)) {
            case "critical" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0;
        };
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private SiemIngestionCheckpoint checkpoint() {
        return checkpointRepository.findByStreamName(SiemStatusService.ALERT_STREAM).orElseGet(() -> {
            SiemIngestionCheckpoint value = new SiemIngestionCheckpoint();
            value.setId("siem-checkpoint-alerts");
            value.setStreamName(SiemStatusService.ALERT_STREAM);
            value.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
            return value;
        });
    }

    private SiemIncidentHistory history(String incidentId, String action,
                                        String previous, String next, String detail) {
        SiemIncidentHistory value = new SiemIncidentHistory();
        value.setId("siem-history-" + UUID.randomUUID());
        value.setIncidentId(incidentId);
        value.setAction(action);
        value.setPreviousValue(previous);
        value.setNewValue(next);
        value.setDetail(detail);
        value.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return value;
    }

    public record IngestionResult(int createdIncidents, int duplicateAlerts, LocalDateTime latestEventTime) {
    }
}
