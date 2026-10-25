package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.SensitiveActionConfirmation;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.ops.PostLoginFeatureExport;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.service.SensitiveActionConfirmationService.Actor;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/** Reuses the frozen numeric representation, at PRE_EXECUTION before any current outcome. */
@Service
public class PostloginSnapshotService {
    private final SiemSecurityEventRepository events;
    private final SiemAccountBehaviorWindowRepository windows;
    public PostloginSnapshotService(SiemSecurityEventRepository events, SiemAccountBehaviorWindowRepository windows) {
        this.events = events; this.windows = windows;
    }
    public record Snapshot(Map<String, Object> packet, boolean covered, boolean ready, int trusted,
                           int requests, int serverErrors, boolean sameSourceScan) { }

    public Snapshot build(Actor actor, SensitiveActionConfirmation action, String sourceIp, LocalDateTime at) {
        var empty = new Snapshot(Map.of(), false, false, 0, 0, 0, false);
        if (action.getObservedAttemptId() == null || actor.session() == null) return empty;
        var original = events.findById(action.getObservedAttemptId()).orElse(null);
        if (original == null || !actor.userId().equals(original.getActorUserId())
                || !action.getOperation().equals(original.getAction())
                || !actor.session().sessionPseudonym().equals(original.getSessionPseudonym())
                || !actor.session().sessionIssuedAt().equals(original.getSessionIssuedAt())
                || !Integer.valueOf(4).equals(original.getTelemetryContractVersion())
                || !"SENSITIVE_ACTION_ATTEMPT".equals(original.getEventType())
                || !"ATTEMPT".equals(original.getOutcome()) || original.getEventTimestamp().isAfter(at)) return empty;
        var page = events.findAccountWindow(actor.userId(), at.minusMinutes(15), at, PageRequest.of(0, 10001));
        if (page.getTotalElements() > 10000) return empty; // Never claim truncated coverage.
        List<SiemSecurityEvent> context = new ArrayList<>(page.getContent().stream()
                .filter(e -> !original.getId().equals(e.getId())).toList());
        // A login can precede the 15-minute activity prefix; obtain it using the exact server session.
        events.findSessionLogin(actor.userId(), actor.session().sessionPseudonym(), at.minusDays(1), at,
                PageRequest.of(0, 1)).stream().filter(e -> context.stream().noneMatch(c -> c.getId().equals(e.getId())))
                .forEach(context::add);
        if (context.size() > 10000) return empty;
        LocalDateTime start = at.withMinute(at.getMinute() / 15 * 15).withSecond(0).withNano(0);
        var historyPage = windows.findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThanOrderByWindowStartDesc(
                actor.userId(), start.minusDays(14), start, PageRequest.of(0, 4 * 96));
        Map<LocalDateTime, SiemAccountBehaviorWindow> unique = new TreeMap<>(Comparator.reverseOrder());
        for (var w : historyPage.getContent()) {
            if (w.getWindowEnd().isAfter(start)) continue;
            unique.merge(w.getWindowStart(), w, (a,b) -> a.getFeatureSchemaVersion() >= b.getFeatureSchemaVersion() ? a : b);
        }
        // The fixed rolling exporter accepts at most 96 closed windows. Do not widen the frozen recipe.
        var history = unique.values().stream().limit(96).toList();
        var target = new SiemSecurityEvent();
        target.setId("postlogin-" + UUID.randomUUID()); target.setActorUserId(actor.userId());
        target.setTargetUserId(actor.userId()); target.setEventType("SENSITIVE_ACTION_ATTEMPT");
        target.setAction(action.getOperation()); target.setOutcome("ATTEMPT"); target.setEventTimestamp(at);
        target.setTelemetryContractVersion(4); target.setSessionPseudonym(actor.session().sessionPseudonym());
        target.setSessionIssuedAt(actor.session().sessionIssuedAt());
        var features = PostLoginFeatureExport.fromObservedRisk(target, context, history);
        var names = new ArrayList<>(AccountBehaviorFeatures.names(4));
        names.addAll(PostLoginBehaviorFeatures.NAMES); names.addAll(PostLoginRiskContextFeatures.NAMES);
        Map<String, Object> packet = Map.of("snapshot_id", target.getId(), "evaluation_unit", "SENSITIVE_ACTION_ATTEMPT",
                "feature_schema_version", 6, "feature_names", names, "features", features.values(),
                "as_of", at.toInstant(ZoneOffset.UTC).toString(),
                "baseline_established", features.observed().baselineEstablished(),
                "trusted_window_count", features.observed().trustedWindowCount());
        var sameSource = context.stream().filter(e -> "HTTP_REQUEST".equals(e.getEventType())
                && actor.userId().equals(e.getActorUserId()) && sourceIp != null && sourceIp.equals(e.getSourceIp())
                && e.getEventTimestamp().isAfter(at.minusMinutes(15))).toList();
        long categories = sameSource.stream().map(SiemSecurityEvent::getEndpointCategory)
                .filter(Objects::nonNull).filter(s -> !s.isBlank()).distinct().count();
        long errors = sameSource.stream().filter(e -> e.getHttpStatus() != null && e.getHttpStatus() >= 400
                && e.getHttpStatus() < 500).count();
        boolean scan = sameSource.size() >= 50 && categories >= 7 && errors >= .45 * sameSource.size();
        return new Snapshot(packet, true, features.observed().baselineEstablished(), features.observed().trustedWindowCount(),
                features.rollingFeatures().get(0).intValue(), features.rollingFeatures().get(3).intValue(), scan);
    }
}
