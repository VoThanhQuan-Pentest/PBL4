package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Rebuilds touched windows from source events, so retries and late events do not double-count. */
@Component
public class AccountBehaviorAggregationWorker {
    private static final Logger LOGGER = LoggerFactory.getLogger(AccountBehaviorAggregationWorker.class);
    private static final int WINDOW_MINUTES = 15;
    private final SiemSecurityEventRepository events;
    private final SiemAccountBehaviorWindowRepository windows;
    private final UserRepository users;
    private final boolean enabled;
    private final ZoneId behaviorZone;
    private final AtomicBoolean running = new AtomicBoolean();

    @org.springframework.beans.factory.annotation.Autowired
    public AccountBehaviorAggregationWorker(SiemSecurityEventRepository events,
                                            SiemAccountBehaviorWindowRepository windows,
                                            UserRepository users,
                                            @Value("${siem.ueba.enabled:false}") boolean enabled,
                                            @Value("${siem.ueba.behavior-zone:Asia/Ho_Chi_Minh}") String zone,
                                            @Value("${siem.postlogin.enabled:false}") boolean postloginEnabled) {
        this(events, windows, users, enabled || postloginEnabled, zone);
    }

    public AccountBehaviorAggregationWorker(SiemSecurityEventRepository events,
                                            SiemAccountBehaviorWindowRepository windows,
                                            UserRepository users,
                                            @Value("${siem.ueba.enabled:false}") boolean enabled,
                                            @Value("${siem.ueba.behavior-zone:Asia/Ho_Chi_Minh}") String zone) {
        this.events = events;
        this.windows = windows;
        this.users = users;
        this.enabled = enabled;
        this.behaviorZone = ZoneId.of(zone);
    }

    @Scheduled(initialDelayString = "${siem.ueba.initial-delay-ms:20000}",
            fixedDelayString = "${siem.ueba.aggregate-interval-ms:30000}")
    @Transactional
    public void aggregatePending() {
        if (!enabled || !running.compareAndSet(false, true)) return;
        try {
            aggregatePendingAt(LocalDateTime.now(ZoneOffset.UTC));
        } catch (RuntimeException exception) {
            LOGGER.warn("UEBA behavior aggregation failed exceptionType={}",
                    exception.getClass().getSimpleName());
            throw exception;
        } finally {
            running.set(false);
        }
    }

    /** Deterministic entry point for backfill and tests; the scheduled caller already has a transaction. */
    @Transactional
    public void aggregatePendingAt(LocalDateTime now) {
        // A window is finalized only after its end plus a two-minute grace period.
        LocalDateTime cutoff = windowStart(now.minusMinutes(2));
        List<SiemSecurityEvent> pending = events
                .findByAggregatedAtIsNullAndEventTimestampBeforeOrderByEventTimestampAsc(
                        cutoff, PageRequest.of(0, 200));
        if (pending.isEmpty()) return;
        Set<WindowKey> touched = new LinkedHashSet<>();
        Map<String, Boolean> customerLookup = new HashMap<>();
        for (SiemSecurityEvent event : pending) {
            String accountId = event.getActorUserId() != null
                    ? event.getActorUserId() : event.getTargetUserId();
            if (!"AUTH_INVESTIGATION".equals(event.getEventType()) && accountId != null && event.getEventTimestamp() != null
                    && customerLookup.computeIfAbsent(accountId, this::isActiveCustomer)) {
                touched.add(new WindowKey(accountId, windowStart(event.getEventTimestamp())));
            }
        }
        for (WindowKey key : touched) rebuild(key, now);
        // Events without a customer actor are intentionally acknowledged, not retried forever.
        pending.forEach(event -> event.setAggregatedAt(now));
        events.saveAll(pending);
    }

    private boolean isActiveCustomer(String accountId) {
        User user = users.findActiveById(accountId).orElse(null);
        return user != null && "ROLE_CUSTOMER".equals(CurrentUserPrincipal.toAuthority(user.getRole()));
    }

    private void rebuild(WindowKey key, LocalDateTime now) {
        List<SiemSecurityEvent> source = new ArrayList<>();
        int page = 0;
        Page<SiemSecurityEvent> result;
        do {
            result = events.findAccountWindow(key.accountId(), key.start(),
                    key.start().plusMinutes(WINDOW_MINUTES), PageRequest.of(page++, 500));
            source.addAll(result.getContent());
        } while (result.hasNext());
        if (source.isEmpty()) return;

        List<SiemAccountBehaviorWindow> priorWindows = historyFor(key.accountId(), key.start());
        AccountBaselinePolicy.Snapshot snapshot = AccountBaselinePolicy.summarize(priorWindows, key.start(), behaviorZone);
        AccountBehaviorFeatures.Vector vector = AccountBehaviorFeatures.fromEvents(source, snapshot.features(), behaviorZone);
        SiemAccountBehaviorWindow window = windows.findByAccountIdAndWindowStartAndFeatureSchemaVersion(
                key.accountId(), key.start(), AccountBehaviorFeatures.SCHEMA_VERSION).orElseGet(() -> {
                    SiemAccountBehaviorWindow created = new SiemAccountBehaviorWindow();
                    created.setId("ueba-window-" + UUID.randomUUID());
                    created.setAccountId(key.accountId());
                    created.setWindowStart(key.start());
                    created.setWindowEnd(key.start().plusMinutes(WINDOW_MINUTES));
                    created.setCreatedAt(now);
                    return created;
                });
        String representativeIp = source.stream().map(SiemSecurityEvent::getSourceIp)
                .filter(ip -> ip != null && !ip.isBlank()).reduce((previous, current) -> current).orElse(null);
        String representativeUa = source.stream().map(SiemSecurityEvent::getUserAgentFamily)
                .filter(ua -> ua != null && !ua.isBlank()).reduce((previous, current) -> current).orElse(null);
        window.replaceFeatures(vector, source.size(), snapshot.features().established(), representativeIp,
                representativeUa, sourceLabel(source), now);
        AccountBehaviorFeatures.Vector personal = AccountBehaviorFeatures.withPersonalFeatures(vector, snapshot);
        window.replacePersonalFeatures(personal, now);
        var contextual = ContextualBehaviorFeatures.fromEvents(personal, snapshot, source);
        window.replaceContextualFeatures(contextual, now);
        window.replaceSessionEndpointFeatures(SessionEndpointBehaviorFeatures.fromEvents(contextual,
                AccountBaselinePolicy.observedRequests(priorWindows, key.start()), key.start(), source), now);
        windows.save(window);
    }

    private String sourceLabel(List<SiemSecurityEvent> source) {
        Set<String> labels = new HashSet<>();
        source.forEach(event -> labels.add(event.getDemoLabel() == null ? "REAL" : event.getDemoLabel()));
        if (labels.size() > 1) return "MIXED";
        String only = labels.iterator().next();
        return Set.of("REAL", "NORMAL", "ABNORMAL").contains(only) ? only : "MIXED";
    }

    private List<SiemAccountBehaviorWindow> historyFor(String accountId, LocalDateTime start) {
        LocalDateTime from = start.minusDays(AccountBaselinePolicy.HISTORY_DAYS);
        List<SiemAccountBehaviorWindow> history = windows
                .findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThan(accountId, from, start);
        return history;
    }

    static LocalDateTime windowStart(LocalDateTime timestamp) {
        return timestamp.withMinute(timestamp.getMinute() / WINDOW_MINUTES * WINDOW_MINUTES)
                .withSecond(0).withNano(0);
    }

    private record WindowKey(String accountId, LocalDateTime start) { }
}
