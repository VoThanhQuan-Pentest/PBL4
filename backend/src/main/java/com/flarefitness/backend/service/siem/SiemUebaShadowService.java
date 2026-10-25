package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.SiemUebaShadowDelivery;
import com.flarefitness.backend.entity.siem.SiemUebaShadowRun;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.repository.siem.SiemUebaShadowDeliveryRepository;
import com.flarefitness.backend.repository.siem.SiemUebaShadowRunRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/** Isolated candidate observation: no incident, provider or response-action dependencies. */
@Service
public class SiemUebaShadowService {
    private static final Set<String> LIVE = Set.of("STARTING", "QUEUED", "RUNNING");
    private static final List<String> BINDINGS = List.of("model_version", "model_sha256", "calibration_sha256",
            "policy_sha256", "dataset_sha256", "feature_schema_version", "started_at_utc", "boot_sha256", "clock_provenance");
    private final SiemUebaGateway worker;
    private final SiemUebaShadowRunRepository runs;
    private final SiemUebaShadowDeliveryRepository deliveries;
    private final SiemAccountBehaviorWindowRepository windows;
    private final SiemUebaModelJobRepository jobs;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final TransactionTemplate tx;
    private final boolean enabled;
    private final AtomicBoolean feeding = new AtomicBoolean();

    public SiemUebaShadowService(SiemUebaGateway worker, SiemUebaShadowRunRepository runs,
            SiemUebaShadowDeliveryRepository deliveries, SiemAccountBehaviorWindowRepository windows,
            SiemUebaModelJobRepository jobs, AuditLogService audit, ObjectMapper json,
            PlatformTransactionManager transactions, @Value("${siem.ueba.enabled:false}") boolean enabled) {
        this.worker = worker; this.runs = runs; this.deliveries = deliveries; this.windows = windows;
        this.jobs = jobs; this.audit = audit; this.json = json; this.tx = new TransactionTemplate(transactions); this.enabled = enabled;
    }

    @Transactional
    public SiemDtos.UebaShadowRun start(SiemDtos.StartUebaShadow request, Authentication authentication) {
        String actor = requireAdmin(authentication);
        if (!enabled) throw new ConflictException("UEBA worker is disabled.");
        var job = jobs.lockedByModelVersion(request.modelVersion())
                .orElseThrow(() -> new ResourceNotFoundException("UEBA candidate not found."));
        if (!"SUCCEEDED".equals(job.getStatus()) || !"SUCCEEDED".equals(job.getEvaluationStatus())
                || !"PASS".equals(job.getQualityGate()) || !Set.of(2, 3, 4).contains(job.getFeatureSchemaVersion())
                || job.getModelSha256() == null || job.getDatasetManifestSha256() == null) {
            throw new ConflictException("Shadow requires a successfully evaluated strict candidate; worker revalidates the full proof.");
        }
        if (runs.existsByModelVersionAndStatusIn(job.getModelVersion(), LIVE)) throw new ConflictException("Candidate already has a live shadow run.");
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        var run = new SiemUebaShadowRun();
        run.setId(UUID.randomUUID().toString().replace("-", "")); run.setModelVersion(job.getModelVersion());
        run.setRequestedByUserId(actor); run.setStatus("STARTING"); run.setCreatedAt(now); run.setUpdatedAt(now);
        runs.save(run);
        // Commit the stable request ID first. Slow worker proof verification is
        // submitted by the feeder, so an HTTP timeout cannot erase its identity.
        audit.success("SIEM_UEBA_SHADOW_REQUESTED", actor, null, "UEBA_MODEL", job.getModelVersion());
        return dto(run);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.UebaShadowRun> list(int page, int size, Authentication authentication) {
        requireAdmin(authentication);
        if (page < 0 || size < 1 || size > 50) throw new BadRequestException("Invalid shadow page.");
        return PageResponse.from(runs.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size)).map(this::dto));
    }

    @Transactional(readOnly = true)
    public SiemDtos.UebaShadowRun get(String id, Authentication authentication) {
        requireAdmin(authentication); validateId(id);
        return dto(runs.findById(id).orElseThrow(() -> new ResourceNotFoundException("Shadow run not found.")));
    }

    @Scheduled(initialDelayString = "${siem.ueba.initial-delay-ms:20000}", fixedDelayString = "${siem.ueba.shadow-feed-interval-ms:30000}")
    public void feed() {
        if (!enabled || !feeding.compareAndSet(false, true)) return;
        try {
            for (var run : runs.findByStatusInOrderByCreatedAtAsc(LIVE, PageRequest.of(0, 4))) advance(run.getId());
        } finally { feeding.set(false); }
    }

    /** Public for integration tests; all inputs are persisted operator run IDs, never client clocks/vectors. */
    public void advance(String runId) {
        validateId(runId);
        Work work = tx.execute(status -> prepare(runId));
        if (work == null) return;
        try {
            if ("STARTING".equals(work.status())) {
                worker.startShadow(work.model(), work.id());
                finish(work, "QUEUED", null, false);
            } else if ("QUEUED".equals(work.status())) {
                var job = worker.trainingJob(work.id());
                if (!work.model().equals(job.modelVersion())) throw new ConflictException("Shadow worker model changed.");
                if ("SUCCEEDED".equals(job.status())) {
                    var state = worker.validateShadowState(job.metadata(), work.id());
                    verifyInitialBinding(work.model(), state);
                    finish(work, state.path("status").asText(), state, false);
                } else if (Set.of("FAILED", "INTERRUPTED").contains(job.status())) finish(work, "FAILED", null, false);
                else finish(work, "QUEUED", null, false);
            } else {
                var state = worker.shadowStatus(work.id());
                verifyUnchanged(readTree(work.state()), state);
                if ("RUNNING".equals(state.path("status").asText()) && !work.deliveries().isEmpty()) {
                    var batch = work.deliveries().stream().map(value -> decode(value.getPayloadJson())).toList();
                    int schema = state.path("feature_schema_version").asInt();
                    if (schema == 2) worker.sendShadowWindows(work.id(), batch);
                    else worker.sendShadowWindows(work.id(), batch, schema);
                    state = worker.shadowStatus(work.id());
                    verifyUnchanged(readTree(work.state()), state);
                    finish(work, state.path("status").asText(), state, true);
                } else finish(work, state.path("status").asText(), state, false);
            }
        } catch (RuntimeException failure) {
            tx.executeWithoutResult(status -> {
                var run = runs.locked(work.id()).orElseThrow();
                run.setLeaseUntil(null); run.setLastErrorType(failure.getClass().getSimpleName());
                if (failure instanceof ConflictException) run.setStatus("INVALIDATED");
                run.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC)); runs.save(run);
            });
        }
    }

    private Work prepare(String id) {
        var run = runs.locked(id).orElseThrow(() -> new ResourceNotFoundException("Shadow run not found."));
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        if (!LIVE.contains(run.getStatus()) || run.getLeaseUntil() != null && run.getLeaseUntil().isAfter(now)) return null;
        run.setLeaseUntil(now.plusMinutes(1)); runs.save(run);
        List<SiemUebaShadowDelivery> pending = List.of();
        if ("RUNNING".equals(run.getStatus())) {
            pending = deliveries.findByRunIdAndAcknowledgedFalseOrderByCreatedAtAscIdAsc(id, PageRequest.of(0, 256));
            int remaining = 256 - pending.size();
            if (remaining > 0) {
                JsonNode binding = readTree(run.getStateJson());
                int schema = binding.path("feature_schema_version").asInt(-1);
                if (!Set.of(2, 3, 4).contains(schema)) throw new ConflictException("Frozen shadow feature schema is invalid.");
                LocalDateTime from = OffsetDateTime.parse(binding.path("started_at_utc").asText())
                        .withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();
                for (var window : windows.findShadowEligible(id, from, now, schema, PageRequest.of(0, remaining))) {
                    var delivery = new SiemUebaShadowDelivery();
                    delivery.setId(digest(id + "/" + window.getId())); delivery.setRunId(id); delivery.setWindowId(window.getId());
                    delivery.setPayloadJson(encode(Map.of("window_id", window.getId(),
                            "window_end_utc", window.getWindowEnd().atOffset(ZoneOffset.UTC).toString(),
                            "baseline_established", window.isBaselineEstablished(), "features", window.modelFeatureVector(schema))));
                    delivery.setCreatedAt(now); delivery.setUpdatedAt(now); deliveries.save(delivery);
                }
                deliveries.flush();
                pending = deliveries.findByRunIdAndAcknowledgedFalseOrderByCreatedAtAscIdAsc(id, PageRequest.of(0, 256));
            }
        }
        return new Work(id, run.getModelVersion(), run.getStatus(), run.getStateJson(), pending);
    }

    private void finish(Work work, String status, JsonNode state, boolean acknowledged) {
        tx.executeWithoutResult(transaction -> {
            var run = runs.locked(work.id()).orElseThrow();
            if (!work.status().equals(run.getStatus())) throw new ConflictException("Shadow lifecycle changed during delivery.");
            LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
            if (acknowledged) for (var sent : work.deliveries()) {
                var delivery = deliveries.findById(sent.getId()).orElseThrow();
                if (!sent.getPayloadJson().equals(delivery.getPayloadJson())) throw new ConflictException("Frozen shadow payload changed.");
                delivery.setAcknowledged(true); delivery.setUpdatedAt(now); deliveries.save(delivery);
            }
            run.setStatus(status); if (state != null) run.setStateJson(state.toString());
            run.setLeaseUntil(null); run.setLastErrorType(null); run.setUpdatedAt(now); runs.save(run);
            if (state != null && "COMPLETED".equals(status)) {
                deliveries.flush();
                var modelJob = jobs.lockedByModelVersion(work.model()).orElseThrow();
                Map<String, Object> summary = new java.util.HashMap<>(modelJob.getEvaluationSummaryJson() == null
                        ? Map.of() : decode(modelJob.getEvaluationSummaryJson()));
                long accepted = deliveries.countByRunIdAndAcknowledgedTrue(work.id());
                summary.put("shadow_run_id", work.id()); summary.put("shadow_status", status);
                summary.put("shadow_clock_provenance", state.path("clock_provenance").asText());
                summary.put("shadow_elapsed_seconds", state.path("elapsed_monotonic_seconds").asDouble());
                summary.put("shadow_closed_windows", state.path("closed_windows").asLong());
                summary.put("shadow_gate", accepted >= 600 && accepted == state.path("closed_windows").asLong() ? "PASS" : "FAIL");
                modelJob.setEvaluationSummaryJson(encode(summary)); modelJob.setUpdatedAt(now); jobs.save(modelJob);
            }
        });
    }

    private void verifyInitialBinding(String model, JsonNode state) {
        var job = jobs.findByModelVersion(model).orElseThrow();
        var trained = worker.trainingJob(job.getWorkerJobId());
        var meta = trained.metadata();
        if (!"SUCCEEDED".equals(trained.status()) || !model.equals(trained.modelVersion())
                || !"STRICT".equals(meta.path("calibration_scope").asText())
                || meta.path("feature_schema_version").asInt(-1) != job.getFeatureSchemaVersion()
                || state.path("feature_schema_version").asInt(-1) != job.getFeatureSchemaVersion()
                || !UebaScorePolicy.fromWire(meta.path("score_policy"), job.getFeatureSchemaVersion()).strict()
                || !model.equals(state.path("model_version").asText())
                || !job.getModelSha256().equals(state.path("model_sha256").asText())
                || !job.getModelSha256().equals(meta.path("sha256").asText())
                || !job.getDatasetManifestSha256().equals(state.path("dataset_sha256").asText())
                || !job.getDatasetManifestSha256().equals(meta.path("dataset_manifest_sha256").asText())
                || !meta.path("calibration_sha256").asText().equals(state.path("calibration_sha256").asText())
                || !meta.path("score_policy").path("policy_sha256").asText().equals(state.path("policy_sha256").asText())) {
            throw new ConflictException("Shadow proof does not match the registered candidate.");
        }
    }

    private void verifyUnchanged(JsonNode before, JsonNode after) {
        for (String name : BINDINGS) if (!before.path(name).equals(after.path(name))) throw new ConflictException("Shadow binding changed.");
        if (after.path("closed_windows").asLong() < before.path("closed_windows").asLong()
                || after.path("elapsed_monotonic_seconds").asDouble() < before.path("elapsed_monotonic_seconds").asDouble()) {
            throw new ConflictException("Shadow progress moved backwards.");
        }
    }

    private SiemDtos.UebaShadowRun dto(SiemUebaShadowRun run) {
        return new SiemDtos.UebaShadowRun(run.getId(), run.getModelVersion(), run.getStatus(),
                jobs.findByModelVersion(run.getModelVersion()).map(value -> value.getDataProvenance()).orElse("UNKNOWN"),
                run.getCreatedAt(), run.getUpdatedAt(), deliveries.countByRunIdAndAcknowledgedTrue(run.getId()),
                run.getLastErrorType(), run.getStateJson() == null ? Map.of() : decode(run.getStateJson()));
    }
    private Map<String, Object> decode(String value) {
        try { return json.readValue(value, new TypeReference<>() {}); }
        catch (Exception failure) { throw new ConflictException("Stored shadow metadata is invalid."); }
    }
    private JsonNode readTree(String value) {
        try { return json.readTree(value); }
        catch (Exception failure) { throw new ConflictException("Stored shadow binding is invalid."); }
    }
    private String encode(Map<String, Object> value) {
        try { return json.writeValueAsString(value); }
        catch (Exception failure) { throw new IllegalStateException("Unable to serialize shadow snapshot."); }
    }
    private static String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception failure) { throw new IllegalStateException("SHA-256 unavailable."); }
    }
    private static void validateId(String value) {
        if (value == null || !value.matches("[a-f0-9]{32}")) throw new BadRequestException("Invalid shadow run ID.");
    }
    private static String requireAdmin(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)
                || !"ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(principal.getUser().getRole()))) {
            throw new AccessDeniedException("Only an administrator can manage candidate shadow runs.");
        }
        return principal.getUser().getId();
    }
    private record Work(String id, String model, String status, String state, List<SiemUebaShadowDelivery> deliveries) { }
}
