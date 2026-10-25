package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemUebaModelJob;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.repository.siem.SiemUebaShadowDeliveryRepository;
import com.flarefitness.backend.repository.siem.SiemUebaShadowRunRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import com.flarefitness.backend.service.siem.SiemUebaShadowService;
import com.flarefitness.backend.service.siem.SiemUebaModelService;
import com.flarefitness.backend.service.siem.UebaExperimentCatalog;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Real MySQL commit/lease/outbox tests. Worker eligibility is stubbed here;
 * these tests are NOT evidence of strict quality or an elapsed 24-hour run. */
@SpringBootTest
class UebaShadowOutboxIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired SiemUebaShadowRunRepository runs;
    @Autowired SiemUebaShadowDeliveryRepository deliveries;
    @Autowired SiemAccountBehaviorWindowRepository windows;
    @Autowired SiemUebaModelJobRepository jobs;
    @Autowired SiemIncidentRepository incidents;
    @Autowired SiemIncidentHistoryRepository history;
    @Autowired SiemSecurityEventRepository events;
    @Autowired AuditLogService audit;
    @Autowired ObjectMapper mapper;
    @Autowired PlatformTransactionManager transactions;
    SiemUebaGateway worker;
    SiemUebaShadowService service;
    TransactionTemplate tx;
    SiemUebaModelJob candidate;
    ObjectNode metadata;
    List<String> ownRuns = new ArrayList<>(), ownWindows = new ArrayList<>();
    List<String> ownJobs = new ArrayList<>();

    @BeforeEach
    void prepare() throws Exception {
        tx = new TransactionTemplate(transactions); worker = mock(SiemUebaGateway.class);
        service = new SiemUebaShadowService(worker, runs, deliveries, windows, jobs, audit, mapper, transactions, true);
        candidate = new SiemUebaModelJob(); String suffix = UUID.randomUUID().toString().substring(0, 8);
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        candidate.setId("owned-shadow-job-" + suffix); candidate.setModelVersion("owned-shadow-model-" + suffix);
        candidate.setWorkerJobId("e".repeat(32)); candidate.setRequestedByUserId("owned-shadow-operator");
        candidate.setTrainingFrom(now.minusDays(31)); candidate.setTrainingTo(now.minusDays(2));
        candidate.setTrainingWindows(50000); candidate.setCalibrationWindows(2000000); candidate.setStatus("SUCCEEDED");
        candidate.setFeatureSchemaVersion(2); candidate.setDataProvenance("DEMO_ONLY");
        candidate.setModelSha256("a".repeat(64)); candidate.setDatasetManifestSha256("b".repeat(64));
        candidate.setEvaluationStatus("SUCCEEDED"); candidate.setQualityGate("PASS"); candidate.setCreatedAt(now); candidate.setUpdatedAt(now);
        tx.executeWithoutResult(status -> jobs.save(candidate));
        metadata = mapper.createObjectNode(); metadata.put("sha256", candidate.getModelSha256());
        metadata.put("calibration_scope", "STRICT"); metadata.put("calibration_sha256", "c".repeat(64));
        metadata.put("dataset_manifest_sha256", candidate.getDatasetManifestSha256());
        metadata.put("model_version", candidate.getModelVersion()); metadata.put("feature_schema_version", 2);
        metadata.put("training_windows", 50000); metadata.put("calibration_windows", 2000000);
        metadata.set("score_policy", mapper.readTree(getClass().getResourceAsStream("/ueba-score-policy-golden.json")));
        when(worker.trainingJob(candidate.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(candidate.getWorkerJobId(),
                "SUCCEEDED", candidate.getModelVersion(), metadata));
        doCallRealMethod().when(worker).validateShadowState(any(), anyString());
    }

    @AfterEach
    void removeOnlyOwnedFixtureRows() {
        tx.executeWithoutResult(status -> {
            for (String id : ownRuns) {
                deliveries.deleteAll(deliveries.findByRunIdAndAcknowledgedFalseOrderByCreatedAtAscIdAsc(id, PageRequest.of(0, 256)));
                // The fixture creates at most one acknowledged row per run.
                for (String window : ownWindows) {
                    String key;
                    try { key = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                            .digest((id + "/" + window).getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
                    catch (Exception failure) { throw new IllegalStateException(failure); }
                    deliveries.deleteById(key);
                }
                deliveries.flush(); runs.deleteById(id);
            }
            windows.deleteAllById(ownWindows); jobs.deleteById(candidate.getId());
            jobs.deleteAllById(ownJobs);
        });
    }

    @Test
    void adminStartIsCommittedBeforeAnyHttpAndPreviewCannotOpenShadow() {
        for (String role : List.of("CUSTOMER", "SOC L1", "SOC L2")) {
            assertThatThrownBy(() -> tx.execute(status -> service.start(request(), actor(role)))).isInstanceOf(AccessDeniedException.class);
            assertThatThrownBy(() -> service.list(0, 20, actor(role))).isInstanceOf(AccessDeniedException.class);
        }
        tx.executeWithoutResult(status -> { var row = jobs.findById(candidate.getId()).orElseThrow(); row.setQualityGate("NOT_RUN"); jobs.save(row); });
        assertThatThrownBy(() -> tx.execute(status -> service.start(request(), actor("Quan tri vien")))).isInstanceOf(ConflictException.class);
        verify(worker, never()).startShadow(anyString(), anyString());
        tx.executeWithoutResult(status -> { var row = jobs.findById(candidate.getId()).orElseThrow(); row.setQualityGate("PASS"); jobs.save(row); });
        var started = start(); assertThat(started.status()).isEqualTo("STARTING");
        assertThat(runs.findById(started.id())).isPresent(); verify(worker, never()).startShadow(anyString(), anyString());
        assertThatThrownBy(() -> tx.execute(status -> service.start(request(), actor("Quan tri vien")))).isInstanceOf(ConflictException.class);
        assertThatThrownBy(() -> service.list(-1, 20, actor("Quan tri vien"))).isInstanceOf(com.flarefitness.backend.exception.BadRequestException.class);
    }

    @Test
    void committedFrozenOutboxSurvivesAmbiguousAckAndLaterWindowUpdatesWithoutActions() throws Exception {
        long beforeIncidents = incidents.count(), beforeHistory = history.count();
        var started = start(); ObjectNode state = runningState(started.id()); bindWorker(started.id(), state);
        service.advance(started.id()); service.advance(started.id());
        assertThat(service.get(started.id(), actor("Quan tri vien")).status()).isEqualTo("RUNNING");
        LocalDateTime from = java.time.OffsetDateTime.parse(state.path("started_at_utc").asText()).toLocalDateTime();
        var current = window(from.plusSeconds(1), 2); var old = window(from.minusSeconds(1), 2); var future = window(LocalDateTime.now(ZoneOffset.UTC).plusHours(1), 2);
        var firstPayload = new AtomicReference<String>(); var failOnce = new AtomicBoolean(true);
        doAnswer(call -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            List<Map<String, Object>> batch = call.getArgument(1);
            assertThat(batch).hasSize(1); assertThat(batch.getFirst().get("window_id")).isEqualTo(current.getId());
            assertThat(deliveries.findByRunIdAndAcknowledgedFalseOrderByCreatedAtAscIdAsc(started.id(), PageRequest.of(0, 256))).hasSize(1);
            String payload = mapper.writeValueAsString(batch);
            if (failOnce.getAndSet(false)) { firstPayload.set(payload); state.put("closed_windows", 1); throw new ServiceUnavailableException("owned ambiguous test acknowledgement"); }
            assertThat(payload).isEqualTo(firstPayload.get()); return null;
        }).when(worker).sendShadowWindows(anyString(), anyList());
        service.advance(started.id());
        assertThat(service.get(started.id(), actor("Quan tri vien")).acknowledgedWindows()).isZero();
        tx.executeWithoutResult(status -> { var changed = windows.findById(current.getId()).orElseThrow(); snapshot(changed, 9); windows.save(changed); });
        service.advance(started.id()); service.advance(started.id());
        var result = service.get(started.id(), actor("Quan tri vien"));
        assertThat(result.acknowledgedWindows()).isEqualTo(1); assertThat(result.state().get("closed_windows")).isEqualTo(1);
        assertThat(result.lastErrorType()).isNull();
        assertThat(windows.findById(current.getId()).orElseThrow().getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
        assertThat(windows.findById(current.getId()).orElseThrow().getRiskScore()).isNull();
        assertThat(incidents.count()).isEqualTo(beforeIncidents); assertThat(history.count()).isEqualTo(beforeHistory);
        assertThat(jobs.findById(candidate.getId()).orElseThrow().getStatus()).isEqualTo("SUCCEEDED");
        verify(worker, org.mockito.Mockito.times(2)).sendShadowWindows(anyString(), anyList());
        verify(worker, never()).activate(anyString());
    }

    @Test
    void bindingTamperingInvalidatesRunInsteadOfScoringOrAcceptingCompletion() {
        var started = start(); ObjectNode state = runningState(started.id()); bindWorker(started.id(), state);
        service.advance(started.id()); service.advance(started.id());
        state.put("policy_sha256", "f".repeat(64)); service.advance(started.id());
        assertThat(service.get(started.id(), actor("Quan tri vien")).status()).isEqualTo("INVALIDATED");
        verify(worker, never()).sendShadowWindows(anyString(), anyList()); verify(worker, never()).activate(anyString());
    }

    @Test
    void contextualOutboxUsesFrozenRunSchemaAndSkipsLegacyOnlySnapshotsWithoutScoringPrimary() throws Exception {
        candidate.setFeatureSchemaVersion(3);
        tx.executeWithoutResult(status -> jobs.save(candidate));
        metadata.put("feature_schema_version", 3);
        metadata.set("score_policy", com.flarefitness.backend.service.siem.UebaTestPolicies.contextual(mapper));
        var started = start(); ObjectNode state = runningState(started.id()); bindWorker(started.id(), state);
        service.advance(started.id()); service.advance(started.id());
        LocalDateTime from = java.time.OffsetDateTime.parse(state.path("started_at_utc").asText()).toLocalDateTime();
        var legacyOnly = window(from.plusSeconds(1), 2);
        var contextual = window(from.plusSeconds(2), 2);
        tx.executeWithoutResult(status -> {
            var row = windows.findById(contextual.getId()).orElseThrow();
            var vector = new ArrayList<>(row.modelFeatureVector(2));
            vector.addAll(List.of(2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
            row.replaceContextualFeatures(new AccountBehaviorFeatures.Vector(3, vector), from.plusSeconds(2)); windows.save(row);
        });
        doAnswer(call -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat((Integer) call.getArgument(2)).isEqualTo(3);
            List<Map<String, Object>> batch = call.getArgument(1);
            assertThat(batch).hasSize(1); assertThat(batch.getFirst().get("window_id")).isEqualTo(contextual.getId());
            assertThat((List<?>) batch.getFirst().get("features")).hasSize(25);
            state.put("closed_windows", 1); return null;
        }).when(worker).sendShadowWindows(anyString(), anyList(), org.mockito.ArgumentMatchers.eq(3));
        service.advance(started.id()); service.advance(started.id());
        assertThat(service.get(started.id(), actor("Quan tri vien")).acknowledgedWindows()).isEqualTo(1);
        assertThat(windows.findById(contextual.getId()).orElseThrow().getScoreStatus()).isEqualTo(BehaviorScoreStatus.PENDING);
        assertThat(windows.findById(legacyOnly.getId()).orElseThrow().getModelVersion()).isNull();
        verify(worker, never()).sendShadowWindows(anyString(), anyList()); verify(worker, never()).activate(anyString());
        state.put("feature_schema_version", 2); service.advance(started.id());
        assertThat(service.get(started.id(), actor("Quan tri vien")).status()).isEqualTo("INVALIDATED");
    }

    @Test
    void activationIsCommittedAndIdempotentAndDoesNotRetirePrimaryBeforeActualAcknowledgement() {
        var lifecycle = activationLifecycle();
        var started = tx.execute(status -> lifecycle.activate(candidate.getModelVersion(), actor("Quan tri vien")));
        assertThat(started.status()).isEqualTo("ACTIVATION_QUEUED");
        var saved = jobs.findById(candidate.getId()).orElseThrow(); String requestId = saved.getActivationWorkerJobId();
        assertThat(requestId).matches("[a-f0-9]{32}"); verify(worker, never()).startActivation(anyString(), anyString());
        tx.execute(status -> lifecycle.activate(candidate.getModelVersion(), actor("Quan tri vien")));
        assertThat(jobs.findById(candidate.getId()).orElseThrow().getActivationWorkerJobId()).isEqualTo(requestId);
        when(worker.isEnabled()).thenReturn(true);
        when(worker.startActivation(candidate.getModelVersion(), requestId)).thenReturn(new SiemUebaGateway.TrainingJob(requestId, "QUEUED", candidate.getModelVersion()));
        when(worker.trainingJob(requestId)).thenReturn(new SiemUebaGateway.TrainingJob(requestId, "SUCCEEDED", candidate.getModelVersion(), metadata));
        when(worker.primaryMetadata()).thenReturn(metadata);
        tx.executeWithoutResult(status -> lifecycle.advanceActivations());
        assertThat(jobs.findById(candidate.getId()).orElseThrow().getStatus()).isEqualTo("ACTIVATING");
        tx.executeWithoutResult(status -> lifecycle.advanceActivations());
        assertThat(jobs.findById(candidate.getId()).orElseThrow().getStatus()).isEqualTo("ACTIVE");
        assertThat(jobs.findById(candidate.getId()).orElseThrow().getActivationStatus()).isEqualTo("SUCCEEDED");
        verify(worker, never()).activate(anyString());
    }

    @Test
    void aSucceededWorkerJobCannotClaimAnotherActualPrimaryAsThisCandidate() {
        var lifecycle = activationLifecycle(); tx.execute(status -> lifecycle.activate(candidate.getModelVersion(), actor("Quan tri vien")));
        String id = jobs.findById(candidate.getId()).orElseThrow().getActivationWorkerJobId();
        when(worker.isEnabled()).thenReturn(true);
        when(worker.startActivation(candidate.getModelVersion(), id)).thenReturn(new SiemUebaGateway.TrainingJob(id, "QUEUED", candidate.getModelVersion()));
        when(worker.trainingJob(id)).thenReturn(new SiemUebaGateway.TrainingJob(id, "SUCCEEDED", candidate.getModelVersion(), metadata));
        when(worker.primaryMetadata()).thenReturn(metadata.deepCopy().put("model_version", "other-owned-primary"));
        tx.executeWithoutResult(status -> lifecycle.advanceActivations()); tx.executeWithoutResult(status -> lifecycle.advanceActivations());
        var result = jobs.findById(candidate.getId()).orElseThrow(); assertThat(result.getStatus()).isEqualTo("SUCCEEDED");
        assertThat(result.getActivationStatus()).isEqualTo("FAILED"); assertThat(result.getActivatedAt()).isNull();
    }

    private SiemUebaModelService activationLifecycle() {
        var catalog = mock(UebaExperimentCatalog.class);
        metadata.put("selected_reference_model_sha256", candidate.getModelSha256());
        metadata.put("model_state_sha256", "e".repeat(64)); metadata.put("model_state_verifier_sha256", "b".repeat(64));
        metadata.put("model_state_format", "SKLEARN_NUMERIC_STATE_V2");
        var reference = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("owned-activation-recipe", "owned-activation-data", "DEMO_ONLY",
                2, 50000, 2000000, candidate.getTrainingFrom(), candidate.getTrainingTo(), 360), candidate.getDatasetManifestSha256(),
                metadata.path("score_policy").path("policy_sha256").asText(), "STRICT", "f".repeat(64), candidate.getModelSha256(), "c".repeat(64),
                "e".repeat(64), "b".repeat(64));
        tx.executeWithoutResult(status -> {
            var row = jobs.findById(candidate.getId()).orElseThrow(); row.setRecipeId("owned-activation-recipe");
            row.setEvaluationDatasetSha256("f".repeat(64)); row.setEvaluationSummaryJson("{\"shadow_gate\":\"PASS\"}"); jobs.save(row);
        });
        when(catalog.strictRecipeOrNull("owned-activation-recipe")).thenReturn(reference);
        when(worker.validateStrictEvaluation(any(), anyString(), anyString(), any())).thenReturn(Map.of("quality_gate", "PASS"));
        return new SiemUebaModelService(worker, windows, jobs, events, audit, catalog, mapper);
    }

    private SiemDtos.UebaShadowRun start() {
        var result = tx.execute(status -> service.start(request(), actor("Quan tri vien"))); ownRuns.add(result.id()); return result;
    }
    private SiemDtos.StartUebaShadow request() { return new SiemDtos.StartUebaShadow(candidate.getModelVersion()); }
    private void bindWorker(String id, ObjectNode state) {
        when(worker.startShadow(candidate.getModelVersion(), id)).thenReturn(new SiemUebaGateway.TrainingJob(id, "QUEUED", candidate.getModelVersion()));
        when(worker.trainingJob(id)).thenAnswer(call -> new SiemUebaGateway.TrainingJob(id, "SUCCEEDED", candidate.getModelVersion(), state.deepCopy()));
        when(worker.shadowStatus(id)).thenAnswer(call -> worker.validateShadowState(state.deepCopy(), id));
    }
    private ObjectNode runningState(String id) {
        ObjectNode state = mapper.createObjectNode(); state.put("run_id", id); state.put("model_version", candidate.getModelVersion());
        state.put("status", "RUNNING"); state.put("feature_schema_version", candidate.getFeatureSchemaVersion()); state.put("clock_provenance", "REAL_SERVER_CLOCK");
        state.put("model_sha256", candidate.getModelSha256()); state.put("dataset_sha256", candidate.getDatasetManifestSha256());
        state.put("calibration_sha256", "c".repeat(64)); state.put("policy_sha256", metadata.path("score_policy").path("policy_sha256").asText());
        state.put("boot_sha256", "d".repeat(64)); state.put("started_at_utc", LocalDateTime.now(ZoneOffset.UTC).minusMinutes(1).atOffset(ZoneOffset.UTC).toString());
        state.put("started_monotonic", 10); state.put("last_heartbeat_monotonic", 70); state.put("elapsed_monotonic_seconds", 60);
        state.put("maximum_heartbeat_gap_seconds", 60); state.put("closed_windows", 0);
        state.set("candidate_side_effects", mapper.valueToTree(Map.of("incidents", 0, "history", 0, "ip_lookups", 0,
                "ip_blocks", 0, "session_revocations", 0, "policy_publications", 0))); return state;
    }
    private SiemAccountBehaviorWindow window(LocalDateTime end, int requests) {
        var value = new SiemAccountBehaviorWindow(); value.setId("owned-shadow-window-" + UUID.randomUUID()); value.setAccountId("owned-shadow-customer");
        value.setWindowStart(end.minusMinutes(15)); value.setWindowEnd(end); value.setCreatedAt(end); snapshot(value, requests);
        tx.executeWithoutResult(status -> windows.save(value)); ownWindows.add(value.getId()); return value;
    }
    private void snapshot(SiemAccountBehaviorWindow value, int requests) {
        List<Double> base = List.of((double) requests, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0);
        value.replaceFeatures(new AccountBehaviorFeatures.Vector(1, base), requests, false, null, "CHROMIUM", "NORMAL", value.getWindowEnd());
        List<Double> personal = new ArrayList<>(base); personal.addAll(List.of(0.0, 0.0, 0.0, 0.0));
        value.replacePersonalFeatures(new AccountBehaviorFeatures.Vector(2, personal), value.getWindowEnd());
    }
    private UsernamePasswordAuthenticationToken actor(String role) {
        User user = new User(); user.setId("owned-shadow-operator"); user.setUsername(user.getId()); user.setRole(role);
        user.setStatus("Hoat dong"); user.setDeleted(false); var principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
