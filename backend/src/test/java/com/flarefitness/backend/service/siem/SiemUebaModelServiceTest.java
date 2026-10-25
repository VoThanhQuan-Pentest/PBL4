package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemUebaModelJob;
import com.flarefitness.backend.exception.ConflictException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class SiemUebaModelServiceTest {
    private final SiemUebaGateway worker = Mockito.mock(SiemUebaGateway.class);
    private final SiemAccountBehaviorWindowRepository windows = Mockito.mock(SiemAccountBehaviorWindowRepository.class);
    private final SiemUebaModelJobRepository jobs = Mockito.mock(SiemUebaModelJobRepository.class);
    private final SiemSecurityEventRepository events = Mockito.mock(SiemSecurityEventRepository.class);
    private final AuditLogService audit = Mockito.mock(AuditLogService.class);
    private final SiemUebaModelService service = new SiemUebaModelService(worker, windows, jobs, events, audit);

    @Test
    void l1CannotSubmitTrainingDataToTheWorker() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        assertThatThrownBy(() -> service.startTraining(
                new SiemDtos.StartUebaTraining(now.minusDays(10), now.minusHours(1)), auth("SOC L1")))
                .isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(worker, windows, jobs, events);
    }

    @Test
    void adminTrainsOnServerSelectedWindowsWithSeparateFiveHundredAndHundredSamples() {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        List<SiemAccountBehaviorWindow> samples = new ArrayList<>();
        for (int index = 0; index < 601; index++) {
            SiemAccountBehaviorWindow window = new SiemAccountBehaviorWindow();
            window.setAccountId("customer-" + index % 3);
            window.setWindowStart(now.minusDays(8).plusMinutes(index * 15L));
            double benignNoise = index % 7 == 0 ? 1.0 : 0.0;
            window.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                    List.of(1.0, benignNoise, 0.0, benignNoise, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0)),
                    1, true, "203.0.113.1", "CHROMIUM", index == 600 ? "ABNORMAL" : "NORMAL", now);
            samples.add(window);
        }
        when(windows.findByWindowStartGreaterThanEqualAndWindowStartLessThanAndFeatureSchemaVersionOrderByWindowStartAscIdAsc(
                any(), any(), anyInt(), any(Pageable.class))).thenAnswer(invocation -> {
            Pageable page = invocation.getArgument(3);
            int start = Math.toIntExact(page.getOffset());
            int end = Math.min(start + page.getPageSize(), samples.size());
            return new PageImpl<>(samples.subList(start, end), page, samples.size());
        });
        when(worker.startTraining(anyString(), anyList(), anyList())).thenAnswer(invocation ->
                new SiemUebaGateway.TrainingJob("a".repeat(32), "QUEUED", invocation.getArgument(0)));

        SiemDtos.UebaTrainingJob result = service.startTraining(
                new SiemDtos.StartUebaTraining(now.minusDays(10), now.minusHours(1)), auth("Quan tri vien"));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<List<Double>>> training = ArgumentCaptor.forClass(List.class);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<List<Double>>> calibration = ArgumentCaptor.forClass(List.class);
        verify(worker).startTraining(anyString(), training.capture(), calibration.capture());
        assertThat(training.getValue()).hasSize(500);
        assertThat(calibration.getValue()).hasSize(100);
        assertThat(result.status()).isEqualTo("QUEUED");
        verify(jobs).save(any());
    }

    private UsernamePasswordAuthenticationToken auth(String role) {
        User user = new User();
        user.setId("analyst-1");
        user.setUsername("analyst");
        user.setPassword("unused");
        user.setRole(role);
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    @Test
    void strictRefreshBindsTheActualFileHashAndRejectsTamperedNumericReferenceMetadata() throws Exception {
        var json = new ObjectMapper(); var policy = json.readTree(getClass().getResourceAsStream("/ueba-score-policy-golden.json"));
        var catalog = Mockito.mock(UebaExperimentCatalog.class);
        var strictService = new SiemUebaModelService(worker, windows, jobs, events, audit, catalog, json);
        LocalDateTime from = LocalDateTime.of(2026, 1, 1, 0, 0), to = from.plusDays(32);
        var reference = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("owned-strict-recipe", "owned-strict-data",
                "DEMO_ONLY", 2, 50000, 2000000, from, to, 360), "d".repeat(64), policy.path("policy_sha256").asText(),
                "STRICT", "f".repeat(64), "f".repeat(64), "c".repeat(64), "e".repeat(64), "b".repeat(64));
        var job = new SiemUebaModelJob(); job.setId("owned-job-id"); job.setModelVersion("owned-refitted-model");
        job.setStatus("QUEUED");
        job.setWorkerJobId("1".repeat(32)); job.setFeatureSchemaVersion(2); job.setTrainingWindows(50000); job.setCalibrationWindows(2000000);
        job.setRecipeId("owned-strict-recipe"); job.setDatasetManifestSha256("d".repeat(64)); job.setTrainingFrom(from); job.setTrainingTo(to);
        when(jobs.findById(job.getId())).thenReturn(Optional.of(job));
        when(catalog.strictRecipeOrNull(job.getRecipeId())).thenReturn(reference);
        var metadata = json.createObjectNode(); metadata.put("sha256", "a".repeat(64)); metadata.put("feature_schema_version", 2);
        metadata.put("training_windows", 50000); metadata.put("calibration_windows", 2000000); metadata.set("score_policy", policy);
        metadata.put("calibration_scope", "STRICT"); metadata.put("dataset_manifest_sha256", "d".repeat(64));
        metadata.put("calibration_sha256", "c".repeat(64)); metadata.put("selected_reference_model_sha256", "f".repeat(64));
        metadata.put("model_state_sha256", "e".repeat(64)); metadata.put("model_state_verifier_sha256", "b".repeat(64));
        metadata.put("model_state_format", "SKLEARN_NUMERIC_STATE_V2");
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), metadata));
        strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"));
        assertThat(job.getStatus()).isEqualTo("SUCCEEDED");
        assertThat(job.getModelSha256()).isEqualTo("a".repeat(64)).isNotEqualTo(reference.expectedModelSha256());
        for (String field : List.of("selected_reference_model_sha256", "model_state_sha256", "model_state_verifier_sha256", "model_state_format", "calibration_sha256", "sha256")) {
            var changed = metadata.deepCopy(); changed.put(field, "changed");
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
    }

    @Test
    void supportRefreshRequiresItsRegisteredKindRecipeHashAndNumericStateFormat() throws Exception {
        var json = new ObjectMapper(); var policy = UebaTestPolicies.sessionEndpoint(json);
        var catalog = Mockito.mock(UebaExperimentCatalog.class);
        var strictService = new SiemUebaModelService(worker, windows, jobs, events, audit, catalog, json);
        LocalDateTime from = LocalDateTime.of(2026, 1, 1, 0, 0), to = from.plusDays(32);
        var reference = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("support-strict-recipe", "support-strict-data",
                "DEMO_ONLY", 4, 50000, 2000000, from, to, 360), "d".repeat(64), policy.path("policy_sha256").asText(),
                "STRICT", "f".repeat(64), "f".repeat(64), "c".repeat(64), "e".repeat(64), "b".repeat(64),
                "normal_support_distance", 1, "9".repeat(64), "NORMAL_SUPPORT_NUMERIC_STATE_V1");
        var job = new SiemUebaModelJob(); job.setId("support-job-id"); job.setModelVersion("support-refitted-model"); job.setStatus("QUEUED");
        job.setWorkerJobId("2".repeat(32)); job.setFeatureSchemaVersion(4); job.setTrainingWindows(50000); job.setCalibrationWindows(2000000);
        job.setRecipeId("support-strict-recipe"); job.setDatasetManifestSha256("d".repeat(64)); job.setTrainingFrom(from); job.setTrainingTo(to);
        when(jobs.findById(job.getId())).thenReturn(Optional.of(job)); when(catalog.strictRecipeOrNull(job.getRecipeId())).thenReturn(reference);
        var metadata = json.createObjectNode(); metadata.put("sha256", "a".repeat(64)); metadata.put("feature_schema_version", 4);
        metadata.put("training_windows", 50000); metadata.put("calibration_windows", 2000000); metadata.set("score_policy", policy);
        metadata.put("calibration_scope", "STRICT"); metadata.put("dataset_manifest_sha256", "d".repeat(64));
        metadata.put("calibration_sha256", "c".repeat(64)); metadata.put("selected_reference_model_sha256", "f".repeat(64));
        metadata.put("model_state_sha256", "e".repeat(64)); metadata.put("model_state_verifier_sha256", "b".repeat(64));
        metadata.put("model_kind", "normal_support_distance"); metadata.put("recipe_version", 1); metadata.put("recipe_sha256", "9".repeat(64));
        metadata.put("model_state_format", "NORMAL_SUPPORT_NUMERIC_STATE_V1");
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), metadata));
        strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"));
        assertThat(job.getModelSha256()).isEqualTo("a".repeat(64));
        for (String field : List.of("model_kind", "recipe_version", "recipe_sha256", "model_state_format")) {
            var changed = metadata.deepCopy(); changed.remove(field);
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
        var changed = metadata.deepCopy(); changed.put("model_state_format", "SKLEARN_NUMERIC_STATE_V2");
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
    }

    @Test
    void hybridPilotTrainingRemainsIdOnlyAndBindsProtectedLabeledMetadata() throws Exception {
        var json = new ObjectMapper(); var policy = UebaTestPolicies.sessionEndpoint(json);
        var catalog = Mockito.mock(UebaExperimentCatalog.class);
        var hybridService = new SiemUebaModelService(worker, windows, jobs, events, audit, catalog, json);
        LocalDateTime from = LocalDateTime.of(2026, 1, 1, 0, 0), to = from.plusDays(32);
        String canonical = "{\"config\":{\"l2_regularization\":1,\"max_iter\":200,\"max_leaf_nodes\":31,\"random_state\":42},\"model_kind\":\"normal_plus_incident_research\",\"recipe_version\":1}";
        String recipeSha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        var proof = new UebaExperimentCatalog.HybridTrainingReference("hybrid-labeled-data", "8".repeat(64), 81500,
                Map.of("0", 71500, "1", 8000, "2", 2000));
        var reference = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("hybrid-owned-pilot", "hybrid-owned-data",
                "DEMO_ONLY", 4, 50000, 120000, from, to, 0), "d".repeat(64), policy.path("policy_sha256").asText(),
                "PILOT", null, null, null, null, null, UebaExperimentCatalog.HYBRID_MODEL_KIND, 1, recipeSha,
                UebaExperimentCatalog.HYBRID_STATE_FORMAT, proof);
        when(catalog.strictRecipeOrNull(reference.descriptor().recipeId())).thenReturn(reference);
        when(worker.startCatalogTraining(anyString(), anyString())).thenAnswer(invocation ->
                new SiemUebaGateway.TrainingJob("3".repeat(32), "QUEUED", invocation.getArgument(0)));
        hybridService.startTraining(new SiemDtos.StartUebaTraining(from, to, reference.descriptor().recipeId()), auth("Quan tri vien"));
        ArgumentCaptor<SiemUebaModelJob> captured = ArgumentCaptor.forClass(SiemUebaModelJob.class);
        verify(jobs).save(captured.capture()); var job = captured.getValue();
        assertThat(job.getTrainingWindows()).isEqualTo(50000); assertThat(job.getCalibrationWindows()).isEqualTo(120000);
        verify(worker).startCatalogTraining(anyString(), Mockito.eq("hybrid-owned-pilot")); verifyNoInteractions(windows, events);
        when(jobs.findById(job.getId())).thenReturn(Optional.of(job));
        var metadata = json.createObjectNode(); metadata.put("sha256", "a".repeat(64)); metadata.put("feature_schema_version", 4);
        metadata.put("training_windows", 50000); metadata.put("calibration_windows", 120000); metadata.set("score_policy", policy);
        metadata.put("data_provenance", "DEMO_ONLY"); metadata.put("calibration_scope", "PILOT_ONLY"); metadata.put("dataset_manifest_sha256", "d".repeat(64));
        metadata.put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND); metadata.put("recipe_version", 1); metadata.put("recipe_sha256", recipeSha);
        metadata.put("model_state_format", UebaExperimentCatalog.HYBRID_STATE_FORMAT); metadata.put("model_state_sha256", "e".repeat(64)); metadata.put("model_state_verifier_sha256", "b".repeat(64)); metadata.put("calibration_sha256", "c".repeat(64));
        metadata.set("model_config", json.readTree(canonical).path("config"));
        metadata.put("labeled_training_artifact_id", proof.artifactId()); metadata.put("labeled_training_manifest_sha256", proof.manifestSha256()); metadata.put("labeled_training_windows", proof.labeledWindows()); metadata.set("labeled_class_windows", json.valueToTree(proof.classWindows()));
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), metadata));
        hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien")); assertThat(job.getModelSha256()).isEqualTo("a".repeat(64));
        for (String field : List.of("model_kind", "recipe_version", "recipe_sha256", "model_config", "model_state_format", "model_state_sha256", "model_state_verifier_sha256", "calibration_sha256", "labeled_training_artifact_id", "labeled_training_manifest_sha256", "labeled_training_windows", "labeled_class_windows")) {
            var changed = metadata.deepCopy(); changed.remove(field);
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
        for (String field : List.of("training_windows", "calibration_windows", "feature_schema_version")) {
            var changed = metadata.deepCopy(); changed.put(field, metadata.path(field).asDouble());
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
        var changed = metadata.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) changed.path("model_config")).put("random_state", 11);
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        changed = metadata.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) changed.path("labeled_class_windows")).put("1", 8001);
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        changed = metadata.deepCopy(); changed.put("model_state_format", "HYBRID_RESEARCH_NUMERIC_STATE_V1");
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        changed = metadata.deepCopy(); changed.put("model_state_sha256", new java.math.BigInteger("9".repeat(64)));
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        var strictReference = new UebaExperimentCatalog.StrictReference(reference.descriptor(), reference.manifestSha256(), reference.policySha256(),
                "STRICT", null, null, null, null, null, reference.modelKind(), 1, recipeSha, reference.modelStateFormat(), proof);
        when(catalog.strictRecipeOrNull(reference.descriptor().recipeId())).thenReturn(strictReference);
        changed = metadata.deepCopy(); changed.put("calibration_scope", "STRICT");
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> hybridService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
    }

    @Test
    void hybridStrictTrainingRequiresReturnedIndependentProofAndBothGenuineComponentFits() throws Exception {
        var json = new ObjectMapper(); var policy = UebaTestPolicies.sessionEndpoint(json);
        var catalog = Mockito.mock(UebaExperimentCatalog.class);
        var strictService = new SiemUebaModelService(worker, windows, jobs, events, audit, catalog, json);
        LocalDateTime from = LocalDateTime.of(2026, 1, 1, 0, 0), to = from.plusDays(32);
        String canonical = "{\"config\":{\"l2_regularization\":1,\"max_iter\":200,\"max_leaf_nodes\":31,\"random_state\":42},\"model_kind\":\"normal_plus_incident_research\",\"recipe_version\":1}";
        String recipeSha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        var labeled = new UebaExperimentCatalog.HybridTrainingReference("labels-fold3", "8".repeat(64), 81500,
                Map.of("0", 71500, "1", 8000, "2", 2000), "f".repeat(64), "4".repeat(64));
        var proof = new UebaExperimentCatalog.HybridStrictReference("7".repeat(64), "6".repeat(64),
                Map.of("1", "1".repeat(64), "2", "2".repeat(64), "3", labeled.manifestSha256()), 45);
        var reference = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("hybrid-owned-strict", "hybrid-owned-data",
                "DEMO_ONLY", 4, 50000, 2000000, from, to, 360), "d".repeat(64), policy.path("policy_sha256").asText(), "STRICT",
                "f".repeat(64), "f".repeat(64), "c".repeat(64), "e".repeat(64), "b".repeat(64), UebaExperimentCatalog.HYBRID_MODEL_KIND,
                1, recipeSha, UebaExperimentCatalog.HYBRID_STATE_FORMAT, labeled, proof);
        when(catalog.strictRecipeOrNull(reference.descriptor().recipeId())).thenReturn(reference);
        when(worker.startCatalogTraining(anyString(), anyString())).thenAnswer(invocation -> new SiemUebaGateway.TrainingJob("4".repeat(32), "QUEUED", invocation.getArgument(0)));
        assertThatThrownBy(() -> strictService.startTraining(new SiemDtos.StartUebaTraining(from, to, reference.descriptor().recipeId()), auth("SOC L1"))).isInstanceOf(AccessDeniedException.class);
        strictService.startTraining(new SiemDtos.StartUebaTraining(from, to, reference.descriptor().recipeId()), auth("Quan tri vien"));
        ArgumentCaptor<SiemUebaModelJob> captured = ArgumentCaptor.forClass(SiemUebaModelJob.class); verify(jobs).save(captured.capture()); var job = captured.getValue();
        verify(worker).startCatalogTraining(anyString(), Mockito.eq(reference.descriptor().recipeId())); verifyNoInteractions(windows, events);
        when(jobs.findById(job.getId())).thenReturn(Optional.of(job));
        var metadata = json.createObjectNode().put("sha256", "a".repeat(64)).put("feature_schema_version", 4).put("training_windows", 50000).put("calibration_windows", 2000000)
                .put("data_provenance", "DEMO_ONLY").put("calibration_scope", "STRICT").put("dataset_manifest_sha256", reference.manifestSha256())
                .put("model_kind", reference.modelKind()).put("recipe_version", 1).put("recipe_sha256", recipeSha)
                .put("model_state_format", reference.modelStateFormat()).put("model_state_sha256", reference.expectedModelStateSha256()).put("model_state_verifier_sha256", reference.modelStateVerifierSha256())
                .put("calibration_sha256", reference.expectedCalibrationSha256()).put("selected_reference_model_sha256", reference.expectedModelSha256())
                .put("labeled_training_artifact_id", labeled.artifactId()).put("labeled_training_manifest_sha256", labeled.manifestSha256()).put("labeled_training_windows", labeled.labeledWindows())
                .put("scope", "FULL_STRICT_SOURCE").put("fold", 3).put("normal_fit_split_sha256", labeled.normalFitSplitSha256()).put("labeled_training_split_sha256", labeled.labeledTrainingSplitSha256())
                .put("strict_proof_sha256", proof.proofSha256()).put("confirmed_attack_target_available", false);
        metadata.set("score_policy", policy); metadata.set("model_config", json.readTree(canonical).path("config")); metadata.set("labeled_class_windows", json.valueToTree(labeled.classWindows()));
        metadata.putObject("actual_component_fit_counts").put("normal_component_fit_calls", 1).put("labeled_component_fit_calls", 1);
        var summary = metadata.putObject("hybrid_strict_proof").put("format", "HYBRID_STRICT_PROOF_V1").put("proof_sha256", proof.proofSha256()).put("selection_sha256", proof.selectionSha256())
                .put("actual_composite_trials", 360).put("actual_component_fit_calls", 720).put("validation_runs", 360).put("zero_fit_recalibrations", 45);
        var sources = summary.putObject("source_label_manifests");
        proof.sourceManifestSha256ByFold().forEach((fold, sha) -> sources.putObject(fold).put("artifact_id", "labels-fold" + fold).put("manifest_sha256", sha));
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), metadata));
        strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"));
        assertThat(job.getModelSha256()).isEqualTo("a".repeat(64)).isNotEqualTo(reference.expectedModelSha256());
        for (String name : List.of("strict_proof_sha256", "hybrid_strict_proof", "actual_component_fit_counts", "scope", "fold", "normal_fit_split_sha256",
                "labeled_training_split_sha256", "confirmed_attack_target_available", "selected_reference_model_sha256", "model_state_format")) {
            var changed = metadata.deepCopy(); changed.remove(name);
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
        for (String name : List.of("actual_composite_trials", "actual_component_fit_calls", "validation_runs", "zero_fit_recalibrations")) {
            var changed = metadata.deepCopy(); changed.withObject("/hybrid_strict_proof").put(name, 1);
            when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
            assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
        }
        var changed = metadata.deepCopy(); changed.withObject("/actual_component_fit_counts").put("labeled_component_fit_calls", true);
        when(worker.trainingJob(job.getWorkerJobId())).thenReturn(new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), changed));
        assertThatThrownBy(() -> strictService.refreshTrainingJob(job.getId(), auth("Quan tri vien"))).isInstanceOf(ConflictException.class);
    }
}
