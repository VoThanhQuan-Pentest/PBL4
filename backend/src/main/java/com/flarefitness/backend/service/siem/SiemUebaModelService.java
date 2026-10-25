package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemUebaModelJob;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import java.util.concurrent.atomic.AtomicBoolean;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Admin-owned lifecycle; training data is selected server-side, never uploaded by a client. */
@Service
public class SiemUebaModelService {
    private final SiemUebaGateway worker;
    private final SiemAccountBehaviorWindowRepository windows;
    private final SiemUebaModelJobRepository jobs;
    private final SiemSecurityEventRepository events;
    private final AuditLogService audit;
    private final UebaExperimentCatalog catalog;
    private final ObjectMapper json;
    private final AtomicBoolean activationPolling = new AtomicBoolean();

    public SiemUebaModelService(SiemUebaGateway worker, SiemAccountBehaviorWindowRepository windows,
                                SiemUebaModelJobRepository jobs, SiemSecurityEventRepository events,
                                AuditLogService audit) {
        this(worker, windows, jobs, events, audit,
                new UebaExperimentCatalog("/run/ueba-catalog", new ObjectMapper()), new ObjectMapper());
    }

    @Autowired
    public SiemUebaModelService(SiemUebaGateway worker, SiemAccountBehaviorWindowRepository windows,
                                SiemUebaModelJobRepository jobs, SiemSecurityEventRepository events,
                                AuditLogService audit, UebaExperimentCatalog catalog, ObjectMapper json) {
        this.worker = worker;
        this.windows = windows;
        this.jobs = jobs;
        this.events = events;
        this.audit = audit;
        this.catalog = catalog;
        this.json = json;
    }

    public List<SiemDtos.UebaRecipe> recipes(Authentication authentication) {
        requireAdmin(authentication);
        return catalog.recipes();
    }

    public SiemDtos.UebaStatus status() {
        SiemUebaGateway.WorkerHealth health = worker.health();
        String provenance = health.modelAvailable() && health.activeModelVersion() != null
                ? jobs.findByModelVersion(health.activeModelVersion())
                        .map(SiemUebaModelJob::getDataProvenance).orElse("UNKNOWN")
                : null;
        return new SiemDtos.UebaStatus(health.workerAvailable(), health.modelAvailable(),
                health.activeModelVersion(), provenance, health.reason(), health.featureSchemaVersion(),
                AccountBehaviorFeatures.names(health.featureSchemaVersion()), events.countByAggregatedAtIsNull(),
                events.countByExportedAtIsNull(), windows.countByScoreStatus(BehaviorScoreStatus.PENDING));
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.UebaTrainingJob> listTrainingJobs(int page, int size,
                                                                   Authentication authentication) {
        requireAdmin(authentication);
        if (page < 0 || size < 1 || size > 50) {
            throw new BadRequestException("Invalid UEBA training job page.");
        }
        return PageResponse.from(jobs.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size)).map(this::toDto));
    }

    @Transactional
    public SiemDtos.UebaTrainingJob startTraining(SiemDtos.StartUebaTraining request,
                                                   Authentication authentication) {
        String actorId = requireAdmin(authentication);
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        if (request.recipeId() != null && !"legacy-v1".equals(request.recipeId())) {
            UebaExperimentCatalog.StrictReference strict = catalog.strictRecipeOrNull(request.recipeId());
            if (strict != null) return startCatalogTraining(request, strict, actorId, now);
        }
        if (request.from() == null || request.to() == null || !request.from().isBefore(request.to())
                || request.to().isAfter(now.minusMinutes(15))
                || Duration.between(request.from(), request.to()).compareTo(Duration.ofDays(30)) > 0) {
            throw new BadRequestException("Training range must be past, ordered and no longer than 30 days.");
        }
        if (request.recipeId() != null && !"legacy-v1".equals(request.recipeId())) {
            return startRecipeTraining(request, actorId, now);
        }
        List<SiemAccountBehaviorWindow> eligible = eligibleWindows(request.from(), request.to());
        if (eligible.size() < 600) {
            throw new BadRequestException("At least 600 normal behavior windows are required.");
        }
        Set<String> accounts = new HashSet<>();
        eligible.forEach(window -> accounts.add(window.getAccountId()));
        if (accounts.size() < 3) {
            throw new BadRequestException("Training requires normal windows from at least three accounts.");
        }

        int calibrationCount = Math.min(10_000, Math.min(eligible.size() - 500,
                Math.max(100, eligible.size() / 5)));
        int trainingCount = Math.min(50_000, eligible.size() - calibrationCount);
        List<List<Double>> training = eligible.subList(0, trainingCount).stream()
                .map(SiemAccountBehaviorWindow::featureVector).toList();
        List<List<Double>> calibration = eligible.subList(trainingCount,
                trainingCount + calibrationCount).stream()
                .map(SiemAccountBehaviorWindow::featureVector).toList();
        String modelVersion = "model-" + DateTimeFormatter.ofPattern("yyyyMMddHHmmss").format(now)
                + "-" + UUID.randomUUID().toString().substring(0, 8);
        SiemUebaGateway.TrainingJob started = worker.startTraining(modelVersion, training, calibration);
        SiemUebaModelJob job = new SiemUebaModelJob();
        job.setId("ueba-job-" + UUID.randomUUID());
        job.setWorkerJobId(started.jobId());
        job.setModelVersion(modelVersion);
        job.setRequestedByUserId(actorId);
        job.setTrainingFrom(request.from());
        job.setTrainingTo(request.to());
        job.setTrainingWindows(trainingCount);
        job.setCalibrationWindows(calibrationCount);
        job.setStatus(started.status());
        long demoCount = eligible.stream().filter(window -> "NORMAL".equals(window.getDemoLabel())).count();
        job.setDataProvenance(demoCount == eligible.size() ? "DEMO_ONLY"
                : demoCount == 0 ? "REAL_ONLY" : "MIXED");
        job.setCreatedAt(now);
        job.setUpdatedAt(now);
        jobs.save(job);
        audit.success("SIEM_UEBA_TRAINING_STARTED", actorId, null, "UEBA_MODEL", modelVersion);
        return toDto(job);
    }

    private SiemDtos.UebaTrainingJob startRecipeTraining(SiemDtos.StartUebaTraining request, String actorId, LocalDateTime now) {
        UebaExperimentCatalog.Dataset dataset = catalog.recipe(request.recipeId());
        if (!request.from().equals(dataset.descriptor().from()) || !request.to().equals(dataset.descriptor().to())) {
            throw new BadRequestException("Training range must match the registered frozen recipe.");
        }
        String modelVersion = newVersion(now);
        SiemUebaGateway.TrainingJob started = worker.startTraining(modelVersion,
                dataset.fit().stream().map(UebaExperimentCatalog.Row::features).toList(),
                dataset.calibration().stream().map(UebaExperimentCatalog.Row::features).toList(), 2, dataset.config());
        SiemUebaModelJob job = new SiemUebaModelJob();
        job.setId("ueba-job-" + UUID.randomUUID());
        job.setWorkerJobId(started.jobId()); job.setModelVersion(modelVersion); job.setRequestedByUserId(actorId);
        job.setTrainingFrom(request.from()); job.setTrainingTo(request.to());
        job.setTrainingWindows(dataset.fit().size()); job.setCalibrationWindows(dataset.calibration().size());
        job.setStatus(started.status()); job.setDataProvenance("DEMO_ONLY"); job.setFeatureSchemaVersion(dataset.descriptor().featureSchemaVersion());
        job.setRecipeId(dataset.descriptor().recipeId()); job.setDatasetId(dataset.descriptor().datasetId());
        job.setDatasetManifestSha256(dataset.manifestSha256()); job.setCreatedAt(now); job.setUpdatedAt(now);
        jobs.save(job);
        audit.success("SIEM_UEBA_TRAINING_STARTED", actorId, null, "UEBA_MODEL", modelVersion);
        return toDto(job);
    }

    private SiemDtos.UebaTrainingJob startCatalogTraining(SiemDtos.StartUebaTraining request, UebaExperimentCatalog.StrictReference recipe,
                                                          String actorId, LocalDateTime now) {
        if (!recipe.descriptor().from().equals(request.from()) || !recipe.descriptor().to().equals(request.to())) {
            throw new BadRequestException("Training range must match the registered frozen sharded recipe.");
        }
        String version = newVersion(now);
        SiemUebaGateway.TrainingJob started = worker.startCatalogTraining(version, recipe.descriptor().recipeId());
        SiemUebaModelJob job = new SiemUebaModelJob();
        job.setId("ueba-job-" + UUID.randomUUID()); job.setWorkerJobId(started.jobId()); job.setModelVersion(version);
        job.setRequestedByUserId(actorId); job.setTrainingFrom(request.from()); job.setTrainingTo(request.to());
        job.setTrainingWindows(recipe.descriptor().trainingWindows()); job.setCalibrationWindows(recipe.descriptor().calibrationWindows());
        job.setStatus(started.status()); job.setDataProvenance("DEMO_ONLY"); job.setFeatureSchemaVersion(recipe.descriptor().featureSchemaVersion());
        job.setRecipeId(recipe.descriptor().recipeId()); job.setDatasetId(recipe.descriptor().datasetId());
        job.setDatasetManifestSha256(recipe.manifestSha256()); job.setCreatedAt(now); job.setUpdatedAt(now);
        job.setEvaluationSummaryJson(encode(Map.of("score_policy_sha256", recipe.policySha256(), "catalogue_mode", recipe.mode(),
                "dataset_manifest_sha256", recipe.manifestSha256(), "quality_gate", "NOT_RUN")));
        jobs.save(job); audit.success("SIEM_UEBA_TRAINING_STARTED", actorId, null, "UEBA_MODEL", version);
        return toDto(job);
    }

    /** Register an offline selected candidate after worker-side artifact/journal verification. */
    @Transactional
    public SiemDtos.UebaTrainingJob adoptQualifiedCandidate(com.fasterxml.jackson.databind.JsonNode packageProof,
                                                              Authentication authentication) {
        String actorId = requireAdmin(authentication);
        if (packageProof == null) throw new BadRequestException("Candidate adoption package is required.");
        String modelVersion = packageProof.path("model_version").asText();
        if (!"UEBA_QUALIFIED_ADOPTION_PACKAGE_V1".equals(packageProof.path("format").asText())
                || !"READY".equals(packageProof.path("status").asText())
                || !"DEMO_ONLY".equals(packageProof.path("data_provenance").asText())
                || !"PASS".equals(packageProof.path("quality_gate").asText())
                || !exactInteger(packageProof.path("feature_schema_version"), 4)) {
            throw new BadRequestException("Invalid worker-verified candidate adoption package.");
        }
        var existing = jobs.lockedByModelVersion(modelVersion);
        if (existing.isPresent()) {
            Map<String, Object> prior = summary(existing.get());
            SiemUebaGateway.QualifiedCandidate known = worker.qualifiedCandidate(modelVersion);
            if ("OPERATOR_ADOPTED".equals(prior.get("execution_origin"))
                    && known.adoptionReceiptSha256().equals(prior.get("adoption_receipt_sha256"))) return toDto(existing.get());
            throw new ConflictException("Candidate version is already registered with a different origin or receipt.");
        }
        SiemUebaGateway.QualifiedCandidate candidate = worker.qualifiedCandidate(modelVersion);
        String adoptionReceiptSha256 = candidate.adoptionReceiptSha256();
        var adoption = candidate.adoptionReceipt();
        if (!modelVersion.equals(packageProof.path("model_version").asText())
                || !candidate.metadata().path("sha256").asText().equals(packageProof.path("model_sha256").asText())
                || !candidate.metadata().path("dataset_manifest_sha256").asText().equals(packageProof.path("original_training_manifest_sha256").asText())
                || !adoption.path("selection_receipt_sha256").asText().equals(packageProof.path("selection_receipt_sha256").asText())
                || !adoption.path("fresh_holdout_manifest_sha256").asText().equals(packageProof.path("fresh_holdout_manifest_sha256").asText())
                || !adoption.path("holdout_split_sha256").asText().equals(packageProof.path("holdout_split_sha256").asText())
                || !adoption.path("recipe_id").asText().equals(packageProof.path("recipe_id").asText())
                || !adoption.path("strict_reference").equals(packageProof.path("strict_reference"))
                || !adoption.path("selection_proof").equals(packageProof.path("selection_proof"))
                || !adoption.path("artifact_sha256").equals(packageProof.path("artifact_sha256"))) {
            throw new ConflictException("Candidate package does not match installed proof and artifact hashes.");
        }
        UebaExperimentCatalog.StrictReference recipe = UebaStrictEvaluation.recoveredReference(adoption);
        String recipeId = recipe.descriptor().recipeId();
        if (!recipe.descriptor().datasetId().equals(adoption.path("original_dataset_id").asText())
                || !recipe.manifestSha256().equals(adoption.path("original_training_manifest_sha256").asText())) {
            throw new ConflictException("Recovered strict reference differs from the original training identity.");
        }
        var candidateEvidence = json.createObjectNode();
        candidateEvidence.put("status", "QUALIFIED");
        candidateEvidence.put("model_version", candidate.modelVersion());
        candidateEvidence.put("adoption_receipt_sha256", candidate.adoptionReceiptSha256());
        candidateEvidence.set("adoption_receipt", candidate.adoptionReceipt());
        candidateEvidence.set("metadata", candidate.metadata());
        candidateEvidence.set("evaluation", candidate.evaluation());
        candidateEvidence.set("evaluation_identity", candidate.evaluationIdentity());
        Map<String, Object> evaluation = UebaStrictEvaluation.validateRecovered(json, candidateEvidence,
                modelVersion, recipe, adoptionReceiptSha256);
        if (!"PASS".equals(evaluation.get("quality_gate"))) {
            throw new ConflictException("Fresh holdout candidate does not pass both strict evaluation scopes.");
        }

        SiemUebaGateway.TrainingJob adoptionJob = worker.registerQualifiedAdoption(modelVersion, adoptionReceiptSha256);
        if (!"SUCCEEDED".equals(adoptionJob.status()) || !modelVersion.equals(adoptionJob.modelVersion())) {
            throw new ConflictException("Worker did not persist the qualified candidate adoption receipt.");
        }
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemUebaModelJob job = new SiemUebaModelJob();
        job.setId("ueba-job-" + UUID.randomUUID());
        job.setWorkerJobId(adoptionJob.jobId());
        job.setModelVersion(modelVersion);
        job.setRequestedByUserId(actorId);
        job.setTrainingFrom(recipe.descriptor().from());
        job.setTrainingTo(recipe.descriptor().to());
        job.setTrainingWindows(recipe.descriptor().trainingWindows());
        job.setCalibrationWindows(recipe.descriptor().calibrationWindows());
        job.setStatus("SUCCEEDED");
        job.setDataProvenance("DEMO_ONLY");
        job.setFeatureSchemaVersion(recipe.descriptor().featureSchemaVersion());
        job.setRecipeId(recipeId);
        job.setDatasetId(recipe.descriptor().datasetId());
        job.setDatasetManifestSha256(recipe.manifestSha256());
        job.setModelSha256(candidate.metadata().path("sha256").asText());
        job.setEvaluationDatasetId(adoption.path("fresh_holdout_dataset_id").asText());
        job.setEvaluationDatasetSha256(adoption.path("holdout_split_sha256").asText());
        job.setEvaluationStatus("SUCCEEDED");
        job.setQualityGate("PASS");
        evaluation.put("execution_origin", "OPERATOR_ADOPTED");
        evaluation.put("adoption_receipt_sha256", adoptionReceiptSha256);
        evaluation.put("fresh_holdout_manifest_sha256", adoption.path("fresh_holdout_manifest_sha256").asText());
        evaluation.put("fresh_holdout_split_sha256", adoption.path("holdout_split_sha256").asText());
        evaluation.put("strict_reference", json.convertValue(adoption.path("strict_reference"), Object.class));
        evaluation.put("shadow_gate", "NOT_RUN");
        job.setEvaluationSummaryJson(encode(evaluation));
        job.setCreatedAt(now);
        job.setUpdatedAt(now);
        jobs.save(job);
        audit.success("SIEM_UEBA_CANDIDATE_ADOPTED", actorId, null, "UEBA_MODEL", modelVersion);
        return toDto(job);
    }

    @Transactional
    public SiemDtos.UebaTrainingJob refreshTrainingJob(String jobId, Authentication authentication) {
        requireAdmin(authentication);
        SiemUebaModelJob job = jobs.findById(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("UEBA training job not found."));
        SiemUebaGateway.TrainingJob workerJob = worker.trainingJob(job.getWorkerJobId());
        if (!job.getModelVersion().equals(workerJob.modelVersion())) {
            throw new IllegalStateException("UEBA worker returned a different model version.");
        }
        recordTrainingMetadata(job, workerJob);
        if ("SUCCEEDED".equals(workerJob.status())) {
            if (!Set.of("ACTIVE", "RETIRED", "ACTIVATION_QUEUED", "ACTIVATING").contains(job.getStatus())) job.setStatus("SUCCEEDED");
        } else job.setStatus(workerJob.status());
        refreshEvaluation(job);
        job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        jobs.save(job);
        return toDto(job);
    }

    @Transactional
    public SiemDtos.UebaTrainingJob evaluate(String modelVersion, SiemDtos.EvaluateUebaModel request,
                                             Authentication authentication) {
        String actor = requireAdmin(authentication);
        SiemUebaModelJob job = jobs.lockedByModelVersion(modelVersion)
                .orElseThrow(() -> new ResourceNotFoundException("UEBA model not found."));
        if (!"NOT_RUN".equals(job.getEvaluationStatus())) throw new ConflictException("Candidate evaluation is already queued or frozen.");
        SiemUebaGateway.TrainingJob trained = worker.trainingJob(job.getWorkerJobId());
        if (!"SUCCEEDED".equals(trained.status()) || !modelVersion.equals(trained.modelVersion())) {
            throw new ConflictException("Only a successful candidate can be evaluated.");
        }
        recordTrainingMetadata(job, trained);
        if (job.getModelSha256() == null) throw new ConflictException("Candidate artifact metadata is unavailable.");
        String id = request.datasetId() == null ? job.getDatasetId() : request.datasetId();
        UebaExperimentCatalog.StrictReference strict = registered(job);
        if (strict != null) {
            if (!"STRICT".equals(strict.mode())) throw new ConflictException("Preview candidate cannot consume the strict holdout.");
            if (!strict.descriptor().datasetId().equals(id) || !strict.manifestSha256().equals(job.getDatasetManifestSha256())) {
                throw new ConflictException("Candidate and registered strict evaluation dataset differ.");
            }
            SiemUebaGateway.TrainingJob evaluation = worker.startCatalogEvaluation(modelVersion, strict.descriptor().recipeId());
            job.setEvaluationWorkerJobId(evaluation.jobId()); job.setEvaluationDatasetId(id);
            job.setEvaluationDatasetSha256(strict.holdoutSplitSha256()); job.setEvaluationStatus(evaluation.status()); job.setQualityGate("NOT_RUN");
            Map<String, Object> binding = new java.util.HashMap<>(summary(job));
            binding.put("catalogue_mode", "STRICT"); binding.put("frozen_holdout_split_sha256", strict.holdoutSplitSha256());
            job.setEvaluationSummaryJson(encode(binding)); job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC)); jobs.save(job);
            audit.success("SIEM_UEBA_STRICT_EVALUATION_STARTED", actor, null, "UEBA_MODEL", modelVersion);
            return toDto(job);
        }
        UebaExperimentCatalog.Dataset dataset = catalog.evaluation(id);
        if (job.getDatasetId() != null && (!job.getDatasetId().equals(id)
                || !dataset.manifestSha256().equals(job.getDatasetManifestSha256()))) {
            throw new ConflictException("Candidate training and evaluation recipe identities differ.");
        }
        int normal = (int) dataset.holdout().stream().filter(row -> row.label() == 0).count();
        int positive = dataset.holdout().size() - normal;
        if (normal < 10000 || positive < 1000) throw new BadRequestException("Insufficient frozen holdout population.");
        Map<String, Object> binding = Map.of("dataset_manifest_sha256", dataset.manifestSha256(),
                "frozen_holdout_split_sha256", dataset.holdoutSplitSha256(), "expected_normal", normal, "expected_positive", positive);
        SiemUebaGateway.TrainingJob evaluation = worker.startEvaluation(modelVersion, dataset, job.getFeatureSchemaVersion());
        job.setEvaluationWorkerJobId(evaluation.jobId()); job.setEvaluationDatasetId(id);
        job.setEvaluationDatasetSha256(dataset.payloadSha256(job.getFeatureSchemaVersion()));
        job.setEvaluationStatus(evaluation.status()); job.setQualityGate("NOT_RUN");
        job.setEvaluationSummaryJson(encode(binding)); job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        jobs.save(job);
        audit.success("SIEM_UEBA_EVALUATION_STARTED", actor, null, "UEBA_MODEL", modelVersion);
        return toDto(job);
    }

    private void refreshEvaluation(SiemUebaModelJob job) {
        if (job.getEvaluationWorkerJobId() == null || !Set.of("QUEUED", "RUNNING").contains(job.getEvaluationStatus())) return;
        SiemUebaGateway.TrainingJob result = worker.trainingJob(job.getEvaluationWorkerJobId());
        if (!job.getModelVersion().equals(result.modelVersion())) throw new ConflictException("Evaluation model identity changed.");
        if ("SUCCEEDED".equals(result.status())) {
            UebaExperimentCatalog.StrictReference strict = registered(job);
            if (strict != null) {
                if (!"STRICT".equals(strict.mode()) || !strict.holdoutSplitSha256().equals(job.getEvaluationDatasetSha256())) {
                    throw new ConflictException("Frozen strict evaluation binding changed.");
                }
                var metrics = worker.validateStrictEvaluation(result.metadata(), job.getModelVersion(), job.getModelSha256(), strict);
                job.setEvaluationSummaryJson(encode(metrics)); job.setQualityGate((String) metrics.get("quality_gate"));
                job.setEvaluationStatus("SUCCEEDED"); return;
            }
            Map<String, Object> binding = summary(job);
            var metrics = worker.validateEvaluation(result.metadata(), job.getModelVersion(), job.getModelSha256(),
                    job.getEvaluationDatasetSha256(), job.getFeatureSchemaVersion(),
                    ((Number) binding.get("expected_normal")).intValue(), ((Number) binding.get("expected_positive")).intValue());
            metrics.put("dataset_manifest_sha256", binding.get("dataset_manifest_sha256"));
            metrics.put("frozen_holdout_split_sha256", binding.get("frozen_holdout_split_sha256"));
            metrics.put("dataset_id", job.getEvaluationDatasetId());
            job.setEvaluationSummaryJson(encode(metrics)); job.setQualityGate((String) metrics.get("quality_gate"));
        } else if (Set.of("FAILED", "INTERRUPTED").contains(result.status())) job.setQualityGate("FAIL");
        job.setEvaluationStatus(result.status());
    }

    private boolean operatorAdopted(SiemUebaModelJob job) {
        return "OPERATOR_ADOPTED".equals(summary(job).get("execution_origin"));
    }

    private UebaExperimentCatalog.StrictReference recoveredReferenceFromSummary(Map<String, Object> state) {
        var wrapper = json.createObjectNode();
        wrapper.set("strict_reference", json.valueToTree(state.get("strict_reference")));
        return UebaStrictEvaluation.recoveredReference(wrapper);
    }

    private Map<String, Object> recordAdoptedCandidate(SiemUebaModelJob job) {
        Map<String, Object> prior = summary(job);
        Object receiptValue = prior.get("adoption_receipt_sha256");
        if (!(receiptValue instanceof String receiptSha) || !receiptSha.matches("[a-f0-9]{64}")) {
            throw new ConflictException("Operator adoption receipt identity is missing.");
        }
        SiemUebaGateway.QualifiedCandidate candidate = worker.qualifiedCandidate(job.getModelVersion());
        if (!receiptSha.equals(candidate.adoptionReceiptSha256())
                || !java.util.Objects.equals(job.getModelSha256(), candidate.metadata().path("sha256").asText())
                || !java.util.Objects.equals(job.getDatasetManifestSha256(), candidate.metadata().path("dataset_manifest_sha256").asText())) {
            throw new ConflictException("Installed adopted candidate or original training identity changed.");
        }
        UebaExperimentCatalog.StrictReference recipe = UebaStrictEvaluation.recoveredReference(candidate.adoptionReceipt());
        var evidence = json.createObjectNode();
        evidence.put("status", "QUALIFIED"); evidence.put("model_version", candidate.modelVersion());
        evidence.put("adoption_receipt_sha256", candidate.adoptionReceiptSha256());
        evidence.set("adoption_receipt", candidate.adoptionReceipt()); evidence.set("metadata", candidate.metadata());
        evidence.set("evaluation", candidate.evaluation()); evidence.set("evaluation_identity", candidate.evaluationIdentity());
        Map<String, Object> verified = UebaStrictEvaluation.validateRecovered(json, evidence,
                job.getModelVersion(), recipe, receiptSha);
        if (!"PASS".equals(verified.get("quality_gate"))
                || !java.util.Objects.equals(job.getEvaluationDatasetSha256(), verified.get("frozen_holdout_split_sha256"))
                || !java.util.Objects.equals(job.getEvaluationDatasetId(), verified.get("dataset_id"))) {
            throw new ConflictException("Adopted candidate fresh evaluation failed backend revalidation.");
        }
        verified.put("execution_origin", "OPERATOR_ADOPTED");
        verified.put("adoption_receipt_sha256", receiptSha);
        verified.put("fresh_holdout_manifest_sha256", candidate.adoptionReceipt().path("fresh_holdout_manifest_sha256").asText());
        verified.put("fresh_holdout_split_sha256", candidate.adoptionReceipt().path("holdout_split_sha256").asText());
        verified.put("strict_reference", json.convertValue(candidate.adoptionReceipt().path("strict_reference"), Object.class));
        verified.put("shadow_gate", prior.getOrDefault("shadow_gate", "NOT_RUN"));
        job.setQualityGate("PASS"); job.setEvaluationStatus("SUCCEEDED");
        job.setEvaluationSummaryJson(encode(verified));
        return verified;
    }

    private void recordTrainingMetadata(SiemUebaModelJob job, SiemUebaGateway.TrainingJob result) {
        if (!job.getModelVersion().equals(result.modelVersion())) throw new ConflictException("Training model identity changed.");
        if (operatorAdopted(job)) {
            if (!"SUCCEEDED".equals(result.status())) throw new ConflictException("Adopted candidate receipt is no longer successful.");
            recordAdoptedCandidate(job);
            return;
        }
        if (!"SUCCEEDED".equals(result.status()) || result.metadata() == null || result.metadata().isMissingNode()) return;
        var meta = result.metadata();
        String checksum = meta.path("sha256").asText();
        if (!checksum.matches("[a-f0-9]{64}") || meta.path("feature_schema_version").asInt() != job.getFeatureSchemaVersion()
                || meta.path("training_windows").asInt() != job.getTrainingWindows()
                || meta.path("calibration_windows").asInt() != job.getCalibrationWindows()) {
            throw new ConflictException("Candidate artifact metadata does not match the training job.");
        }
        if (job.getModelSha256() != null && !job.getModelSha256().equals(checksum)) throw new ConflictException("Candidate artifact changed.");
        UebaExperimentCatalog.StrictReference recipe = job.getRecipeId() == null || "legacy-v1".equals(job.getRecipeId())
                ? null : catalog.strictRecipeOrNull(job.getRecipeId());
        if (recipe != null) {
            UebaExperimentCatalog.RecipeIdentity identity;
            try { identity = UebaExperimentCatalog.recipeIdentity(meta); }
            catch (RuntimeException failure) { throw new ConflictException("Candidate model recipe identity is invalid."); }
            if (!recipe.modelKind().equals(identity.modelKind()) || recipe.recipeVersion() != identity.recipeVersion()
                    || !java.util.Objects.equals(recipe.recipeSha256(), identity.recipeSha256())) {
                throw new ConflictException("Candidate model kind or recipe differs from its registered recipe.");
            }
            UebaScorePolicy policy;
            try { policy = UebaScorePolicy.fromWire(meta.path("score_policy"), job.getFeatureSchemaVersion()); }
            catch (IllegalArgumentException failure) { throw new ConflictException("Candidate score policy is invalid."); }
            String expectedScope = "STRICT".equals(recipe.mode()) ? "STRICT" : "PILOT_ONLY";
            if (!recipe.policySha256().equals(policy.sha256()) || !recipe.manifestSha256().equals(meta.path("dataset_manifest_sha256").asText())
                    || !expectedScope.equals(meta.path("calibration_scope").asText())) {
                throw new ConflictException("Candidate policy, calibration scope or dataset differs from its registered recipe.");
            }
            if (UebaExperimentCatalog.HYBRID_MODEL_KIND.equals(recipe.modelKind())) {
                try { UebaExperimentCatalog.validateRecipeConfig(json, meta.path("model_config"), identity); }
                catch (RuntimeException failure) { throw new ConflictException("Hybrid candidate scalar recipe is invalid or changed."); }
                var labeled = recipe.labeledTraining();
                if (!java.util.Set.of("PILOT", "STRICT").contains(recipe.mode()) || job.getFeatureSchemaVersion() != 4 || labeled == null
                        || !exactInteger(meta.path("feature_schema_version"), 4)
                        || !"DEMO_ONLY".equals(meta.path("data_provenance").asText())
                        || !UebaExperimentCatalog.HYBRID_STATE_FORMAT.equals(meta.path("model_state_format").asText())
                        || !hexHash(meta.path("sha256")) || !hexHash(meta.path("model_state_sha256"))
                        || !hexHash(meta.path("model_state_verifier_sha256")) || !hexHash(meta.path("calibration_sha256"))
                        || !meta.path("labeled_training_artifact_id").isTextual() || !meta.path("labeled_training_manifest_sha256").isTextual()
                        || !labeled.artifactId().equals(meta.path("labeled_training_artifact_id").asText())
                        || !labeled.manifestSha256().equals(meta.path("labeled_training_manifest_sha256").asText())
                        || !exactInteger(meta.path("training_windows"), job.getTrainingWindows())
                        || !exactInteger(meta.path("calibration_windows"), job.getCalibrationWindows())
                        || !exactInteger(meta.path("labeled_training_windows"), labeled.labeledWindows())
                        || !meta.path("labeled_class_windows").isObject() || meta.path("labeled_class_windows").size() != 3) {
                    throw new ConflictException("Hybrid candidate lacks its protected independent training/state proof.");
                }
                for (var target : labeled.classWindows().entrySet()) {
                    if (!exactInteger(meta.path("labeled_class_windows").path(target.getKey()), target.getValue())) {
                        throw new ConflictException("Hybrid candidate labeled context populations changed.");
                    }
                }
                if ("STRICT".equals(recipe.mode()) && (recipe.strictProof() == null
                        || !hexHash(meta.path("strict_proof_sha256")) || !recipe.strictProof().proofSha256().equals(meta.path("strict_proof_sha256").asText())
                        || !UebaExperimentCatalog.matchesHybridStrictProof(meta.path("hybrid_strict_proof"), recipe)
                        || !exactInteger(meta.path("fold"), 3) || !exactInteger(meta.path("model_config").path("random_state"), 42)
                        || !"FULL_STRICT_SOURCE".equals(meta.path("scope").asText())
                        || !hexHash(meta.path("normal_fit_split_sha256")) || !java.util.Objects.equals(labeled.normalFitSplitSha256(), meta.path("normal_fit_split_sha256").asText())
                        || !hexHash(meta.path("labeled_training_split_sha256")) || !java.util.Objects.equals(labeled.labeledTrainingSplitSha256(), meta.path("labeled_training_split_sha256").asText())
                        || !meta.path("confirmed_attack_target_available").isBoolean() || meta.path("confirmed_attack_target_available").asBoolean()
                        || !meta.path("actual_component_fit_counts").isObject() || meta.path("actual_component_fit_counts").size() != 2
                        || !exactInteger(meta.path("actual_component_fit_counts").path("normal_component_fit_calls"), 1)
                        || !exactInteger(meta.path("actual_component_fit_counts").path("labeled_component_fit_calls"), 1))) {
                    throw new ConflictException("Hybrid strict candidate differs from its frozen independent source/proof.");
                }
            }
            // The selected reference keeps its immutable binary SHA. A genuine
            // refit has its own binary SHA (stored below) and must reproduce all
            // numeric state; non-semantic C-struct padding can change pickle bytes.
            if ("STRICT".equals(recipe.mode()) && (!recipe.expectedModelSha256().equals(meta.path("selected_reference_model_sha256").asText())
                    || !java.util.Objects.equals(recipe.expectedModelStateSha256(), meta.path("model_state_sha256").asText())
                    || !java.util.Objects.equals(recipe.modelStateVerifierSha256(), meta.path("model_state_verifier_sha256").asText())
                    || !recipe.modelStateFormat().equals(meta.path("model_state_format").asText())
                    || !recipe.expectedCalibrationSha256().equals(meta.path("calibration_sha256").asText()))) {
                throw new ConflictException("Actual worker fit/calibration differs from frozen selection.");
            }
        }
        job.setModelSha256(checksum);
    }

    private static boolean exactInteger(com.fasterxml.jackson.databind.JsonNode value, int expected) {
        return value.isIntegralNumber() && value.canConvertToInt() && value.asInt() == expected;
    }

    private static boolean hexHash(com.fasterxml.jackson.databind.JsonNode value) {
        return value.isTextual() && value.asText().matches("[a-f0-9]{64}");
    }

    @Transactional
    public SiemDtos.UebaTrainingJob activate(String modelVersion, Authentication authentication) {
        String actorId = requireAdmin(authentication);
        SiemUebaModelJob job = jobs.lockedByModelVersion(modelVersion)
                .orElseThrow(() -> new ResourceNotFoundException("UEBA model not found."));
        if (Set.of("QUEUED", "RUNNING").contains(job.getActivationStatus()) || "ACTIVE".equals(job.getStatus())) return toDto(job);
        boolean legacyRestore = "LEGACY_RESTORE".equals(job.getQualityGate()) && job.getActivatedAt() != null
                && job.getFeatureSchemaVersion() == 1;
        if (!legacyRestore && (!"PASS".equals(job.getQualityGate()) || !"SUCCEEDED".equals(job.getEvaluationStatus()))) {
            throw new ConflictException("Candidate must pass the frozen model-only quality gate before activation.");
        }
        SiemUebaGateway.TrainingJob workerJob = worker.trainingJob(job.getWorkerJobId());
        if (!"SUCCEEDED".equals(workerJob.status())
                || !modelVersion.equals(workerJob.modelVersion())) {
            throw new BadRequestException("Only a successful training job can be activated.");
        }
        recordTrainingMetadata(job, workerJob);
        if (!legacyRestore) {
            Map<String, Object> stored = summary(job);
            UebaExperimentCatalog.StrictReference strict = operatorAdopted(job)
                    ? recoveredReferenceFromSummary(stored) : registered(job);
            if (strict != null) {
                if (!"STRICT".equals(strict.mode())) throw new ConflictException("Strict candidate dataset binding changed.");
                if (operatorAdopted(job)) {
                    if (!java.util.Objects.equals(stored.get("fresh_holdout_split_sha256"), job.getEvaluationDatasetSha256())) {
                        throw new ConflictException("Recovered candidate fresh holdout binding changed.");
                    }
                } else {
                    if (!strict.holdoutSplitSha256().equals(job.getEvaluationDatasetSha256())) {
                        throw new ConflictException("Strict candidate dataset binding changed.");
                    }
                    worker.validateStrictEvaluation(json.valueToTree(stored), modelVersion, job.getModelSha256(), strict);
                }
                if (!"PASS".equals(stored.get("shadow_gate"))) throw new ConflictException("Strict candidate requires a completed real shadow run.");
            } else {
                throw new ConflictException("Legacy metrics cannot qualify a new primary; use a registered strict candidate.");
            }
        }
        // Persist the identity before any submission. Slow journal verification
        // cannot make the remote primary change without an observable job.
        job.setActivationWorkerJobId(UUID.randomUUID().toString().replace("-", ""));
        job.setActivationRequestedByUserId(actorId); job.setActivationStatus("QUEUED");
        job.setStatus("ACTIVATION_QUEUED"); job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC)); jobs.save(job);
        audit.success("SIEM_UEBA_ACTIVATION_REQUESTED", actorId, null, "UEBA_MODEL", modelVersion);
        return toDto(job);
    }

    @Scheduled(initialDelayString = "${siem.ueba.initial-delay-ms:20000}", fixedDelayString = "${siem.ueba.activation-interval-ms:30000}")
    @Transactional
    public void advanceActivations() {
        if (!worker.isEnabled() || !activationPolling.compareAndSet(false, true)) return;
        try {
            for (var job : jobs.findByActivationStatusInOrderByUpdatedAtAsc(List.of("QUEUED", "RUNNING"), PageRequest.of(0, 4))) {
                try {
                    if ("QUEUED".equals(job.getActivationStatus())) {
                        worker.startActivation(job.getModelVersion(), job.getActivationWorkerJobId());
                        job.setActivationStatus("RUNNING"); job.setStatus("ACTIVATING");
                    } else {
                        var result = worker.trainingJob(job.getActivationWorkerJobId());
                        if (!job.getModelVersion().equals(result.modelVersion())) throw new ConflictException("Activation job model identity changed.");
                        if ("SUCCEEDED".equals(result.status())) {
                            if (!job.getModelSha256().equals(result.metadata().path("sha256").asText())) throw new ConflictException("Activation artifact changed.");
                            confirmPrimaryAndFinish(job);
                        } else if ("INTERRUPTED".equals(result.status())) {
                            // Crash after publishing active.json but before writing
                            // SUCCEEDED: reconcile the actual primary, never a guessed PASS.
                            confirmPrimaryAndFinish(job);
                        } else if ("FAILED".equals(result.status())) activationFailed(job, "WORKER_REJECTED");
                    }
                    job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC)); jobs.save(job);
                } catch (RuntimeException unavailable) {
                    Map<String, Object> state = new java.util.HashMap<>(summary(job));
                    state.put("activation_error_type", unavailable.getClass().getSimpleName()); job.setEvaluationSummaryJson(encode(state));
                    if (unavailable instanceof ConflictException) activationFailed(job, "IDENTITY_CONFLICT");
                    job.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC)); jobs.save(job);
                }
            }
        } finally { activationPolling.set(false); }
    }

    private void activationFailed(SiemUebaModelJob job, String reason) {
        job.setActivationStatus("FAILED"); job.setStatus(job.getActivatedAt() == null ? "SUCCEEDED" : "RETIRED");
        Map<String, Object> state = new java.util.HashMap<>(summary(job)); state.put("activation_error_type", reason);
        job.setEvaluationSummaryJson(encode(state));
    }

    private void confirmPrimaryAndFinish(SiemUebaModelJob job) {
        var primary = worker.primaryMetadata();
        if (!job.getModelVersion().equals(primary.path("model_version").asText())
                || !job.getModelSha256().equals(primary.path("sha256").asText())) {
            activationFailed(job, "PRIMARY_IDENTITY_MISMATCH"); return;
        }
        recordTrainingMetadata(job, new SiemUebaGateway.TrainingJob(job.getWorkerJobId(), "SUCCEEDED", job.getModelVersion(), primary));
        finishActivation(job);
    }

    private void finishActivation(SiemUebaModelJob job) {
        String modelVersion = job.getModelVersion();
        boolean legacyRestore = "LEGACY_RESTORE".equals(job.getQualityGate());
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        for (SiemUebaModelJob previous : jobs.findByStatus("ACTIVE")) {
            if (!previous.getId().equals(job.getId())) {
                previous.setStatus("RETIRED");
                previous.setUpdatedAt(now);
                jobs.save(previous);
            }
        }
        job.setStatus("ACTIVE");
        job.setActivationStatus("SUCCEEDED");
        job.setActivatedAt(now);
        job.setActivatedByUserId(job.getActivationRequestedByUserId());
        job.setUpdatedAt(now);
        jobs.save(job);
        windows.markRuleOnlyPendingSince(now.minusHours(24),
                BehaviorScoreStatus.SCORED_RULE_ONLY, BehaviorScoreStatus.PENDING);
        audit.success(legacyRestore ? "SIEM_UEBA_LEGACY_MODEL_RESTORED" : "SIEM_UEBA_MODEL_ACTIVATED",
                job.getActivationRequestedByUserId(), null, "UEBA_MODEL", modelVersion);
    }

    private List<SiemAccountBehaviorWindow> eligibleWindows(LocalDateTime from, LocalDateTime to) {
        List<SiemAccountBehaviorWindow> eligible = new ArrayList<>();
        int page = 0;
        Page<SiemAccountBehaviorWindow> batch;
        do {
            batch = windows
                    .findByWindowStartGreaterThanEqualAndWindowStartLessThanAndFeatureSchemaVersionOrderByWindowStartAscIdAsc(
                            from, to, AccountBehaviorFeatures.SCHEMA_VERSION, PageRequest.of(page++, 500));
            batch.getContent().stream().filter(this::eligible).forEach(eligible::add);
            if (eligible.size() > 60_000 || page > 240) {
                throw new BadRequestException("Training range contains too many behavior windows.");
            }
        } while (batch.hasNext());
        return eligible;
    }

    private UebaExperimentCatalog.StrictReference registered(SiemUebaModelJob job) {
        return job.getRecipeId() == null || "legacy-v1".equals(job.getRecipeId()) ? null : catalog.strictRecipeOrNull(job.getRecipeId());
    }

    private boolean eligible(SiemAccountBehaviorWindow window) {
        List<Double> values = window.featureVector();
        boolean benignDemo = "NORMAL".equals(window.getDemoLabel());
        return window.isBaselineEstablished()
                && Set.of("REAL", "NORMAL").contains(window.getDemoLabel())
                && values.get(1) <= (benignDemo ? 1 : 0)
                && values.get(2) == 0 && values.get(3) <= (benignDemo ? 1 : 0)
                && values.get(5) == 0
                && values.get(8) == 0 && values.get(9) == 0 && values.get(10) == 0
                && values.get(0) < 60
                && (window.getRiskScore() == null || window.getRiskScore() < 30);
    }

    private String requireAdmin(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)
                || !"ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(principal.getUser().getRole()))) {
            throw new AccessDeniedException("Only an administrator can manage UEBA models.");
        }
        return principal.getUser().getId();
    }

    private SiemDtos.UebaTrainingJob toDto(SiemUebaModelJob job) {
        Map<String, Object> state = new java.util.HashMap<>(summary(job)); state.put("activation_status", job.getActivationStatus());
        return new SiemDtos.UebaTrainingJob(job.getId(), job.getModelVersion(), job.getStatus(),
                job.getDataProvenance(), job.getTrainingWindows(), job.getCalibrationWindows(),
                job.getCreatedAt(), job.getActivatedAt(), job.getFeatureSchemaVersion(), job.getRecipeId(), job.getDatasetId(),
                job.getEvaluationStatus(), job.getQualityGate(), state);
    }

    private Map<String, Object> summary(SiemUebaModelJob job) {
        if (job.getEvaluationSummaryJson() == null) return Map.of();
        try { return json.readValue(job.getEvaluationSummaryJson(), new com.fasterxml.jackson.core.type.TypeReference<>() { }); }
        catch (Exception failure) { throw new ConflictException("Stored evaluation summary is invalid."); }
    }
    private String encode(Map<String, Object> value) {
        try { return json.writeValueAsString(value); }
        catch (Exception failure) { throw new IllegalStateException("Unable to persist model evaluation metadata."); }
    }
    private static String newVersion(LocalDateTime now) {
        return "model-" + DateTimeFormatter.ofPattern("yyyyMMddHHmmss").format(now) + "-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
