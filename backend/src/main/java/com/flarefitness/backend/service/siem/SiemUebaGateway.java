package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Fixed internal numeric-feature API. No user-provided URL or identity is sent to Python. */
@Service
public class SiemUebaGateway {
    private final boolean enabled;
    private final URI baseUri;
    private final Path tokenFile;
    private final ObjectMapper mapper;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2)).build();

    public SiemUebaGateway(@Value("${siem.ueba.enabled:false}") boolean enabled,
                           @Value("${siem.ueba.url:http://ueba-worker:8091}") String baseUrl,
                           @Value("${siem.ueba.service-token-file:/run/secrets/ueba.token}") String tokenFile,
                           ObjectMapper mapper) {
        this.enabled = enabled;
        this.baseUri = URI.create(baseUrl);
        this.tokenFile = Path.of(tokenFile);
        this.mapper = mapper;
        if (baseUri.getHost() == null || baseUri.getUserInfo() != null
                || baseUri.getRawQuery() != null || baseUri.getFragment() != null
                || (baseUri.getPath() != null && !baseUri.getPath().isBlank())
                || (!"http".equals(baseUri.getScheme()) && !"https".equals(baseUri.getScheme()))) {
            throw new IllegalArgumentException("SIEM UEBA URL must be a fixed HTTP(S) origin.");
        }
        if ("http".equals(baseUri.getScheme()) && !"ueba-worker".equals(baseUri.getHost())
                && !"127.0.0.1".equals(baseUri.getHost()) && !"localhost".equals(baseUri.getHost())) {
            throw new IllegalArgumentException("Unencrypted UEBA traffic is allowed only on the internal worker network.");
        }
    }

    public boolean isEnabled() { return enabled; }

    public WorkerHealth health() {
        if (!enabled) return new WorkerHealth(false, false, null, "DISABLED");
        try {
            JsonNode root = call("GET", "/health", null, 200);
            if (!hasFeatureContract(root)) {
                return new WorkerHealth(false, false, null, "FEATURE_SCHEMA_MISMATCH");
            }
            return new WorkerHealth(true, root.path("model_available").asBoolean(false),
                    root.path("model_version").isNull() ? null : root.path("model_version").asText(), null,
                    root.path("feature_schema_version").asInt());
        } catch (Exception exception) {
            return new WorkerHealth(false, false, null, "WORKER_UNAVAILABLE");
        }
    }

    public TrainingJob startTraining(String version, List<List<Double>> training,
                                     List<List<Double>> calibration) {
        return startTraining(version, training, calibration, 1, Map.of());
    }

    public TrainingJob startCatalogTraining(String version, String recipeId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        if (recipeId == null || !recipeId.matches("[a-z0-9_-]{8,96}")) throw new IllegalArgumentException("Invalid UEBA recipe ID.");
        try {
            JsonNode root = call("POST", "/internal/v1/train-catalog", mapper.writeValueAsString(Map.of(
                    "model_version", version, "recipe_id", recipeId)), 202);
            String jobId = root.path("job_id").asText();
            if (!jobId.matches("[0-9a-f]{32}") || !version.equals(root.path("model_version").asText())
                    || !"QUEUED".equals(root.path("status").asText())) throw new ServiceUnavailableException("Invalid UEBA catalogue job response.");
            return new TrainingJob(jobId, "QUEUED", version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("UEBA catalogue training unavailable: " + failure.getClass().getSimpleName()); }
    }

    /** Slow quality-proof verification runs as a worker job, not inside a 5s HTTP call. */
    public TrainingJob startShadow(String version, String requestId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version); validateShadowId(requestId);
        try {
            JsonNode root = call("POST", "/internal/v1/shadow-runs", mapper.writeValueAsString(Map.of(
                    "model_version", version, "request_id", requestId)), 202);
            String status = root.path("status").asText();
            if (!requestId.equals(root.path("job_id").asText()) || !version.equals(root.path("model_version").asText())
                    || !Set.of("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "INTERRUPTED").contains(status)) {
                throw new ServiceUnavailableException("Invalid shadow job acknowledgement.");
            }
            return new TrainingJob(requestId, status, version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Shadow submission unavailable: " + failure.getClass().getSimpleName()); }
    }

    public JsonNode shadowStatus(String runId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateShadowId(runId);
        try { return validateShadowState(call("GET", "/internal/v1/shadow-runs/" + runId, null, 200), runId); }
        catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Shadow lookup unavailable: " + failure.getClass().getSimpleName()); }
    }

    public JsonNode validateShadowState(JsonNode value, String runId) {
        validateShadowId(runId);
        String status = value.path("status").asText();
        if (!runId.equals(value.path("run_id").asText()) || !Set.of("RUNNING", "COMPLETED", "INVALIDATED").contains(status)
                || !value.path("feature_schema_version").isIntegralNumber() || !Set.of(2, 3, 4).contains(value.path("feature_schema_version").asInt(-1))
                || !"REAL_SERVER_CLOCK".equals(value.path("clock_provenance").asText())) {
            throw new ServiceUnavailableException("Shadow identity, clock provenance or state is invalid.");
        }
        validateModelVersion(value.path("model_version").asText());
        for (String name : List.of("model_sha256", "calibration_sha256", "policy_sha256", "dataset_sha256", "boot_sha256")) {
            if (!value.path(name).isTextual() || !value.path(name).asText().matches("[a-f0-9]{64}")) {
                throw new ServiceUnavailableException("Shadow artifact binding is invalid.");
            }
        }
        for (String name : List.of("started_monotonic", "last_heartbeat_monotonic", "elapsed_monotonic_seconds", "maximum_heartbeat_gap_seconds")) {
            double number = value.path(name).asDouble(Double.NaN);
            if (!value.path(name).isNumber() || !Double.isFinite(number) || number < 0) {
                throw new ServiceUnavailableException("Shadow timing is invalid.");
            }
        }
        if (!value.path("closed_windows").isIntegralNumber() || !value.path("closed_windows").canConvertToLong()
                || value.path("closed_windows").asLong() < 0) throw new ServiceUnavailableException("Shadow coverage is invalid.");
        validateShadowSideEffects(value.path("candidate_side_effects"));
        try {
            var start = java.time.OffsetDateTime.parse(value.path("started_at_utc").asText());
            if (!isUtc(start)) throw new IllegalArgumentException("UTC required");
            if ("COMPLETED".equals(status)) {
                var end = java.time.OffsetDateTime.parse(value.path("ended_at_utc").asText());
                if (!isUtc(end) || Duration.between(start, end).getSeconds() < 86400
                        || value.path("elapsed_monotonic_seconds").asDouble() < 86400
                        || value.path("maximum_heartbeat_gap_seconds").asDouble() > 300
                        || value.path("closed_windows").asLong() < 600) {
                    throw new IllegalArgumentException("incomplete real shadow observation");
                }
            }
        } catch (RuntimeException failure) { throw new ServiceUnavailableException("Shadow elapsed time proof is invalid."); }
        return value;
    }

    public void sendShadowWindows(String runId, List<Map<String, Object>> rows) {
        sendShadowWindows(runId, rows, 2);
    }

    public void sendShadowWindows(String runId, List<Map<String, Object>> rows, int schema) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        if (!Set.of(2, 3, 4).contains(schema)) throw new IllegalArgumentException("Invalid strict shadow feature schema.");
        validateShadowId(runId);
        if (rows == null || rows.isEmpty() || rows.size() > 256) throw new IllegalArgumentException("Invalid shadow batch size.");
        List<String> ids = new ArrayList<>();
        for (var row : rows) {
            if (!row.keySet().equals(Set.of("window_id", "window_end_utc", "baseline_established", "features"))
                    || !(row.get("window_id") instanceof String id) || !id.matches("[a-zA-Z0-9_-]{8,128}")
                    || !(row.get("baseline_established") instanceof Boolean)) throw new IllegalArgumentException("Invalid shadow window.");
            ids.add(id);
            List<Double> vector = mapper.convertValue(row.get("features"), mapper.getTypeFactory().constructCollectionType(List.class, Double.class));
            validateVectors(List.of(vector), 1, 1, schema);
        }
        if (new java.util.HashSet<>(ids).size() != ids.size()) throw new IllegalArgumentException("Duplicate shadow window.");
        try {
            JsonNode response = call("POST", "/internal/v1/shadow-runs/" + runId + "/windows",
                    mapper.writeValueAsString(Map.of("windows", rows)), 200);
            if (!response.path("accepted_window_ids").isArray()) throw new ServiceUnavailableException("Missing shadow acknowledgement.");
            List<String> accepted = mapper.convertValue(response.path("accepted_window_ids"),
                    mapper.getTypeFactory().constructCollectionType(List.class, String.class));
            if (!runId.equals(response.path("run_id").asText()) || !ids.equals(accepted)
                    || !response.path("newly_scored_windows").isIntegralNumber()
                    || response.path("newly_scored_windows").asLong(-1) < 0
                    || response.path("newly_scored_windows").asLong() > rows.size()) {
                throw new ServiceUnavailableException("Shadow batch acknowledgement mismatch.");
            }
            validateShadowSideEffects(response.path("candidate_side_effects"));
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Shadow scoring unavailable: " + failure.getClass().getSimpleName()); }
    }

    private static boolean isUtc(java.time.OffsetDateTime value) { return java.time.ZoneOffset.UTC.equals(value.getOffset()); }
    private static void validateShadowId(String value) {
        if (value == null || !value.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("Invalid shadow request ID.");
    }
    private static void validateShadowSideEffects(JsonNode effects) {
        Set<String> expected = Set.of("incidents", "history", "ip_lookups", "ip_blocks", "session_revocations", "policy_publications");
        if (!effects.isObject() || effects.size() != expected.size()) throw new ServiceUnavailableException("Shadow side-effect contract is missing.");
        for (String name : expected) {
            if (!effects.path(name).isIntegralNumber() || effects.path(name).asLong(-1) != 0) {
                throw new ServiceUnavailableException("Shadow cannot perform response actions.");
            }
        }
    }

    public TrainingJob startTraining(String version, List<List<Double>> training,
                                     List<List<Double>> calibration, int schema, Map<String, Object> config) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        validateVectors(training, 500, 50_000, schema);
        validateVectors(calibration, 100, 10_000, schema);
        try {
            JsonNode root = call("POST", "/internal/v1/train", mapper.writeValueAsString(Map.of(
                    "model_version", version, "feature_schema_version", schema,
                    "feature_names", AccountBehaviorFeatures.names(schema),
                    "samples", training, "calibration", calibration, "config", config)), 202);
            String jobId = root.path("job_id").asText();
            if (!jobId.matches("[0-9a-f]{32}")) throw new ServiceUnavailableException("Invalid UEBA job ID.");
            return new TrainingJob(jobId, root.path("status").asText(), version);
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("UEBA training unavailable: "
                    + exception.getClass().getSimpleName());
        }
    }

    public TrainingJob trainingJob(String jobId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        if (jobId == null || !jobId.matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException("Invalid UEBA job ID.");
        }
        try {
            JsonNode root = call("GET", "/internal/v1/jobs/" + jobId, null, 200);
            String status = root.path("status").asText();
            if (!Set.of("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "INTERRUPTED").contains(status)) {
                throw new ServiceUnavailableException("Invalid UEBA training status.");
            }
            return new TrainingJob(jobId, status, root.path("model_version").asText(), root.path("metadata"));
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("UEBA job lookup unavailable: "
                    + exception.getClass().getSimpleName());
        }
    }

    public String activate(String version) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        try {
            JsonNode root = call("POST", "/internal/v1/models/activate",
                    mapper.writeValueAsString(Map.of("model_version", version)), 200);
            if (!version.equals(root.path("model_version").asText()) || !hasFeatureContract(root)) {
                throw new ServiceUnavailableException("UEBA activation response is invalid.");
            }
            return version;
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("UEBA activation unavailable: "
                    + exception.getClass().getSimpleName());
        }
    }

    public TrainingJob startActivation(String version, String requestId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version); validateShadowId(requestId);
        try {
            JsonNode value = call("POST", "/internal/v1/models/activation-jobs", mapper.writeValueAsString(Map.of(
                    "model_version", version, "request_id", requestId)), 202);
            String status = value.path("status").asText();
            if (!requestId.equals(value.path("job_id").asText()) || !version.equals(value.path("model_version").asText())
                    || !Set.of("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "INTERRUPTED").contains(status)) {
                throw new ServiceUnavailableException("Activation job acknowledgement failed identity validation.");
            }
            return new TrainingJob(requestId, status, version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Activation submission unavailable: " + failure.getClass().getSimpleName()); }
    }

    public JsonNode primaryMetadata() {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        try {
            JsonNode value = call("GET", "/internal/v1/models/primary", null, 200);
            if (!value.path("available").isBoolean() || !value.path("available").asBoolean()) {
                throw new ServiceUnavailableException("Primary model metadata is unavailable.");
            }
            return value.path("metadata");
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Primary lookup unavailable: " + failure.getClass().getSimpleName()); }
    }

    /** Read-only worker revalidation of a privately installed candidate and its actual scored journal. */
    public QualifiedCandidate qualifiedCandidate(String version) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        try {
            JsonNode root = call("GET", "/internal/v1/models/" + version + "/qualification", null, 200);
            JsonNode metadata = root.path("metadata");
            JsonNode evaluation = root.path("evaluation");
            JsonNode identity = root.path("evaluation_identity");
            JsonNode adoption = root.path("adoption_receipt");
            JsonNode artifacts = adoption.path("artifact_sha256");
            if (!"QUALIFIED".equals(root.path("status").asText())
                    || !version.equals(root.path("model_version").asText())
                    || !version.equals(metadata.path("model_version").asText())
                    || adoption.isMissingNode() || !"UEBA_QUALIFIED_ADOPTION_V1".equals(adoption.path("format").asText())
                    || !"CANDIDATE_INSTALLED".equals(adoption.path("status").asText())
                    || !version.equals(adoption.path("model_version").asText())
                    || !"DEMO_ONLY".equals(adoption.path("data_provenance").asText())
                    || !hexHash(metadata.path("sha256")) || metadata.path("feature_schema_version").asInt(-1) != 4
                    || !"STRICT".equals(metadata.path("calibration_scope").asText())
                    || !"SUCCEEDED".equals(evaluation.path("status").asText())
                    || !"PASS".equals(evaluation.path("quality_gate").asText())
                    || !"FROZEN_HOLDOUT".equals(evaluation.path("evaluation_scope").asText())
                    || !"DEMO_ONLY".equals(evaluation.path("data_provenance").asText())
                    || !evaluation.path("evaluation_identity").equals(identity)
                    || !hexHash(identity.path("fresh_holdout_manifest_sha256"))
                    || !hexHash(identity.path("holdout_split_sha256"))
                    || !hexHash(identity.path("frozen_selection_receipt_sha256"))
                    || !hexHash(root.path("adoption_receipt_sha256"))
                    || !metadata.path("sha256").asText().equals(adoption.path("model_sha256").asText())
                    || !metadata.path("calibration_sha256").asText().equals(adoption.path("calibration_sha256").asText())
                    || !metadata.path("dataset_manifest_sha256").asText().equals(adoption.path("original_training_manifest_sha256").asText())
                    || !identity.path("fresh_holdout_manifest_sha256").asText().equals(adoption.path("fresh_holdout_manifest_sha256").asText())
                    || !identity.path("holdout_split_sha256").asText().equals(adoption.path("holdout_split_sha256").asText())
                    || !identity.path("frozen_selection_receipt_sha256").asText().equals(adoption.path("selection_receipt_sha256").asText())
                    || !hexHash(artifacts.path("joblib")) || !hexHash(artifacts.path("metadata"))
                    || !hexHash(artifacts.path("evaluation")) || !hexHash(artifacts.path("evaluation_identity"))
                    || !hexHash(artifacts.path("metrics"))) {
                throw new ServiceUnavailableException("Worker candidate qualification identity or evidence is invalid.");
            }
            return new QualifiedCandidate(version, metadata, evaluation, identity, adoption,
                    root.path("adoption_receipt_sha256").asText());
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Worker candidate qualification unavailable: " + failure.getClass().getSimpleName()); }
    }

    /** Idempotently register an already installed, worker-verified artifact; performs no fit or upload. */
    public TrainingJob registerQualifiedAdoption(String version, String receiptSha256) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        if (receiptSha256 == null || !receiptSha256.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Invalid adoption receipt checksum.");
        }
        try {
            String requestId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(("UEBA_QUALIFIED_ADOPTION_V1:" + receiptSha256).getBytes(StandardCharsets.UTF_8))).substring(0, 32);
            JsonNode response = call("POST", "/internal/v1/models/qualified-adoptions", mapper.writeValueAsString(Map.of(
                    "model_version", version, "adoption_receipt_sha256", receiptSha256, "request_id", requestId)), 202);
            if (!requestId.equals(response.path("job_id").asText())
                    || !version.equals(response.path("model_version").asText())
                    || !"SUCCEEDED".equals(response.path("status").asText())) {
                throw new ServiceUnavailableException("Qualified adoption acknowledgement is invalid.");
            }
            return new TrainingJob(requestId, "SUCCEEDED", version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Candidate adoption unavailable: " + failure.getClass().getSimpleName()); }
    }

    public TrainingJob startEvaluation(String version, UebaExperimentCatalog.Dataset dataset, int schema) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        List<List<Double>> vectors = dataset.holdout().stream()
                .map(row -> schema == 1 ? List.copyOf(row.features().subList(0, 11)) : row.features()).toList();
        validateVectors(vectors, 11000, 20000, schema);
        try {
            String body = mapper.writeValueAsString(Map.of("model_version", version, "feature_schema_version", schema,
                    "feature_names", AccountBehaviorFeatures.names(schema), "vectors", vectors,
                    "labels", dataset.holdout().stream().map(UebaExperimentCatalog.Row::label).toList(),
                    "families", dataset.holdout().stream().map(UebaExperimentCatalog.Row::family).toList(),
                    "groups", dataset.holdout().stream().map(row -> row.accountId() + "/" + row.start().toLocalDate()).toList()));
            JsonNode root = call("POST", "/internal/v1/evaluations", body, 202);
            String job = root.path("job_id").asText();
            if (!job.matches("[a-f0-9]{32}")) throw new ServiceUnavailableException("Invalid UEBA evaluation job.");
            return new TrainingJob(job, root.path("status").asText(), version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("UEBA evaluation unavailable: " + failure.getClass().getSimpleName()); }
    }

    public TrainingJob startCatalogEvaluation(String version, String recipeId) {
        if (!enabled) throw new ServiceUnavailableException("UEBA worker is disabled.");
        validateModelVersion(version);
        if (recipeId == null || !recipeId.matches("[a-z0-9_-]{8,96}")) throw new IllegalArgumentException("Invalid evaluation recipe ID.");
        try {
            JsonNode value = call("POST", "/internal/v1/evaluations/catalog", mapper.writeValueAsString(Map.of(
                    "model_version", version, "recipe_id", recipeId)), 202);
            String id = value.path("job_id").asText();
            if (!id.matches("[a-f0-9]{32}") || !version.equals(value.path("model_version").asText())
                    || !"QUEUED".equals(value.path("status").asText())) throw new ServiceUnavailableException("Invalid strict evaluation acknowledgement.");
            return new TrainingJob(id, "QUEUED", version);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw new ServiceUnavailableException("Strict evaluation unavailable: " + failure.getClass().getSimpleName()); }
    }

    public Map<String, Object> validateStrictEvaluation(JsonNode value, String version, String modelSha,
                                                         UebaExperimentCatalog.StrictReference recipe) {
        return UebaStrictEvaluation.validate(mapper, value, version, modelSha, recipe);
    }

    /** Recompute the gate from allowlisted counters; never trust a bare upstream PASS string. */
    public Map<String, Object> validateEvaluation(JsonNode root, String modelVersion, String modelSha256,
                                                  String payloadSha256, int schema, int expectedNormal, int expectedPositive) {
        if (!"SUCCEEDED".equals(root.path("status").asText()) || !modelVersion.equals(root.path("model_version").asText())
                || !modelSha256.equals(root.path("model_sha256").asText())
                || !payloadSha256.equals(root.path("evaluation_dataset_sha256").asText())
                || root.path("feature_schema_version").asInt() != schema
                || !"MODEL_ONLY".equals(root.path("scope").asText())
                || !"FROZEN_HOLDOUT".equals(root.path("evaluation_scope").asText())
                || !"DEMO_ONLY".equals(root.path("data_provenance").asText())
                || root.path("percentile_threshold").asInt() != 99) throw invalidEvaluation();
        int tp = count(root, "tp"), fp = count(root, "fp"), tn = count(root, "tn"), fn = count(root, "fn");
        if (tp + fn != expectedPositive || fp + tn != expectedNormal || expectedPositive < 1000 || expectedNormal < 10000) throw invalidEvaluation();
        double recall = (double) tp / (tp + fn), fpr = (double) fp / (fp + tn);
        if (!close(root.path("recall").asDouble(Double.NaN), recall)
                || !close(root.path("false_positive_rate").asDouble(Double.NaN), fpr)) throw invalidEvaluation();
        boolean pass = recall >= 0.9 && fpr <= 0.02;
        Map<String, Object> families = new java.util.LinkedHashMap<>();
        int familyTotal = 0, familyHits = 0;
        for (String family : List.of("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")) {
            JsonNode value = root.path("families").path(family);
            int positives = count(value, "positive_samples"), hits = count(value, "tp"), misses = count(value, "fn");
            if (positives < 200 || positives != hits + misses) throw invalidEvaluation();
            double familyRecall = (double) hits / positives;
            if (!close(value.path("recall").asDouble(Double.NaN), familyRecall)) throw invalidEvaluation();
            pass &= familyRecall >= 0.8;
            familyTotal += positives; familyHits += hits;
            families.put(family, Map.of("positive_samples", positives, "tp", hits, "fn", misses, "recall", familyRecall));
        }
        if (familyTotal != expectedPositive || familyHits != tp || !root.path("minimum_sizes_met").asBoolean(false)
                || !(pass ? "PASS" : "FAIL").equals(root.path("quality_gate").asText())) throw invalidEvaluation();
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("scope", "MODEL_ONLY"); result.put("evaluation_scope", "FROZEN_HOLDOUT");
        result.put("status", "SUCCEEDED"); result.put("model_version", modelVersion);
        result.put("feature_schema_version", schema); result.put("minimum_sizes_met", true); result.put("percentile_threshold", 99);
        result.put("data_provenance", "DEMO_ONLY"); result.put("quality_gate", pass ? "PASS" : "FAIL");
        result.put("model_sha256", modelSha256); result.put("evaluation_dataset_sha256", payloadSha256);
        result.put("normal_samples", expectedNormal); result.put("positive_samples", expectedPositive);
        result.put("tp", tp); result.put("fp", fp); result.put("tn", tn); result.put("fn", fn);
        result.put("recall", recall); result.put("false_positive_rate", fpr);
        if (tp + fp > 0) {
            double precision = (double) tp / (tp + fp);
            if (!close(root.path("precision").asDouble(Double.NaN), precision)) throw invalidEvaluation();
            result.put("precision", precision);
        } else {
            if (!root.path("precision").isNull()) throw invalidEvaluation();
            result.put("precision", null);
        }
        result.put("families", families);
        JsonNode confidence = root.path("confidence_95");
        if (!confidence.isObject() || !"account_day_cluster_bootstrap".equals(confidence.path("method").asText())
                || count(confidence, "clusters") < 2 || count(confidence, "resamples") != 2000) throw invalidEvaluation();
        {
            Map<String, Object> interval = new java.util.LinkedHashMap<>();
            interval.put("method", "account_day_cluster_bootstrap");
            interval.put("clusters", count(confidence, "clusters"));
            interval.put("resamples", count(confidence, "resamples"));
            for (String metric : List.of("recall", "false_positive_rate")) {
                JsonNode bounds = confidence.path(metric);
                if (!bounds.isArray() || bounds.size() != 2 || !Double.isFinite(bounds.get(0).asDouble(Double.NaN))
                        || !Double.isFinite(bounds.get(1).asDouble(Double.NaN)) || bounds.get(0).asDouble() < 0
                        || bounds.get(1).asDouble() > 1 || bounds.get(0).asDouble() > bounds.get(1).asDouble()) throw invalidEvaluation();
                interval.put(metric, List.of(bounds.get(0).asDouble(), bounds.get(1).asDouble()));
            }
            result.put("confidence_95", interval);
        }
        return result;
    }

    private static int count(JsonNode node, String key) {
        JsonNode value = node.path(key);
        if (!value.isIntegralNumber() || !value.canConvertToInt() || value.asInt() < 0 || value.asInt() > 20000) throw invalidEvaluation();
        return value.asInt();
    }
    private static boolean close(double actual, double expected) { return Double.isFinite(actual) && Math.abs(actual - expected) < 1e-9; }
    private static ServiceUnavailableException invalidEvaluation() { return new ServiceUnavailableException("UEBA evaluation response failed integrity validation."); }

    public ScoreBatch score(List<List<Double>> vectors) {
        return score(vectors, 1);
    }

    public ScoreBatch score(List<List<Double>> vectors, int schema) {
        return scoreAt(vectors, schema, null, null);
    }

    public ScoreBatch score(List<List<Double>> vectors, int schema, List<String> cohorts) {
        return scoreAt(vectors, schema, null, cohorts);
    }

    public ScoreBatch scoreCandidate(String version, List<List<Double>> vectors, int schema) {
        validateModelVersion(version);
        return scoreAt(vectors, schema, version, null);
    }

    public ScoreBatch scoreCandidate(String version, List<List<Double>> vectors, int schema, List<String> cohorts) {
        validateModelVersion(version);
        return scoreAt(vectors, schema, version, cohorts);
    }

    private ScoreBatch scoreAt(List<List<Double>> vectors, int schema, String candidate, List<String> cohorts) {
        if (!enabled) return ScoreBatch.unavailable("DISABLED");
        validateVectors(vectors, 1, 256, schema);
        if (cohorts != null && (cohorts.size() != vectors.size() || cohorts.stream().anyMatch(value ->
                value == null || !Set.of("READY", "COLD").contains(value)))) throw new IllegalArgumentException("Invalid score cohorts.");
        try {
            Map<String, Object> input = new java.util.HashMap<>(Map.of(
                    "feature_schema_version", schema,
                    "feature_names", AccountBehaviorFeatures.names(schema), "vectors", vectors));
            if (candidate != null) input.put("model_version", candidate);
            if (cohorts != null) input.put("cohorts", cohorts);
            JsonNode root = call("POST", candidate == null ? "/internal/v1/score" : "/internal/v1/score-candidate",
                    mapper.writeValueAsString(input), 200);
            if (!root.path("available").asBoolean(false)) {
                return ScoreBatch.unavailable(root.path("reason").asText("MODEL_NOT_READY"));
            }
            List<Score> scores = new ArrayList<>();
            if (!root.path("results").isArray() || root.path("results").size() != vectors.size()) {
                throw new ServiceUnavailableException("UEBA score batch shape mismatch.");
            }
            UebaScorePolicy policy = root.has("score_policy") ? UebaScorePolicy.fromWire(root.path("score_policy"), schema) : null;
            String calibrationSha = root.path("calibration_sha256").asText(null);
            if (policy != null && (calibrationSha == null || !calibrationSha.matches("[a-f0-9]{64}"))) {
                throw new ServiceUnavailableException("UEBA calibration binding is missing.");
            }
            int index = 0;
            for (JsonNode entry : root.path("results")) {
                double raw = entry.path("raw_anomaly_score").asDouble(Double.NaN);
                double percentile = entry.path("normal_percentile").asDouble(Double.NaN);
                String level = entry.path("level").asText();
                if (!Double.isFinite(raw) || !Double.isFinite(percentile)
                        || percentile < 0 || percentile > 100
                        || !List.of("NORMAL_RANGE", "UNUSUAL", "VERY_UNUSUAL").contains(level)
                        || (policy == null && ("NORMAL_RANGE".equals(level) && percentile >= 99
                            || "UNUSUAL".equals(level) && (percentile < 99 || percentile >= 99.9)
                            || "VERY_UNUSUAL".equals(level) && percentile < 99.9))) {
                    throw new ServiceUnavailableException("UEBA score response is invalid.");
                }
                String cohort = cohorts == null ? "READY" : cohorts.get(index);
                if (policy != null && (!policy.level(percentile, cohort).equals(level)
                        || !cohort.equals(entry.path("scoring_cohort").asText()))) throw new ServiceUnavailableException("UEBA score policy/cohort mismatch.");
                scores.add(new Score(raw, percentile, level, policy, cohort)); index++;
            }
            if (scores.size() != vectors.size()) {
                throw new ServiceUnavailableException("UEBA score batch size mismatch.");
            }
            String modelVersion = root.path("model_version").asText();
            validateModelVersion(modelVersion);
            if (!hasFeatureContract(root) || root.path("feature_schema_version").asInt() != schema
                    || candidate != null && !candidate.equals(modelVersion)) {
                throw new ServiceUnavailableException("UEBA score feature contract mismatch.");
            }
            return new ScoreBatch(true, modelVersion, null, scores, schema, policy, calibrationSha);
        } catch (ServiceUnavailableException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ServiceUnavailableException("UEBA worker unavailable: " + exception.getClass().getSimpleName());
        }
    }

    private JsonNode call(String method, String path, String body, int expectedStatus) throws Exception {
        String token = Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
        if (token.length() < 32) throw new ServiceUnavailableException("UEBA service credential is invalid.");
        HttpRequest.Builder builder = HttpRequest.newBuilder(baseUri.resolve(path))
                .timeout(Duration.ofSeconds(5))
                .header("X-UEBA-Token", token);
        if ("POST".equals(method)) {
            builder.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body));
        } else if ("GET".equals(method)) {
            builder.GET();
        } else {
            throw new IllegalArgumentException("Unsupported UEBA method.");
        }
        HttpRequest request = builder.build();
        HttpResponse<byte[]> response = client.send(request, boundedBody());
        if (response.statusCode() != expectedStatus) throw new ServiceUnavailableException("UEBA worker returned HTTP " + response.statusCode());
        return mapper.readTree(response.body());
    }

    private static HttpResponse.BodyHandler<byte[]> boundedBody() { return boundedBody(1024 * 1024); }

    private static HttpResponse.BodyHandler<byte[]> boundedBody(int maximum) {
        return info -> new HttpResponse.BodySubscriber<>() {
            private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
            private java.util.concurrent.Flow.Subscription subscription;
            private int received;
            @Override public java.util.concurrent.CompletionStage<byte[]> getBody() { return delegate.getBody(); }
            @Override public void onSubscribe(java.util.concurrent.Flow.Subscription value) { subscription = value; delegate.onSubscribe(value); }
            @Override public void onNext(List<java.nio.ByteBuffer> items) {
                for (var value : items) received += value.remaining();
                if (received > maximum) {
                    subscription.cancel(); delegate.onError(new java.io.IOException("UEBA response exceeded its bound"));
                } else delegate.onNext(items);
            }
            @Override public void onError(Throwable failure) { delegate.onError(failure); }
            @Override public void onComplete() { delegate.onComplete(); }
        };
    }

    /** Independent schema6 snapshot API; this never activates a window model. */
    public JsonNode scoreAuthShadow(Map<String,Object> packet,String expectedManifest) {
        if(expectedManifest==null||!expectedManifest.matches("[a-f0-9]{64}"))throw new ServiceUnavailableException("Shadow manifest not configured.");
        try {
            String token=Files.readString(tokenFile,StandardCharsets.UTF_8).trim();
            if(token.length()<32||token.length()>256)throw new ServiceUnavailableException("Invalid service credential.");
            HttpRequest request=HttpRequest.newBuilder(baseUri.resolve("/internal/v1/postlogin/shadow-score")).timeout(Duration.ofSeconds(2))
                .header("Content-Type","application/json").header("X-UEBA-Token",token)
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(Map.of("snapshots",List.of(packet))))).build();
            var response=client.send(request,HttpResponse.BodyHandlers.ofByteArray());
            if(response.statusCode()!=200||response.body().length>131072)throw new ServiceUnavailableException("Shadow worker unavailable.");
            JsonNode body=mapper.readTree(response.body());
            if(!"PILOT_ONLY".equals(body.path("scope").asText())||!"SHADOW".equals(body.path("mode").asText())||body.path("feature_schema_version").asInt()!=7||!expectedManifest.equals(body.path("manifest_sha256").asText()))throw new ServiceUnavailableException("Shadow identity differs.");
            var effects=body.path("candidate_side_effects");
            if(effects.size()!=5)throw new ServiceUnavailableException("Shadow side-effect contract missing.");
            for(String name:List.of("holds","incidents","ip_blocks","session_revocations","policy_publications"))if(!effects.path(name).isIntegralNumber()||effects.path(name).asInt(-1)!=0)throw new ServiceUnavailableException("Shadow cannot have response side effects.");
            var results=body.path("assessments");if(!results.isArray()||results.size()!=1||!Objects.equals(packet.get("snapshot_id"),results.path(0).path("snapshot_id").asText()))throw new ServiceUnavailableException("Shadow acknowledgement differs.");
            var assessment=results.path(0);String recommendation=assessment.path("recommendation").asText();
            if(!Set.of("ROUTINE","REVIEW","OPS","UNDETERMINED").contains(recommendation))throw new ServiceUnavailableException("Invalid shadow recommendation.");
            if(!"UNDETERMINED".equals(recommendation)&&(!assessment.path("raw_score").isNumber()||!Double.isFinite(assessment.path("raw_score").doubleValue())||!Set.of("ROUTINE_CONTEXT","BEHAVIOR_REVIEW_CONTEXT","SERVICE_DEGRADATION_CONTEXT").contains(assessment.path("context").asText())))throw new ServiceUnavailableException("Invalid shadow score/context.");
            return assessment;
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new ServiceUnavailableException("Shadow interrupted.");}
        catch(ServiceUnavailableException failure){throw failure;}
        catch(Exception unavailable){throw new ServiceUnavailableException("Shadow worker unavailable.");}
    }
    public PostloginScore scorePostlogin(Map<String, Object> snapshot, String expectedManifest) {
        java.util.concurrent.CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            if (expectedManifest == null || !expectedManifest.matches("[a-f0-9]{64}")) {
                throw new ServiceUnavailableException("Post-login model is not configured.");
            }
            String token = Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
            if (token.length() < 32 || token.length() > 256) throw new ServiceUnavailableException("Invalid service credential.");
            HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/internal/v1/postlogin/score"))
                    .timeout(Duration.ofMillis(500)).header("X-UEBA-Token", token).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(Map.of("snapshots", List.of(snapshot))))).build();
            pending = client.sendAsync(request, boundedBody(65536));
            HttpResponse<byte[]> response = pending.get(500, java.util.concurrent.TimeUnit.MILLISECONDS);
            if (response.statusCode() != 200) throw new ServiceUnavailableException("Post-login scoring unavailable.");
            JsonNode value = mapper.readTree(response.body());
            if (!PostloginDecisionPolicy.MODEL.equals(value.path("model_version").asText())
                    || !expectedManifest.equals(value.path("manifest_sha256").asText())
                    || !"7bf434569e388ac7c53ad0c19e1eef5b0d65d6848c1970da21638ce9e953a7aa".equals(value.path("model_sha256").asText())
                    || !"PROJECT_LIMITED".equals(value.path("qualification_scope").asText())
                    || !"DEMO_ONLY_RULE_DISTILLATION".equals(value.path("data_provenance").asText())
                    || !value.path("feature_schema_version").isIntegralNumber() || value.path("feature_schema_version").asInt() != 6
                    || !"SENSITIVE_ACTION_ATTEMPT".equals(value.path("evaluation_unit").asText())
                    || !hexHash(value.get("runtime_state_sha256")) || !hexHash(value.get("calibration_sha256"))
                    || !value.path("assessments").isArray() || value.path("assessments").size() != 1) {
                throw new ServiceUnavailableException("Post-login model identity mismatch.");
            }
            JsonNode result = value.path("assessments").get(0);
            String cohort = Boolean.TRUE.equals(snapshot.get("baseline_established")) ? "READY" : "COLD";
            double threshold = "READY".equals(cohort) ? 99.99 : 99.9995;
            double raw = result.path("raw_score").asDouble(Double.NaN);
            double percentile = result.path("normal_percentile").asDouble(Double.NaN);
            if (!snapshot.get("snapshot_id").equals(result.path("snapshot_id").asText())
                    || !snapshot.get("as_of").equals(result.path("as_of").asText())
                    || !cohort.equals(result.path("cohort").asText())
                    || !result.path("trusted_window_count").isIntegralNumber()
                    || ((Number) snapshot.get("trusted_window_count")).intValue() != result.path("trusted_window_count").asInt()
                    || !result.path("raw_score").isNumber() || !result.path("normal_percentile").isNumber()
                    || !Double.isFinite(raw) || !Double.isFinite(percentile) || percentile < 0 || percentile > 100
                    || !result.path("threshold").isNumber() || result.path("threshold").asDouble() != threshold
                    || !result.path("above_threshold").isBoolean() || result.path("above_threshold").asBoolean() != (percentile >= threshold)
                    || !Set.of("ROUTINE_CONTEXT", "BEHAVIOR_REVIEW_CONTEXT", "SERVICE_DEGRADATION_CONTEXT").contains(result.path("context").asText())) {
                throw new ServiceUnavailableException("Invalid post-login score response.");
            }
            return new PostloginScore(raw, percentile, result.path("context").asText(), percentile >= threshold,
                    value.path("model_sha256").asText(), expectedManifest);
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true);
            Thread.currentThread().interrupt();throw new ServiceUnavailableException("Post-login scoring interrupted.");
        } catch (Exception failure) {
            if (pending != null) pending.cancel(true);
            throw new ServiceUnavailableException("Post-login scoring unavailable: " + failure.getClass().getSimpleName());
        }
    }

    public record PostloginScore(double rawScore, double normalPercentile, String context,
                                 boolean aboveThreshold, String modelSha256, String manifestSha256) { }

    private void validateModelVersion(String version) {
        if (version == null || !version.matches("[a-z0-9_-]{8,64}")) {
            throw new IllegalArgumentException("Invalid UEBA model version.");
        }
    }

    private boolean hexHash(JsonNode value) {
        return value != null && value.isTextual() && value.asText().matches("[a-f0-9]{64}");
    }

    private boolean hasFeatureContract(JsonNode root) {
        int schema = root.path("feature_schema_version").asInt(-1);
        if (schema != 1 && schema != 2 && schema != 3 && schema != 4) {
            return false;
        }
        List<String> names = mapper.convertValue(root.path("feature_names"),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        return AccountBehaviorFeatures.names(schema).equals(names);
    }

    private void validateVectors(List<List<Double>> vectors, int minimum, int maximum, int schema) {
        int count = AccountBehaviorFeatures.names(schema).size();
        if (vectors == null || vectors.size() < minimum || vectors.size() > maximum
                || vectors.stream().anyMatch(row -> row == null || row.size() != count
                        || row.stream().anyMatch(value -> value == null || !Double.isFinite(value)))) {
            throw new IllegalArgumentException("Invalid UEBA training windows.");
        }
    }

    public record Score(double rawAnomalyScore, double normalPercentile, String level, UebaScorePolicy policy, String cohort) {
        public Score(double rawAnomalyScore, double normalPercentile, String level) {
            this(rawAnomalyScore, normalPercentile, level, null, "READY");
        }
    }
    public record WorkerHealth(boolean workerAvailable, boolean modelAvailable,
                               String activeModelVersion, String reason, int featureSchemaVersion) {
        public WorkerHealth(boolean workerAvailable, boolean modelAvailable, String activeModelVersion, String reason) {
            this(workerAvailable, modelAvailable, activeModelVersion, reason, 1);
        }
    }
    public record TrainingJob(String jobId, String status, String modelVersion, JsonNode metadata) {
        public TrainingJob(String jobId, String status, String modelVersion) {
            this(jobId, status, modelVersion, com.fasterxml.jackson.databind.node.MissingNode.getInstance());
        }
    }
    public record QualifiedCandidate(String modelVersion, JsonNode metadata, JsonNode evaluation,
                                     JsonNode evaluationIdentity, JsonNode adoptionReceipt,
                                     String adoptionReceiptSha256) { }
    public record ScoreBatch(boolean available, String modelVersion, String reason, List<Score> results,
                              int featureSchemaVersion, UebaScorePolicy policy, String calibrationSha256) {
        public ScoreBatch(boolean available, String modelVersion, String reason, List<Score> results, int featureSchemaVersion) {
            this(available, modelVersion, reason, results, featureSchemaVersion, null, null);
        }
        public ScoreBatch(boolean available, String modelVersion, String reason, List<Score> results) {
            this(available, modelVersion, reason, results, 1, null, null);
        }
        static ScoreBatch unavailable(String reason) { return new ScoreBatch(false, null, reason, List.of()); }
    }
}
