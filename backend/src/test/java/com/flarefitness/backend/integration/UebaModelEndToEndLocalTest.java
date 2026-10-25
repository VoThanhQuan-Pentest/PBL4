package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import com.flarefitness.backend.service.siem.SiemUebaModelService;
import com.flarefitness.backend.service.siem.UebaExperimentCatalog;
import com.flarefitness.backend.service.siem.UebaScorePolicy;
import com.flarefitness.backend.service.siem.UebaTestPolicies;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/** Real Spring/MySQL -> ID-only HTTP -> actual Python fitting/calibration.
 * Preview proves transport/persistence only, never quality or elapsed shadow. */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "RUN_LOCAL_UEBA_WORKER", matches = "true")
class UebaModelEndToEndLocalTest extends ContainerizedIntegrationTest {
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private AuditLogService audit;
    @Autowired private ObjectMapper mapper;
    @Autowired private PlatformTransactionManager transactionManager;
    @TempDir Path temporary;

    @ParameterizedTest
    @CsvSource({"2,isolation_forest", "3,isolation_forest", "4,isolation_forest", "4,normal_support_distance"})
    void catalogueJobPersistsRealWorkerResultAndCannotBypassAdminOrQualityGates(int schema, String modelKind) throws Exception {
        Path catalog = Files.createDirectory(temporary.resolve("catalog"));
        ObjectNode policyWire = registerPreview(catalog, schema, modelKind);
        UebaScorePolicy policy = UebaScorePolicy.fromWire(policyWire, schema);
        if (schema == 4) {
            assertThat(AccountBehaviorFeatures.names(schema)).hasSize(37);
            assertThat(AccountBehaviorFeatures.names(schema).subList(0, 25)).isEqualTo(AccountBehaviorFeatures.names(3));
            assertThat(vector(2, true, schema)).hasSize(37);
            assertThat(vector(2, true, schema).subList(0, 25)).isEqualTo(vector(2, true, 3));
            assertThat(policy.id()).startsWith("strict-v4d-");
        }
        Path token = temporary.resolve("worker.token");
        Files.writeString(token, "local-test-only-ueba-token-at-least-32-characters");
        Path source = Path.of("..", "ueba-worker").toAbsolutePath().normalize();
        String image = System.getenv().getOrDefault("UEBA_WORKER_TEST_IMAGE", "flare-ueba-worker:local");
        try (GenericContainer<?> python = new GenericContainer<>(image)
                .withExposedPorts(8091)
                .withFileSystemBind(source.toString(), "/service", BindMode.READ_ONLY)
                .withCopyFileToContainer(MountableFile.forHostPath(token, 0644), "/tmp/ueba-token")
                .withCopyFileToContainer(MountableFile.forHostPath(catalog, 0755), "/run/ueba-catalog")
                .withEnv("UEBA_SERVICE_TOKEN_FILE", "/tmp/ueba-token")
                .withEnv("UEBA_MODEL_DIR", "/tmp/ueba-model")
                .withEnv("UEBA_EXPERIMENT_CATALOG_DIR", "/run/ueba-catalog")
                .withCreateContainerCmdModifier(command -> command.getHostConfig().withMemory(384L * 1024 * 1024).withNanoCPUs(1_000_000_000L))
                .waitingFor(Wait.forHttp("/health").forPort(8091).forStatusCode(200))) {
            python.start();
            var gateway = new SiemUebaGateway(true, "http://127.0.0.1:" + python.getMappedPort(8091), token.toString(), mapper);
            var service = new SiemUebaModelService(gateway, windows, jobs, events, audit,
                    new UebaExperimentCatalog(catalog.toString(), mapper), mapper);
            var tx = new TransactionTemplate(transactionManager);
            var request = new SiemDtos.StartUebaTraining(LocalDateTime.parse("2026-01-01T00:00:00"),
                    LocalDateTime.parse("2026-02-01T00:15:00"), "owned-preview-recipe");
            for (String role : List.of("CUSTOMER", "SOC L1", "SOC L2")) {
                assertThatThrownBy(() -> service.startTraining(request, actor(role))).isInstanceOf(AccessDeniedException.class);
            }
            var admin = actor("Quan tri vien");
            SiemDtos.UebaTrainingJob started = tx.execute(status -> service.startTraining(request, admin));
            assertThat(started).isNotNull();
            assertThat(started.status()).isEqualTo("QUEUED");
            assertThat(started.trainingWindows()).isEqualTo(600);
            assertThat(started.calibrationWindows()).isEqualTo(600);
            assertThat(started.featureSchemaVersion()).isEqualTo(schema);
            assertThat(jobs.findById(started.id())).isPresent();
            SiemDtos.UebaTrainingJob state = started;
            for (int attempt = 0; attempt < 200 && !List.of("SUCCEEDED", "FAILED", "INTERRUPTED").contains(state.status()); attempt++) {
                Thread.sleep(100);
                state = tx.execute(status -> service.refreshTrainingJob(started.id(), admin));
            }
            assertThat(state.status()).isEqualTo("SUCCEEDED");
            assertThat(state.qualityGate()).isEqualTo("NOT_RUN");
            assertThat(state.evaluationStatus()).isEqualTo("NOT_RUN");
            var stored = jobs.findById(started.id()).orElseThrow();
            assertThat(stored.getModelSha256()).matches("[a-f0-9]{64}");
            assertThat(stored.getDatasetManifestSha256()).matches("[a-f0-9]{64}");
            assertThat(stored.getDataProvenance()).isEqualTo("DEMO_ONLY");
            var worker = gateway.trainingJob(stored.getWorkerJobId());
            assertThat(worker.metadata().path("calibration_scope").asText()).isEqualTo("PILOT_ONLY");
            assertThat(worker.metadata().path("feature_schema_version").asInt()).isEqualTo(schema);
            assertThat(worker.metadata().path("feature_names")).isEqualTo(mapper.valueToTree(AccountBehaviorFeatures.names(schema)));
            assertThat(worker.metadata().path("training_windows").asInt()).isEqualTo(600);
            assertThat(worker.metadata().path("calibration_windows").asInt()).isEqualTo(600);
            assertThat(worker.metadata().path("calibration_cohort_windows")).isEqualTo(mapper.readTree("{\"READY\":300,\"COLD\":300}"));
            assertThat(worker.metadata().path("score_policy")).isEqualTo(policyWire);
            assertThat(worker.metadata().path("dataset_manifest_sha256").asText()).isEqualTo(stored.getDatasetManifestSha256());
            if ("normal_support_distance".equals(modelKind)) {
                assertThat(worker.metadata().path("model_kind").asText()).isEqualTo(modelKind);
                assertThat(worker.metadata().path("recipe_version").asInt()).isEqualTo(1);
                assertThat(worker.metadata().path("recipe_sha256").asText()).matches("[a-f0-9]{64}");
                assertThat(worker.metadata().path("model_state_format").asText()).isEqualTo("NORMAL_SUPPORT_NUMERIC_STATE_V1");
            }
            var scored = gateway.scoreCandidate(started.modelVersion(), List.of(vector(2, false, schema), vector(2, true, schema)),
                    schema, List.of("READY", "COLD"));
            assertThat(scored.available()).isTrue();
            assertThat(scored.results()).extracting(SiemUebaGateway.Score::cohort).containsExactly("READY", "COLD");
            assertThat(scored.featureSchemaVersion()).isEqualTo(schema);
            assertThat(scored.policy().sha256()).isEqualTo(policy.sha256());
            assertThat(scored.calibrationSha256()).isEqualTo(worker.metadata().path("calibration_sha256").asText());
            assertThatThrownBy(() -> tx.execute(status -> service.activate(started.modelVersion(), admin))).isInstanceOf(ConflictException.class);
            assertThat(gateway.health().modelAvailable()).isFalse();
            assertThat(jobs.findById(started.id()).orElseThrow().getStatus()).isEqualTo("SUCCEEDED");
        }
    }

    private ObjectNode registerPreview(Path catalog, int schema, String modelKind) throws Exception {
        Path directory = Files.createDirectory(catalog.resolve("owned-catalog-fixture"));
        Files.createDirectory(directory.resolve("shards"));
        ObjectNode manifest = mapper.createObjectNode();
        manifest.put("catalog_schema_version", 2); manifest.put("dataset_id", "owned-catalog-fixture"); manifest.put("stage", "PILOT");
        manifest.put("data_provenance", "DEMO_ONLY"); manifest.put("feature_schema_version", schema);
        manifest.put("telemetry_contract_version", schema == 4 ? 3 : 2);
        manifest.set("feature_names", mapper.valueToTree(AccountBehaviorFeatures.names(schema)));
        ObjectNode splits = manifest.putObject("splits");
        addSplit(directory, splits, "fold1-fit", 600, false, "2026-01-01T00:00:00Z", schema);
        addSplit(directory, splits, "fold1-calibration-ready", 300, false, "2026-02-01T00:00:00Z", schema);
        addSplit(directory, splits, "fold1-calibration-cold", 300, true, "2026-02-01T00:00:00Z", schema);
        Files.writeString(directory.resolve("manifest.json"), canonical(manifest));
        ObjectNode registry = mapper.createObjectNode(); registry.putArray("entries");
        ObjectNode entry = registry.putArray("strict_entries").addObject();
        entry.put("recipe_id", "owned-preview-recipe"); entry.put("dataset_id", "owned-catalog-fixture"); entry.put("mode", "PILOT"); entry.put("fold", 1);
        entry.put("manifest_sha256", digest(Files.readAllBytes(directory.resolve("manifest.json"))));
        ObjectNode golden;
        try (var input = getClass().getResourceAsStream("/ueba-score-policy-golden.json")) {
            golden = (ObjectNode) mapper.readTree(input);
        }
        ObjectNode policy = schema == 4 ? UebaTestPolicies.sessionEndpoint(mapper)
                : schema == 3 ? UebaTestPolicies.contextual(mapper) : golden;
        var originalDocument = mapper.readTree(golden.path("policy_document_json").asText());
        var policyDocument = mapper.readTree(policy.path("policy_document_json").asText());
        assertThat(policyDocument.path("telemetry_contract_version").asInt()).isEqualTo(schema == 4 ? 3 : 2);
        for (String target : List.of("quality", "risk", "shadow", "warning_percentile_micro", "detection_percentile_micro", "positive_level")) {
            assertThat(policyDocument.path(target)).isEqualTo(originalDocument.path(target));
        }
        assertThat(policy.path("policy_sha256").asText()).isEqualTo(digest(canonical(policyDocument).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        entry.set("score_policy", policy);
        ObjectNode config = entry.putObject("config");
        if ("normal_support_distance".equals(modelKind)) {
            assertThat(schema).isEqualTo(4);
            config.put("neighbor_count", 8); config.put("reference_count", 128); config.put("metric", "euclidean"); config.put("random_state", 42);
            entry.put("model_kind", modelKind); entry.put("recipe_version", 1);
            ObjectNode identity = mapper.createObjectNode();
            identity.set("config", config.deepCopy()); identity.put("model_kind", modelKind); identity.put("recipe_version", 1);
            entry.put("recipe_sha256", digest(canonical(identity).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } else {
            assertThat(modelKind).isEqualTo("isolation_forest");
            config.put("n_estimators", 200); config.put("max_samples", 128); config.put("max_features", 1.0); config.put("random_state", 42);
        }
        Files.writeString(catalog.resolve("catalog.json"), canonical(registry));
        return policy;
    }

    private void addSplit(Path directory, ObjectNode splits, String name, int count, boolean cold, String timestamp, int schema) throws Exception {
        var rows = mapper.createArrayNode();
        for (int index = 0; index < count; index++) {
            ObjectNode row = rows.addObject();
            row.put("frame_id", name + "-frame-" + index);
            row.put("account_id", (cold ? "cold" : "mature") + "-owned-account-" + index); row.put("window_start", timestamp);
            row.put("label", 0); row.put("family", "normal"); row.put("cohort", cold ? "COLD" : "READY");
            row.put("baseline_established", !cold); row.put("trusted_window_count", cold ? 3 : 48);
            row.set("features", mapper.valueToTree(vector(index, cold, schema)));
        }
        String id = name + "-000000";
        Path path = directory.resolve("shards/" + id + ".json"); Files.writeString(path, canonical(rows));
        ObjectNode split = splits.putObject(name); split.put("records", count); split.put("normal", count); split.put("positive", 0);
        split.putObject("families").put("normal", count); split.putObject("cohorts").put(cold ? "COLD" : "READY", count);
        split.put("from", timestamp); split.put("to", timestamp);
        ObjectNode shard = split.putArray("shards").addObject();
        shard.put("id", id); shard.put("path", "shards/" + path.getFileName()); shard.put("sha256", digest(Files.readAllBytes(path)));
        for (String key : List.of("records", "normal", "positive", "families", "cohorts", "from", "to")) shard.set(key, split.get(key));
        split.put("sha256", digest(canonical(split).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private List<Double> vector(int index, boolean cold, int schema) {
        double requests = 4.0 + index % 7;
        var vector = new java.util.ArrayList<>(List.of(requests, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0,
                cold ? 0.0 : (index % 7 - 3) / 4.0, 0.0, 0.0, 0.0));
        if (schema >= 3) vector.addAll(List.of(requests, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
        if (schema == 4) vector.addAll(List.of(requests, 1.0, 0.0, 0.0, 1.0, requests,
                requests, 1.0, 600.0, 1.0, cold ? 3.0 : 48.0, 0.5));
        return new AccountBehaviorFeatures.Vector(schema, vector).values();
    }

    private String canonical(com.fasterxml.jackson.databind.JsonNode value) throws Exception {
        if (value.isObject()) {
            ObjectNode sorted = mapper.createObjectNode(); var keys = new java.util.ArrayList<String>();
            value.fieldNames().forEachRemaining(keys::add); keys.sort(String::compareTo);
            for (String key : keys) sorted.set(key, mapper.readTree(canonical(value.get(key))));
            return mapper.writeValueAsString(sorted);
        }
        if (value.isArray()) {
            var result = mapper.createArrayNode(); for (var item : value) result.add(mapper.readTree(canonical(item)));
            return mapper.writeValueAsString(result);
        }
        return mapper.writeValueAsString(value);
    }

    private static String digest(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    private UsernamePasswordAuthenticationToken actor(String role) {
        User user = new User(); user.setId("owned-actor-" + role.replace(' ', '-')); user.setUsername(user.getId()); user.setRole(role);
        user.setStatus("Hoat dong"); user.setDeleted(false); var principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
