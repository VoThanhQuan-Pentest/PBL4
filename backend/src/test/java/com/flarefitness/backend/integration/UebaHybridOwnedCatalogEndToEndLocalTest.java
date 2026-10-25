package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.BehaviorScoreStatus;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import com.flarefitness.backend.repository.siem.SiemUebaModelJobRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.AuditLogService;
import com.flarefitness.backend.service.siem.AccountBehaviorScoringWorker;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import com.flarefitness.backend.service.siem.SiemUebaModelService;
import com.flarefitness.backend.service.siem.UebaExperimentCatalog;
import com.flarefitness.backend.service.siem.UebaScorePolicy;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

/** One real transport/persistence composite fit (two components), not a campaign or quality proof.
 * Opt in with -Drun.local.ueba.hybrid=true and -Dueba.hybrid.catalog-root=<installed operator root>.
 * Missing/broken real artifacts fail after opt-in; only the absent opt-in flag skips this test. */
@SpringBootTest(properties = "siem.ueba.enabled=false")
@EnabledIfSystemProperty(named = "run.local.ueba.hybrid", matches = ".*")
class UebaHybridOwnedCatalogEndToEndLocalTest extends ContainerizedIntegrationTest {
    private static final String KIND = "normal_plus_incident_research";
    private static final String FORMAT = "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1";
    private static final String WORKER_IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f";

    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemUebaModelJobRepository jobs;
    @Autowired private SiemSecurityEventRepository events;
    @Autowired private SiemIncidentRepository incidents;
    @Autowired private SiemIncidentHistoryRepository history;
    @Autowired private AuditLogService audit;
    @Autowired private ObjectMapper mapper;
    @Autowired private PlatformTransactionManager transactionManager;
    @TempDir Path temporary;

    @Test
    @Timeout(value = 15, unit = TimeUnit.MINUTES)
    void ownedHybridRecipeFitsThroughRealHttpPersistsAndNeverActivatesPilot() throws Exception {
        assertThat(System.getProperty("run.local.ueba.hybrid")).as("Explicit opt-in must be true; a present invalid flag cannot silently skip").isEqualTo("true");
        String configuredRoot = System.getProperty("ueba.hybrid.catalog-root");
        assertThat(configuredRoot).as("Explicit installed real operator catalog fixture is required after opt-in").isNotBlank();
        Path original = Path.of(configuredRoot).toAbsolutePath().normalize();
        assertThat(Files.isSymbolicLink(original)).isFalse();
        JsonNode registry = mapper.readTree(original.resolve("catalog.json").toFile());
        var selected = new ArrayList<JsonNode>();
        for (JsonNode candidate : registry.path("strict_entries")) {
            if (KIND.equals(candidate.path("model_kind").asText())) selected.add(candidate);
        }
        assertThat(selected).as("Exactly one actual owned hybrid recipe, not a fabricated fallback").hasSize(1);
        JsonNode entry = selected.getFirst();
        assertThat(entry.path("mode").asText()).isEqualTo("PILOT");
        assertThat(entry.path("model_state_format").asText()).isEqualTo(FORMAT);
        assertThat(entry.path("config")).isEqualTo(mapper.readTree("{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":42}"));
        Path catalog = Files.createDirectory(temporary.resolve("catalog"));
        Files.setPosixFilePermissions(catalog, PosixFilePermissions.fromString("rwx------"));
        copyArtifact(original, catalog, entry.path("dataset_id").asText());
        copyArtifact(original, catalog, entry.path("labeled_training_artifact_id").asText());
        ObjectNode privateRegistry = mapper.createObjectNode(); privateRegistry.putArray("entries");
        privateRegistry.putArray("strict_entries").add(entry.deepCopy());
        Files.writeString(catalog.resolve("catalog.json"), mapper.writeValueAsString(privateRegistry));
        Files.setPosixFilePermissions(catalog.resolve("catalog.json"), PosixFilePermissions.fromString("rw-------"));
        assertThat(((Number) Files.getAttribute(catalog, "unix:uid")).intValue()).as("Private bind must be owned by worker UID1000, without chowning any original").isEqualTo(1000);
        Path normalDirectory = catalog.resolve(entry.path("dataset_id").asText());
        Path labeledDirectory = catalog.resolve(entry.path("labeled_training_artifact_id").asText());
        assertThat(digest(normalDirectory.resolve("manifest.json"))).isEqualTo(entry.path("manifest_sha256").asText());
        assertThat(digest(labeledDirectory.resolve("manifest.private.json"))).isEqualTo(entry.path("labeled_training_manifest_sha256").asText());
        var localCatalog = new UebaExperimentCatalog(catalog.toString(), mapper);
        var recipe = localCatalog.strictRecipeOrNull(entry.path("recipe_id").asText());
        assertThat(recipe).isNotNull(); assertThat(recipe.modelKind()).isEqualTo(KIND);
        assertThat(recipe.descriptor().trainingWindows()).isEqualTo(50000);
        assertThat(recipe.descriptor().calibrationWindows()).isEqualTo(120000);
        assertThat(recipe.descriptor().completedSearchFits()).isZero();
        assertThat(recipe.labeledTraining().labeledWindows()).isEqualTo(81500);
        JsonNode manifest = mapper.readTree(normalDirectory.resolve("manifest.json").toFile());
        var ready = featuresFromFirstShard(normalDirectory, manifest, "fold1-fit");
        var cold = featuresFromFirstShard(normalDirectory, manifest, "fold1-calibration-cold");
        Path token = temporary.resolve("worker.token");
        Files.writeString(token, "owned-hybrid-local-only-" + UUID.randomUUID());
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"));
        Path source = Path.of("..", "ueba-worker").toAbsolutePath().normalize();
        UebaScorePolicy policy = UebaScorePolicy.fromWire(entry.path("score_policy"), 4);
        try (GenericContainer<?> worker = new GenericContainer<>(WORKER_IMAGE)
                .withImagePullPolicy(image -> false)
                .withExposedPorts(8091)
                .withFileSystemBind(source.toString(), "/service", BindMode.READ_ONLY)
                .withFileSystemBind(catalog.toString(), "/run/ueba-catalog", BindMode.READ_ONLY)
                .withFileSystemBind(token.toString(), "/tmp/ueba-token", BindMode.READ_ONLY)
                .withEnv("UEBA_SERVICE_TOKEN_FILE", "/tmp/ueba-token")
                .withEnv("UEBA_MODEL_DIR", "/tmp/owned-hybrid-model")
                .withEnv("UEBA_EXPERIMENT_CATALOG_DIR", "/run/ueba-catalog")
                .withEnv("PYTHONDONTWRITEBYTECODE", "1")
                .withEnv("OMP_NUM_THREADS", "2").withEnv("OPENBLAS_NUM_THREADS", "1")
                .withCreateContainerCmdModifier(command -> {
                    command.withUser("1000:1000");
                    command.getHostConfig().withMemory(2L * 1024 * 1024 * 1024).withNanoCPUs(2_000_000_000L);
                })
                .waitingFor(Wait.forHttp("/health").forPort(8091).forStatusCode(200).withStartupTimeout(Duration.ofMinutes(3)))) {
            worker.start();
            var gateway = new SiemUebaGateway(true, "http://127.0.0.1:" + worker.getMappedPort(8091), token.toString(), mapper);
            var service = new SiemUebaModelService(gateway, windows, jobs, events, audit, localCatalog, mapper);
            var tx = new TransactionTemplate(transactionManager);
            var request = new SiemDtos.StartUebaTraining(recipe.descriptor().from(), recipe.descriptor().to(), recipe.descriptor().recipeId());
            for (String role : List.of("CUSTOMER", "SOC L1", "SOC L2")) {
                assertThatThrownBy(() -> service.startTraining(request, actor(role))).isInstanceOf(AccessDeniedException.class);
            }
            var admin = actor("Quan tri vien");
            SiemDtos.UebaTrainingJob started = tx.execute(status -> service.startTraining(request, admin));
            assertThat(started).isNotNull(); assertThat(started.status()).isEqualTo("QUEUED");
            assertThat(started.trainingWindows()).isEqualTo(50000); assertThat(started.calibrationWindows()).isEqualTo(120000);
            assertThat(started.featureSchemaVersion()).isEqualTo(4); assertThat(jobs.findById(started.id())).isPresent();
            SiemDtos.UebaTrainingJob state = started;
            Instant deadline = Instant.now().plus(Duration.ofMinutes(5));
            while (!List.of("SUCCEEDED", "FAILED", "INTERRUPTED").contains(state.status()) && Instant.now().isBefore(deadline)) {
                Thread.sleep(1000);
                state = tx.execute(status -> service.refreshTrainingJob(started.id(), admin));
            }
            var stored = jobs.findById(started.id()).orElseThrow();
            var actual = gateway.trainingJob(stored.getWorkerJobId());
            assertThat(state.status()).as("Real ID-only worker training result: %s", actual.status()).isEqualTo("SUCCEEDED");
            assertThat(stored.getStatus()).isEqualTo("SUCCEEDED"); assertThat(stored.getModelSha256()).matches("[a-f0-9]{64}");
            assertThat(state.qualityGate()).isEqualTo("NOT_RUN"); assertThat(state.evaluationStatus()).isEqualTo("NOT_RUN");
            JsonNode metadata = actual.metadata();
            assertThat(metadata.path("model_kind").asText()).isEqualTo(KIND);
            assertThat(metadata.path("model_state_format").asText()).isEqualTo(FORMAT);
            assertThat(metadata.path("recipe_sha256").asText()).isEqualTo(entry.path("recipe_sha256").asText());
            assertThat(metadata.path("model_config")).isEqualTo(entry.path("config"));
            assertThat(metadata.path("model_state_sha256").asText()).matches("[a-f0-9]{64}");
            assertThat(metadata.path("model_state_verifier_sha256").asText()).matches("[a-f0-9]{64}");
            assertThat(metadata.path("training_windows").asInt()).isEqualTo(50000);
            assertThat(metadata.path("labeled_training_windows").asInt()).isEqualTo(81500);
            assertThat(metadata.path("labeled_class_windows")).isEqualTo(mapper.readTree("{\"0\":71500,\"1\":8000,\"2\":2000}"));
            assertThat(metadata.path("labeled_training_artifact_id").asText()).isEqualTo(entry.path("labeled_training_artifact_id").asText());
            assertThat(metadata.path("labeled_training_manifest_sha256").asText()).isEqualTo(entry.path("labeled_training_manifest_sha256").asText());
            assertThat(metadata.path("calibration_scope").asText()).isEqualTo("PILOT_ONLY");
            assertThat(metadata.path("calibration_cohort_windows")).isEqualTo(mapper.readTree("{\"READY\":60000,\"COLD\":60000}"));
            assertThat(metadata.path("dataset_manifest_sha256").asText()).isEqualTo(entry.path("manifest_sha256").asText());
            assertThat(stored.getDatasetManifestSha256()).isEqualTo(entry.path("manifest_sha256").asText());
            assertThat(metadata.path("score_policy")).isEqualTo(entry.path("score_policy"));
            assertThat(metadata.path("data_provenance").asText()).isEqualTo("DEMO_ONLY");
            assertThat(metadata.path("confirmed_attack_target_available").asBoolean(true)).isFalse();
            var scored = gateway.scoreCandidate(started.modelVersion(), List.of(ready, cold), 4, List.of("READY", "COLD"));
            assertThat(scored.available()).isTrue(); assertThat(scored.featureSchemaVersion()).isEqualTo(4);
            assertThat(scored.results()).extracting(SiemUebaGateway.Score::cohort).containsExactly("READY", "COLD");
            assertThat(scored.policy().sha256()).isEqualTo(policy.sha256());
            assertThat(scored.calibrationSha256()).isEqualTo(metadata.path("calibration_sha256").asText());

            String readyWindowId = "ueba-window-worker-e2e-ready-" + UUID.randomUUID().toString().substring(0, 8);
            String coldWindowId = "ueba-window-worker-e2e-cold-" + UUID.randomUUID().toString().substring(0, 8);
            LocalDateTime windowStart = LocalDateTime.now(ZoneOffset.UTC).minusMinutes(15).withSecond(0).withNano(0);
            var readyWindow = behaviorWindow(readyWindowId, "worker-e2e-ready-" + UUID.randomUUID(),
                    ready, true, windowStart);
            var coldWindow = behaviorWindow(coldWindowId, "worker-e2e-cold-" + UUID.randomUUID(),
                    cold, false, windowStart);
            tx.executeWithoutResult(status -> {
                windows.saveAndFlush(readyWindow);
                windows.saveAndFlush(coldWindow);
            });
            var candidateScorer = new AccountBehaviorScoringWorker(windows, incidents, history, gateway, true);
            ReflectionTestUtils.setField(candidateScorer, "candidateAcceptanceEnabled", true);
            tx.executeWithoutResult(status -> candidateScorer.scorePendingCandidateAt(LocalDateTime.now(ZoneOffset.UTC),
                    started.modelVersion(), List.of(readyWindowId, coldWindowId)));
            assertThat(windows.findById(readyWindowId).orElseThrow().getScoreStatus())
                    .isEqualTo(BehaviorScoreStatus.SCORED_MODEL);
            assertThat(windows.findById(readyWindowId).orElseThrow().getModelVersion()).isEqualTo(started.modelVersion());
            assertThat(windows.findById(coldWindowId).orElseThrow().getScoreStatus())
                    .isEqualTo(BehaviorScoreStatus.SCORED_MODEL);
            assertThat(windows.findById(coldWindowId).orElseThrow().getModelVersion()).isEqualTo(started.modelVersion());
            assertThat(gateway.health().modelAvailable()).isFalse();
            for (String role : List.of("CUSTOMER", "SOC L1", "SOC L2")) {
                assertThatThrownBy(() -> tx.execute(status -> service.activate(started.modelVersion(), actor(role)))).isInstanceOf(AccessDeniedException.class);
            }
            assertThatThrownBy(() -> tx.execute(status -> service.activate(started.modelVersion(), admin))).isInstanceOf(ConflictException.class);
            assertThat(gateway.health().modelAvailable()).isFalse();
            assertThat(jobs.findById(started.id()).orElseThrow().getStatus()).isEqualTo("SUCCEEDED");
        }
        // Assert real source byte identities after the worker has closed; no original writes/chown.
        assertThat(digest(original.resolve(entry.path("dataset_id").asText()).resolve("manifest.json"))).isEqualTo(entry.path("manifest_sha256").asText());
        assertThat(digest(original.resolve(entry.path("labeled_training_artifact_id").asText()).resolve("manifest.private.json"))).isEqualTo(entry.path("labeled_training_manifest_sha256").asText());
    }

    private void copyArtifact(Path original, Path destination, String id) throws Exception {
        assertThat(id).matches("[a-z0-9_-]{8,64}");
        Path source = original.resolve(id); assertThat(Files.isSymbolicLink(source)).isFalse();
        try (var tree = Files.walk(source)) {
            for (Path path : tree.sorted().toList()) {
                assertThat(Files.isSymbolicLink(path)).as("No symlink fixture inputs").isFalse();
                Path target = destination.resolve(id).resolve(source.relativize(path));
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                    Files.createDirectory(target); Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rwx------"));
                } else {
                    assertThat(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)).isTrue();
                    // Copies rather than chmodded hardlinks keep original inode metadata untouched.
                    Files.copy(path, target); Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
                }
            }
        }
    }

    private List<Double> featuresFromFirstShard(Path directory, JsonNode manifest, String split) throws Exception {
        String relative = manifest.path("splits").path(split).path("shards").get(0).path("path").asText();
        Path path = directory.resolve(relative).normalize(); assertThat(path.startsWith(directory)).isTrue();
        JsonNode row = mapper.readTree(path.toFile()).get(0); var features = new ArrayList<Double>();
        for (JsonNode value : row.path("features")) features.add(value.asDouble());
        return new AccountBehaviorFeatures.Vector(4, features).values();
    }

    private static SiemAccountBehaviorWindow behaviorWindow(String id, String accountId, List<Double> features,
                                                            boolean baselineEstablished, LocalDateTime start) {
        var schema4 = new AccountBehaviorFeatures.Vector(4, features);
        var window = new SiemAccountBehaviorWindow();
        window.setId(id); window.setAccountId(accountId); window.setWindowStart(start);
        window.setWindowEnd(start.plusMinutes(15)); window.setCreatedAt(start);
        window.replaceFeatures(schema4.base(), schema4.values().getFirst().intValue(), baselineEstablished,
                "198.51.100.23", "FIREFOX", "NORMAL", start);
        window.replacePersonalFeatures(new AccountBehaviorFeatures.Vector(2, schema4.values().subList(0, 15)), start);
        window.replaceContextualFeatures(new AccountBehaviorFeatures.Vector(3, schema4.values().subList(0, 25)), start);
        window.replaceSessionEndpointFeatures(schema4, start);
        return window;
    }

    private static String digest(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024]; int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private UsernamePasswordAuthenticationToken actor(String role) {
        User user = new User(); user.setId("owned-hybrid-actor-" + role.replace(' ', '-')); user.setUsername(user.getId());
        user.setRole(role); user.setStatus("Hoat dong"); user.setDeleted(false);
        var principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }
}
