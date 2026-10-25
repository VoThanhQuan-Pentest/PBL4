package com.flarefitness.monitor;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.model.SiemModels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;

/** 60 fresh DEMO_ONLY closed-window samples, observed in the real FX-thread table model. */
class AwsJavaFxIncidentLatencyTest {
    private static Label pageLabel(BorderPane root) {
        return root.lookupAll(".label").stream().filter(node -> node instanceof Label label
                && label.getText() != null && label.getText().matches("Page [0-9]+ of [0-9]+.*"))
                .map(node -> (Label) node).findFirst().orElseThrow();
    }

    private static Button pageButton(BorderPane root, String textPrefix) {
        return root.lookupAll(".button").stream().filter(node -> node instanceof Button button
                && button.getText() != null && button.getText().startsWith(textPrefix))
                .map(node -> (Button) node).findFirst().orElseThrow();
    }

    private static int currentPage(BorderPane root) {
        return Integer.parseInt(pageLabel(root).getText().split("\\s+")[1]);
    }

    private static void resetQueueToFirstPage(BorderPane root) throws Exception {
        for (int attempt = 0; attempt < 40; attempt++) {
            CountDownLatch observed = new CountDownLatch(1);
            AtomicReference<Integer> page = new AtomicReference<>();
            Platform.runLater(() -> {
                try {
                    page.set(currentPage(root));
                    if (page.get() > 1) {
                        Button previous = pageButton(root, "← Previous");
                        if (!previous.isDisabled()) previous.fire();
                    }
                } finally { observed.countDown(); }
            });
            assertTrue(observed.await(10, TimeUnit.SECONDS));
            if (Integer.valueOf(1).equals(page.get())) return;
            Thread.sleep(250);
        }
        fail("Could not return the live incident queue to its first page.");
    }

    private static String key(String user, LocalDateTime start) {
        return user + "|" + start.truncatedTo(ChronoUnit.HOURS);
    }

    @Test
    void measuresSixtySelectedModelIncidentsAtLightLoadWithoutChangingRefreshOrWorkerIntervals() throws Exception {
        String credentialFile = System.getenv("FLARE_AWS_LIVE_CREDENTIALS");
        String outputDirectory = System.getenv("FLARE_AWS_LIVE_OUTPUT");
        String host = System.getenv("FLARE_AWS_WEB_HOST");
        String controlPath = System.getenv("FLARE_AWS_SSH_CONTROL_PATH");
        String phase = System.getenv("FLARE_AWS_LATENCY_PHASE");
        String expectedModelVersion = System.getenv("FLARE_AWS_EXPECTED_MODEL_VERSION");
        assumeTrue(credentialFile != null && outputDirectory != null && host != null
                && controlPath != null && phase != null && expectedModelVersion != null,
                "Explicit AWS live acceptance settings and selected model identity required");
        assumeTrue(System.getenv("DISPLAY") != null, "Use xvfb-run");
        assertTrue(host.matches("ubuntu@\\d{1,3}(?:\\.\\d{1,3}){3}"));
        assertTrue(phase.matches("latency-[a-z0-9-]{4,32}"));
        assertTrue(expectedModelVersion.matches("[a-z0-9_-]{8,64}"));
        Path credentialPath = Path.of(credentialFile);
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(credentialPath));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode state = mapper.readTree(credentialPath.toFile());
        String dataset = state.path("dataset").asText();
        assertTrue(dataset.matches("[a-z0-9][a-z0-9_-]{3,23}"));
        JsonNode credential = state.path("accounts").path("l1");
        SiemApiClient api = new SiemApiClient("http://127.0.0.1:18089");
        var login = api.login(credential.path("username").asText(), credential.path("password").asText())
                .get(20, TimeUnit.SECONDS);
        assertEquals(credential.path("id").asText(), login.user().id());
        var model = api.uebaStatus().get(15, TimeUnit.SECONDS);
        assertTrue(model.modelAvailable());
        assertEquals("DEMO_ONLY", model.activeModelProvenance());
        assertEquals(expectedModelVersion, model.activeModelVersion());
        assertEquals(4, model.featureSchemaVersion());
        try { Platform.startup(() -> { }); }
        catch (IllegalStateException alreadyRunning) { }
        AtomicReference<BorderPane> rootRef = new AtomicReference<>();
        AtomicReference<Stage> stageRef = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch initialized = new CountDownLatch(1);
        Platform.runLater(() -> {
            try {
                FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
                BorderPane root = loader.load();
                DashboardController controller = loader.getController();
                Stage stage = new Stage();
                stage.setScene(new Scene(root, 1440, 1000));
                stage.getScene().getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                controller.initializeSession(api, login.user());
                stage.show();
                root.applyCss(); root.layout();
                Button queue = root.lookupAll(".nav-button").stream().filter(node -> node instanceof Button button
                        && button.getText().contains("Incident queue")).map(node -> (Button) node).findFirst().orElseThrow();
                queue.fire();
                rootRef.set(root); stageRef.set(stage);
            } catch (Throwable error) { failure.set(error); }
            finally { initialized.countDown(); }
        });
        assertTrue(initialized.await(20, TimeUnit.SECONDS));
        if (failure.get() != null) throw new AssertionError("Live queue initialization failed", failure.get());
        Path output = Path.of(outputDirectory);
        Files.createDirectories(output);
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        List<Double> values = new ArrayList<>();
        int failed = 0;
        Path csv = output.resolve("incident-latency.csv");
        try (var writer = Files.newBufferedWriter(csv, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            writer.write("sample,eligible_at,first_ui_available_at,incident_id,visible_seconds,passed\n");
            writer.flush();
            for (int pair = 0; pair < 30; pair++) {
                if (pair > 0) resetQueueToFirstPage(rootRef.get());
                if (pair > 0 && pair % 4 == 0) {
                    api.login(credential.path("username").asText(), credential.path("password").asText())
                            .get(20, TimeUnit.SECONDS);
                }
                String remote = "cd /opt/flare && python3 observability/scripts/seed-aws-incident-latency.py"
                        + " --dataset " + dataset + " --phase " + phase + " --pair " + pair;
                Process seed = new ProcessBuilder("ssh", "-o", "BatchMode=yes", "-o", "ControlPath=" + controlPath,
                        "-o", "StrictHostKeyChecking=accept-new", host, remote).redirectErrorStream(true).start();
                assertTrue(seed.waitFor(30, TimeUnit.SECONDS), "Fixture insertion timed out");
                String result = new String(seed.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                assertEquals(0, seed.exitValue(), "Fixture operation failed; inspect private operator logs");
                JsonNode metadata = mapper.readTree(result);
                assertEquals("ABNORMAL", metadata.path("demo_label").asText());
                Instant eligible = Instant.parse(metadata.path("eligible_at").asText());
                Map<String, JsonNode> expected = new LinkedHashMap<>();
                for (JsonNode sample : metadata.path("samples")) {
                    expected.put(key(sample.path("target_user_id").asText(),
                            LocalDateTime.parse(sample.path("window_start").asText())), sample);
                }
                assertEquals(2, expected.size());
                Map<String, Instant> visible = new HashMap<>();
                Map<String, String> identifiers = new HashMap<>();
                Set<Integer> pagesVisited = new HashSet<>();
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
                while (visible.size() < 2 && System.nanoTime() < deadline) {
                    CountDownLatch observed = new CountDownLatch(1);
                    Platform.runLater(() -> {
                        try {
                            BorderPane root = rootRef.get();
                            root.applyCss(); root.layout();
                            for (var node : root.lookupAll(".table-view")) {
                                if (!(node instanceof TableView<?> table)) continue;
                                for (var row : table.getItems()) {
                                    if (!(row instanceof SiemModels.Incident item) || !"UEBA".equals(item.origin())) continue;
                                    String identity = key(item.targetUserId(), item.bucketStart());
                                    JsonNode expectedSample = expected.get(identity);
                                    if (expectedSample != null && expectedSample.path("source_ip").asText().equals(item.sourceIp())) {
                                        assertTrue(item.score() >= 0 && item.score() <= 100);
                                        visible.putIfAbsent(identity, Instant.now());
                                        identifiers.putIfAbsent(identity, item.id());
                                    }
                                }
                            }
                            if (visible.size() < 2) {
                                int page = currentPage(root);
                                if (pagesVisited.add(page)) {
                                    Button next = pageButton(root, "Next");
                                    if (!next.isDisabled()) next.fire();
                                }
                            }
                        } catch (Throwable error) { failure.set(error); }
                        finally { observed.countDown(); }
                    });
                    assertTrue(observed.await(10, TimeUnit.SECONDS));
                    if (failure.get() != null) throw new AssertionError("Live table observation failed", failure.get());
                    if (visible.size() < 2) Thread.sleep(250);
                }
                for (var entry : expected.entrySet()) {
                    Instant seen = visible.get(entry.getKey());
                    String incidentId = identifiers.get(entry.getKey());
                    assertNotNull(incidentId, "A new matching UEBA incident must be visible in JavaFX");
                    var behavior = api.incidentBehaviorWindows(incidentId).get(20, TimeUnit.SECONDS);
                    JsonNode expectedSample = entry.getValue();
                    boolean selectedModelScoredWindow = behavior.content().stream().anyMatch(window ->
                            key(window.accountId(), window.windowStart()).equals(entry.getKey())
                                    && expectedSample.path("source_ip").asText().equals(window.sourceIp())
                                    && "SCORED_MODEL".equals(window.scoreStatus())
                                    && expectedModelVersion.equals(window.modelVersion())
                                    && Integer.valueOf(4).equals(window.scoredFeatureSchemaVersion()));
                    assertTrue(selectedModelScoredWindow,
                            "Incident must have a matching schema-4 behavior window scored by the selected candidate");
                    Double seconds = seen == null ? null : Duration.between(eligible, seen).toNanos() / 1_000_000_000.0;
                    boolean passed = seconds != null && seconds >= 0 && seconds <= 90;
                    if (seconds != null) values.add(seconds);
                    if (!passed) failed++;
                    writer.write(entry.getValue().path("sample").asInt() + "," + eligible + ","
                            + (seen == null ? "" : seen) + "," + identifiers.getOrDefault(entry.getKey(), "") + ","
                            + (seconds == null ? "" : seconds) + "," + passed + "\n");
                    writer.flush();
                    System.out.println("AWS FX incident sample " + entry.getValue().path("sample").asInt()
                            + ": " + (passed ? "PASS" : "FAIL"));
                }
            }
            values.sort(Double::compare);
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("passed", failed == 0); summary.put("environment", "AWS");
            summary.put("samples", 60); summary.put("failed_samples", failed);
            summary.put("model_version", model.activeModelVersion()); summary.put("data_provenance", "DEMO_ONLY");
            summary.put("p50_seconds", values.isEmpty() ? null : values.get((int) Math.ceil(values.size() * .5) - 1));
            summary.put("p95_seconds", values.isEmpty() ? null : values.get((int) Math.ceil(values.size() * .95) - 1));
            summary.put("method", "Closed historic ABNORMAL fixtures: commit ACK until matching incident is available in the real FX-thread table model; two samples per batch; default worker and 15s UI refresh intervals unchanged.");
            summary.put("limitation", "UI-available table rows, not all simultaneously onscreen; does not benchmark collection of live HTTP behavior before window closure.");
            Path summaryFile = output.resolve("incident-latency-summary.json");
            try (var stream = Files.newOutputStream(summaryFile, StandardOpenOption.CREATE_NEW)) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(stream, summary);
            }
            assertEquals(0, failed, "All 30 light-load UI samples must meet the 90-second target");
        } finally {
            Platform.runLater(() -> stageRef.get().close());
            api.logout().get(15, TimeUnit.SECONDS);
        }
    }
}
