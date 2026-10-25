package com.flarefitness.monitor;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.monitor.api.SiemApiClient;
import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.model.SiemModels;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;

/** Opt-in acceptance against the deployed owned AWS lab, never a synthetic UI fixture. */
class AwsJavaFxLiveTest {
    @Test
    void authenticatesL1PersistsAClaimAndRendersTheCloudDashboard() throws Exception {
        String credentialFile = System.getenv("FLARE_AWS_LIVE_CREDENTIALS");
        String outputDirectory = System.getenv("FLARE_AWS_LIVE_OUTPUT");
        String fixtureDataset = System.getenv("FLARE_AWS_FIXTURE_DATASET");
        assumeTrue(credentialFile != null && outputDirectory != null,
                "AWS live acceptance requires explicit private credentials and output directory");
        assumeTrue(System.getenv("DISPLAY") != null, "Use xvfb-run for JavaFX rendering");
        Path credentialPath = Path.of(credentialFile);
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(credentialPath));
        if (fixtureDataset != null) {
            assertTrue(fixtureDataset.matches("[a-z0-9][a-z0-9_-]{3,23}"),
                    "AWS fixture dataset must be an explicit synthetic dataset ID");
        }
        String expectedFixtureTarget = fixtureDataset == null ? null : "ueba-demo-" + fixtureDataset + "-1";
        var incidentQuery = expectedFixtureTarget == null ? SiemModels.IncidentQuery.openPriority()
                : new SiemModels.IncidentQuery(0, 50, null, null, null, null, "OPEN", "PRIORITY",
                        null, null, "L1", "UEBA", expectedFixtureTarget, false);
        ObjectMapper mapper = new ObjectMapper();
        var credential = mapper.readTree(credentialPath.toFile()).path("accounts").path("l1");
        SiemApiClient api = new SiemApiClient("http://127.0.0.1:18089");
        var login = api.login(credential.path("username").asText(), credential.path("password").asText())
                .get(20, TimeUnit.SECONDS);
        assertEquals(credential.path("id").asText(), login.user().id());
        assertEquals("SOC L1", login.user().role());
        var status = api.status().get(15, TimeUnit.SECONDS);
        assertTrue(status.enabled());
        assertTrue(status.elasticsearchAvailable());
        var model = api.uebaStatus().get(15, TimeUnit.SECONDS);
        assertTrue(model.modelAvailable());
        assertEquals("DEMO_ONLY", model.activeModelProvenance());
        SiemModels.Incident incident = null;
        for (int attempt = 0; attempt < 45 && incident == null; attempt++) {
            incident = api.incidents(incidentQuery).get(15, TimeUnit.SECONDS)
                    .content().stream().filter(item -> "UEBA".equals(item.origin())
                            && "L1".equals(item.queueTier()) && item.assigneeUserId() == null
                            && (expectedFixtureTarget == null || expectedFixtureTarget.equals(item.targetUserId())))
                    .findFirst().orElse(null);
            if (incident == null) Thread.sleep(2000);
        }
        assertNotNull(incident, "The cloud abnormal fixture must produce an unassigned L1 UEBA incident");
        var claimed = api.transitionIncident(incident, "CLAIM", null, null).get(15, TimeUnit.SECONDS);
        assertEquals(login.user().id(), claimed.assigneeUserId());
        var stored = api.incident(claimed.id()).get(15, TimeUnit.SECONDS).incident();
        assertEquals(claimed.version(), stored.version());
        assertEquals(login.user().id(), stored.assigneeUserId());

        Path output = Path.of(outputDirectory);
        Files.createDirectories(output);
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"));
        try {
            Platform.startup(() -> { });
        } catch (IllegalStateException alreadyRunning) {
            // Toolkit can be shared with the ordinary FXML tests.
        }
        CountDownLatch loaded = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<BorderPane> rootRef = new AtomicReference<>();
        AtomicReference<Stage> stageRef = new AtomicReference<>();
        Platform.runLater(() -> {
            try {
                FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
                BorderPane root = loader.load();
                DashboardController controller = loader.getController();
                Stage stage = new Stage();
                stage.setScene(new Scene(root, 1440, 1000));
                stage.getScene().getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                rootRef.set(root);
                stageRef.set(stage);
                controller.initializeSession(api, login.user());
                stage.show();
            } catch (Throwable error) {
                failure.set(error);
            } finally {
                loaded.countDown();
            }
        });
        assertTrue(loaded.await(20, TimeUnit.SECONDS));
        if (failure.get() != null) throw new AssertionError("Live FXML initialization failed", failure.get());
        boolean rendered = false;
        try {
            for (int attempt = 0; attempt < 60 && !rendered; attempt++) {
                CountDownLatch inspected = new CountDownLatch(1);
                AtomicReference<Boolean> ready = new AtomicReference<>(false);
                Platform.runLater(() -> {
                    try {
                        BorderPane root = rootRef.get();
                        Label connection = (Label) root.lookup("#connectionLabel");
                        if (connection != null && "ELASTIC ONLINE".equals(connection.getText())) {
                            root.applyCss();
                            root.layout();
                            assertEquals(5, root.lookupAll(".donut-card").size());
                            WritableImage snapshot = root.snapshot(null, null);
                            BufferedImage image = new BufferedImage((int) snapshot.getWidth(),
                                    (int) snapshot.getHeight(), BufferedImage.TYPE_INT_ARGB);
                            for (int y = 0; y < image.getHeight(); y++) {
                                for (int x = 0; x < image.getWidth(); x++) {
                                    image.setRGB(x, y, snapshot.getPixelReader().getArgb(x, y));
                                }
                            }
                            ImageIO.write(image, "png", output.resolve("javafx-aws-l1.png").toFile());
                            ready.set(true);
                        }
                    } catch (Throwable error) {
                        failure.set(error);
                    } finally {
                        inspected.countDown();
                    }
                });
                assertTrue(inspected.await(10, TimeUnit.SECONDS));
                if (failure.get() != null) throw new AssertionError("Live dashboard render failed", failure.get());
                rendered = ready.get();
                if (!rendered) Thread.sleep(500);
            }
            assertTrue(rendered, "Dashboard must render successful responses from AWS, not fixture data");
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("passed", true);
            result.put("environment", "AWS");
            result.put("render_mode", "JavaFX on Xvfb");
            result.put("server", "http://127.0.0.1:18089");
            result.put("role", "SOC L1");
            result.put("model_provenance", "DEMO_ONLY");
            result.put("incident_id", claimed.id());
            result.put("claim_persisted", true);
            result.put("observed_at", Instant.now().toString());
            if (fixtureDataset != null) result.put("fixture_dataset", fixtureDataset);
            mapper.writeValue(output.resolve("javafx-live-result.json").toFile(), result);
        } finally {
            Platform.runLater(() -> stageRef.get().close());
            api.logout().get(15, TimeUnit.SECONDS);
        }
    }
}
