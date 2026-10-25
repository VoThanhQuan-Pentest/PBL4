package com.flarefitness.monitor;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.controller.DashboardController;
import com.flarefitness.monitor.model.SiemModels;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableView;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;

/** Headless rendering of controls only; never claims human rehearsal/24-hour proof. */
class UebaShadowSettingsVisualTest {
    @Test
    void rendersSeparateShadowTableAndBlocksStrictActivationBeforeRealObservation() throws Exception {
        assumeTrue(System.getenv("DISPLAY") != null, "requires xvfb-run");
        try { Platform.startup(() -> Platform.setImplicitExit(false)); }
        catch (IllegalStateException alreadyStarted) { Platform.setImplicitExit(false); }
        var complete = new CountDownLatch(1); var failure = new AtomicReference<Throwable>();
        Platform.runLater(() -> {
            Stage stage = null;
            try {
                var loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
                BorderPane root = loader.load(); DashboardController controller = loader.getController();
                LocalDateTime now = LocalDateTime.now();
                Map<String, Object> bounds = Map.of("precision", Map.of("available", true, "lower", 0.9995, "upper", 1.0),
                        "recall", Map.of("available", true, "lower", 0.9995, "upper", 1.0),
                        "false_positive_rate", Map.of("available", true, "lower", 0.0, "upper", 0.000001));
                Map<String, Object> counts = Map.of("tp", 10000, "fn", 0, "fp", 0, "tn", 10000000, "quality_gate", "PASS",
                        "confidence", Map.of("conservative", bounds));
                var job = new SiemModels.UebaTrainingJob("owned-ui-job", "owned-ui-candidate", "SUCCEEDED", "DEMO_ONLY", 50000, 2000000,
                        now, null, 2, "owned-ui-recipe", "owned-ui-dataset", "SUCCEEDED", "PASS",
                        Map.of("scopes", Map.of("MODEL_ONLY", counts, "SIEM_FINAL", counts)));
                field(controller, "lastTrainingJob", job); field(controller, "currentView", "settings");
                var jobs = new SiemModels.Page<>(List.of(job), 1, 20, 21, 2, false);
                var run = new SiemModels.UebaShadowRun("a".repeat(32), job.modelVersion(), "RUNNING", "DEMO_ONLY", now, now,
                        120, null, Map.of("elapsed_monotonic_seconds", 3600, "closed_windows", 120, "clock_provenance", "REAL_SERVER_CLOCK"));
                var shadows = new SiemModels.Page<>(List.of(run), 0, 20, 1, 1, false);
                Node modelPanel = invoke(controller, "uebaAdminActions", new Class<?>[]{SiemModels.Page.class, List.class}, jobs, List.of());
                Node shadowPanel = invoke(controller, "shadowAdminActions", new Class<?>[]{SiemModels.Page.class}, shadows);
                var scroll = new ScrollPane(new VBox(14, modelPanel, shadowPanel)); scroll.setFitToWidth(true);
                ((VBox) root.getCenter()).getChildren().setAll(scroll);
                stage = new Stage(); stage.setScene(new Scene(root, 1440, 1200));
                stage.getScene().getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                stage.show(); root.applyCss(); root.layout();
                Button activate = (Button) root.lookup("#ueba-activate-candidate"); Button start = (Button) root.lookup("#ueba-start-shadow");
                assertNotNull(activate); assertTrue(activate.isDisabled()); assertNotNull(start); assertFalse(start.isDisabled());
                TableView<?> table = (TableView<?>) root.lookup("#ueba-shadow-runs"); assertNotNull(table); assertEquals(1, table.getItems().size());
                assertEquals(6, table.getColumns().size());
                String imagePath = System.getProperty("flare.shadow.screenshot");
                if (imagePath != null) {
                    var snapshot = root.snapshot(null, null); var image = new java.awt.image.BufferedImage((int) snapshot.getWidth(),
                            (int) snapshot.getHeight(), java.awt.image.BufferedImage.TYPE_INT_ARGB);
                    for (int y = 0; y < image.getHeight(); y++) for (int x = 0; x < image.getWidth(); x++) image.setRGB(x, y, snapshot.getPixelReader().getArgb(x, y));
                    javax.imageio.ImageIO.write(image, "png", java.nio.file.Path.of(imagePath).toFile());
                }
            } catch (Throwable problem) { failure.set(problem); }
            finally { if (stage != null) stage.close(); complete.countDown(); }
        });
        assertTrue(complete.await(30, TimeUnit.SECONDS), "render timeout");
        if (failure.get() != null) throw new AssertionError("shadow settings rendering failed", failure.get());
    }
    private static void field(Object target, String name, Object value) throws Exception {
        Field field = DashboardController.class.getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }
    private static Node invoke(Object target, String name, Class<?>[] types, Object... values) throws Exception {
        Method method = DashboardController.class.getDeclaredMethod(name, types); method.setAccessible(true); return (Node) method.invoke(target, values);
    }
}
