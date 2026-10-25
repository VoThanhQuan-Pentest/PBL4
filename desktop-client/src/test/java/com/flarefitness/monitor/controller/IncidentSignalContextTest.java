package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.model.SiemModels;
import com.flarefitness.monitor.ui.BehaviorSignalSummary;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class IncidentSignalContextTest {
    private static final LocalDateTime AT = LocalDateTime.of(2026, 10, 1, 12, 0);

    @BeforeAll static void toolkit() {
        assumeTrue(System.getenv("DISPLAY") != null, "Run with xvfb-run for JavaFX node verification.");
        try { Platform.startup(() -> Platform.setImplicitExit(false)); }
        catch (IllegalStateException alreadyRunning) { Platform.setImplicitExit(false); }
    }

    @Test void uebaDetailSeparatesHttp503FromACompromiseVerdictAndKeepsManualWorkflow() throws Exception {
        onFx(() -> {
            var window = new SiemModels.BehaviorWindow("window-1", "account-1", AT, AT.plusMinutes(15),
                    100, true, Map.of("http_5xx_count", 25.0), "203.0.113.20", "Other", "ABNORMAL",
                    "SCORED_MODEL", "model-1", 99.9, 100, "High anomaly percentile", 4, 4);
            VBox root = render("UEBA", List.of(window));
            Stage stage = stage(root);
            try {
                Label context = (Label) root.lookup("#ueba-signal-context");
                assertNotNull(context);
                assertTrue(context.getText().startsWith("Service-error signal (possible operational fault)"));
                assertTrue(context.getText().contains(BehaviorSignalSummary.CAUTION));
                assertTrue(context.getText().contains("missing or paginated evidence"));
                assertFalse(context.getText().contains("CONFIRMED_ATTACK"));
                assertTrue(root.lookupAll(".note-card").stream().anyMatch(node -> node instanceof Label label
                        && label.getText().contains("Service-error signal")));
                List<String> actions = root.lookupAll(".button").stream()
                        .filter(Button.class::isInstance).map(Button.class::cast).map(Button::getText).toList();
                assertTrue(actions.contains("Claim"));
                assertFalse(actions.contains("Close"));
                assertFalse(actions.contains("Revoke customer sessions"));
            } finally { stage.close(); }
        });
    }

    @Test void noRetainedEvidenceDoesNotFabricateAnOperationalOrSecurityVerdict() throws Exception {
        onFx(() -> {
            VBox root = render("UEBA", List.of());
            Stage stage = stage(root);
            try {
                Label context = (Label) root.lookup("#ueba-signal-context");
                assertTrue(context.getText().startsWith("Cause undetermined"));
                assertTrue(context.getText().contains("not attack confirmation"));
            } finally { stage.close(); }
        });
    }

    @Test void nonUebaIncidentWorkflowIsUnchanged() throws Exception {
        onFx(() -> {
            VBox root = render("PREVENTION", List.of());
            Stage stage = stage(root);
            try { assertNull(root.lookup("#ueba-signal-context")); }
            finally { stage.close(); }
        });
    }

    @SuppressWarnings("unchecked")
    private static VBox render(String origin, List<SiemModels.BehaviorWindow> windows) throws Exception {
        var controller = new DashboardController();
        Field apiField=DashboardController.class.getDeclaredField("api");apiField.setAccessible(true);
        apiField.set(controller,new com.flarefitness.monitor.api.SiemApiClient("http://127.0.0.1:8089") {
            @Override public java.util.concurrent.CompletableFuture<SiemModels.EvidencePage> incidentEvidence(String id,String cursor) {
                return java.util.concurrent.CompletableFuture.completedFuture(new SiemModels.EvidencePage(List.of(),null,"NO_DETECTION_LOG"));
            }
            @Override public java.util.concurrent.CompletableFuture<List<SiemModels.ContainmentAction>> containment(String id) {
                return java.util.concurrent.CompletableFuture.completedFuture(List.of());
            }
        });
        Field userField = DashboardController.class.getDeclaredField("signedInUser");
        userField.setAccessible(true);
        userField.set(controller, new SiemModels.User("analyst-1", "analyst", "SOC L2", null, null, null));
        var incident = new SiemModels.Incident("case-1", "Anomaly needs triage", "flare", "UEBA_ACCOUNT",
                "203.0.113.20", AT, "HIGH", 95, "HIGH", "INVESTIGATE", "Anomaly needs triage",
                false, "NEW", "UNREVIEWED", null, false, 1, 1, AT, AT, AT, 0, "L2", origin, "account-1");
        Class<?> bundleType = Class.forName(DashboardController.class.getName() + "$IncidentBundle");
        Constructor<?> constructor = bundleType.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object bundle = constructor.newInstance(new SiemModels.IncidentDetail(incident, List.of()),
                List.of(), List.of(), List.of(), windows, List.of(), 0L, List.of());
        Method method = DashboardController.class.getDeclaredMethod("incidentDetailNodes", bundleType);
        method.setAccessible(true);
        return new VBox(12, ((List<Node>) method.invoke(controller, bundle)).toArray(Node[]::new));
    }

    private static Stage stage(VBox root) {
        Stage stage = new Stage();
        Scene scene = new Scene(root, 1200, 1000);
        scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
        stage.setScene(scene);
        stage.show();
        root.applyCss();
        root.lookupAll(".titled-pane").forEach(node->((javafx.scene.control.TitledPane)node).setExpanded(true));
        root.applyCss();root.layout();
        root.lookupAll(".titled-pane").forEach(node->((javafx.scene.control.TitledPane)node).setExpanded(true));
        root.applyCss();root.layout();
        return stage;
    }

    private static void onFx(FxAction action) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();
        Platform.runLater(() -> {
            try { action.run(); } catch (Throwable problem) { error.set(problem); } finally { done.countDown(); }
        });
        assertTrue(done.await(15, TimeUnit.SECONDS), "JavaFX rendering timed out");
        if (error.get() != null) throw new AssertionError("JavaFX rendering failed", error.get());
    }

    @FunctionalInterface private interface FxAction { void run() throws Exception; }
}
