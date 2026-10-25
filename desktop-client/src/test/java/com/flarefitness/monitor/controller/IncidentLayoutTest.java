package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import static com.flarefitness.monitor.controller.WorkspaceInteractionTest.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.model.SiemModels;
import com.flarefitness.monitor.ui.IncidentPresentationTest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;

class IncidentLayoutTest {
    @BeforeAll static void toolkit() { WorkspaceInteractionTest.toolkit(); }
    static SiemModels.Incident item(String status, boolean assigned) {
        return IncidentPresentationTest.incident("AUTH_BRUTE_TARGET", "Điều tra tài khoản · AUTH_BRUTE_TARGET", "",
                assigned ? "staff-opaque-id" : null, assigned ? new SiemModels.AssignedAnalyst("James", "SOC_L1") : null, status);
    }
    static final class Api extends WorkspaceInteractionTest.Api {
        String incidentStatus = "IN_PROGRESS";
        final AtomicInteger historyRequests = new AtomicInteger();
        final List<String> timelineTypes = new ArrayList<>();
        @Override public CompletableFuture<SiemModels.Page<SiemModels.Incident>> incidents(SiemModels.IncidentQuery query) {
            return CompletableFuture.completedFuture(new SiemModels.Page<>(List.of(item("NEW", false), item("IN_PROGRESS", true)), 0, 50, 2, 1, false));
        }
        @Override public CompletableFuture<SiemModels.IncidentDetail> incident(String id) {
            return CompletableFuture.completedFuture(new SiemModels.IncidentDetail(item(incidentStatus, true), List.of()));
        }
        @Override public CompletableFuture<List<SiemModels.History>> incidentHistory(String id) {
            historyRequests.incrementAndGet();
            return CompletableFuture.completedFuture(List.of(new SiemModels.History("h", "a", "staff", "CLOSE", "IN_PROGRESS", "CLOSED", "Analyst completed recovery", LocalDateTime.now())));
        }
        @Override public CompletableFuture<SiemModels.TimelinePage> incidentTimeline(String id, String types, boolean related, String cursor) {
            timelineTypes.add(types);
            try {
                var hit = new ObjectMapper().readTree("{\"_index\":\"logs-flare.security-lab\",\"_id\":\"log\",\"_source\":{\"@timestamp\":\"2026-10-24T01:02:03Z\",\"source\":{\"ip\":\"192.0.2.25\"},\"event\":{\"action\":\"LOGIN\"}}}");
                return CompletableFuture.completedFuture(new SiemModels.TimelinePage(List.of(
                        new SiemModels.TimelineEntry("log", "ELK", LocalDateTime.now(), hit, null, null),
                        new SiemModels.TimelineEntry("history", "WORKFLOW", LocalDateTime.now(), null, null, new ObjectMapper().readTree("{\"action\":\"CLOSE\"}"))), null, "AVAILABLE", LocalDateTime.now()));
            } catch (Exception error) { return CompletableFuture.failedFuture(error); }
        }
    }
    static void refreshDetail(DashboardController controller) throws Exception {
        var method = DashboardController.class.getDeclaredMethod("loadIncidentDetail", String.class);
        method.setAccessible(true); method.invoke(controller, "a");
    }
    record Workspace(DashboardController controller, Stage stage) implements AutoCloseable {
        @Override public void close() throws Exception { fx(() -> { controller.dispose(); stage.close(); return null; }); }
    }
    static Workspace workspace(Api api) throws Exception {
        return fx(() -> {
            FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
            Parent root = loader.load(); DashboardController controller = loader.getController(); Stage stage = new Stage();
            Scene scene = new Scene(root, 1366, 768); scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
            stage.setScene(scene); stage.show(); controller.initializeSession(api, new SiemModels.User("l1", "l1", "SOC L1", "Analyst", null, null));
            return new Workspace(controller, stage);
        });
    }
    @Test void queueShowsShortScenarioOnlySourceIpAssigneeIdentityAndOccurrenceTime() throws Exception {
        try (var workspace = workspace(new Api())) {
            fx(() -> null);
            fx(() -> {
                var table = (TableView<?>) field(workspace.controller(), "incidentTable");
                Map<String, TableColumn<?, ?>> columns = new LinkedHashMap<>(); table.getColumns().forEach(c -> columns.put(c.getText(), c));
                assertEquals("Sign in brute force", columns.get("Tình huống").getCellData(0));
                assertEquals("192.0.2.25", columns.get("Nguồn").getCellData(0));
                assertEquals("Chưa có người nhận", columns.get("Người nhận").getCellData(0));
                assertEquals("James-SOC_L1", columns.get("Người nhận").getCellData(1));
                assertEquals("24/10 08:02:03", columns.get("Thời gian xảy ra").getCellData(0));
                assertFalse(columns.containsKey("Lần cuối")); snapshot(workspace.stage().getScene().getRoot(), "queue-requested-layout-1366x768"); return null;
            });
        }
    }
    @Test void twoTabsKeepTreatmentBelowInformationAndSeparateLogEventsFromCompletedProcessing() throws Exception {
        Api api = new Api();
        try (var workspace = workspace(api)) {
            fx(() -> { open(workspace.controller(), "a"); return null; }); fx(() -> null); fx(() -> null);
            Stage detail = fx(() -> (Stage) field(workspace.controller(), "incidentStage"));
            fx(() -> {
                Parent root = detail.getScene().getRoot(); root.applyCss(); root.layout();
                TabPane tabs = (TabPane) root.lookup("#incident-tabs");
                assertEquals(List.of("Thông tin log", "Dòng thời gian log"), tabs.getTabs().stream().map(Tab::getText).toList());
                assertEquals(0, tabs.getSelectionModel().getSelectedIndex());
                ScrollPane scroll = (ScrollPane) tabs.getTabs().getFirst().getContent(); Parent info = (Parent) scroll.getContent();
                Node summary = info.lookup(".investigation-header"), treatment = info.lookup("#incident-treatment");
                assertTrue(treatment.getBoundsInParent().getMinY() >= summary.getBoundsInParent().getMaxY());
                assertNull(info.lookup("#incident-handling-history")); assertEquals(0, api.historyRequests.get());
                snapshot(root, "incident-information-requested-layout-1366x768");
                tabs.getSelectionModel().select(1); root.applyCss(); root.layout();
                Parent timeline = (Parent) tabs.getTabs().get(1).getContent();
                TableView<?> table = (TableView<?>) timeline.lookup(".table-view"); assertEquals(1, table.getItems().size());
                assertTrue(table.getItems().stream().allMatch(row -> row instanceof SiemModels.TimelineEntry entry && "ELK".equals(entry.kind())));
                assertEquals(List.of("ELK"), api.timelineTypes); assertTrue(timeline.lookupAll(".combo-box").isEmpty());
                snapshot(root, "incident-log-timeline-requested-layout-1366x768");
                assertTrue(detail.isResizable()); assertEquals(javafx.stage.StageStyle.DECORATED, detail.getStyle());
                ((Button) root.lookup("#incident-fullscreen")).fire(); assertTrue(detail.isFullScreen());
                root.fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED, "", "", KeyCode.F11, false, false, false, false)); assertFalse(detail.isFullScreen());
                detail.setMaximized(true); assertTrue(detail.isMaximized()); detail.setMaximized(false);
                detail.setWidth(1920); detail.setHeight(1080); tabs.getSelectionModel().select(0); snapshot(root, "incident-information-requested-layout-1920x1080");
                api.incidentStatus = "CLOSED"; refreshDetail(workspace.controller()); return null;
            }); fx(() -> null); fx(() -> null);
            fx(() -> {
                assertSame(detail, field(workspace.controller(), "incidentStage"));
                assertNotNull(detail.getScene().lookup("#incident-handling-history")); assertEquals(1, api.historyRequests.get());
                api.incidentStatus = "IN_PROGRESS"; refreshDetail(workspace.controller()); return null;
            }); fx(() -> null); fx(() -> null);
            fx(() -> { assertNull(detail.getScene().lookup("#incident-handling-history")); assertEquals(1, api.historyRequests.get()); return null; });
        }
    }
}
