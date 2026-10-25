package com.flarefitness.monitor.ui;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.model.SiemModels;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.stage.Stage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AccountWatchPaneTest {
    private static final LocalDateTime AT = LocalDateTime.of(2026, 9, 30, 12, 0);

    @BeforeAll static void toolkit() {
        assumeTrue(System.getenv("DISPLAY") != null, "Run with xvfb-run to verify actual JavaFX nodes.");
        try { Platform.startup(() -> Platform.setImplicitExit(false)); }
        catch (IllegalStateException alreadyRunning) { Platform.setImplicitExit(false); }
    }

    static IntStream states() { return IntStream.range(0, 108); }
    static IntStream interactions() { return IntStream.range(0, 12); }

    @ParameterizedTest(name = "render-state-{0}")
    @MethodSource("states")
    void rendersCoverageRiskAndTransportStatesOnFxThread(int scenario) throws Exception {
        onFx(() -> {
            int cohort = scenario % 6;
            int view = scenario / 6 % 3;
            boolean scored = scenario / 18 % 2 == 1;
            int transport = scenario / 36;
            var pane = new AccountWatchPane(() -> { }, (id, detail) -> { });
            Stage stage = stage(pane);
            try {
                var filter = (ComboBox<?>) pane.lookup("#baseline-view-filter");
                filter.getSelectionModel().select(view);
                assertEquals(List.of("RISK", "BASELINE_GAPS", "ALL").get(view), pane.view());
                SiemModels.WatchAccount account = account(cohort, scored, "state-" + scenario);
                pane.accept(new SiemModels.Page<>(List.of(account), 0, 50, 1, 1, false));
                if (transport == 1) pane.accept(new SiemModels.Page<>(List.of(), 0, 50, 0, 0, false));
                if (transport == 2) { pane.loading(); pane.error("Fixture transport unavailable"); }
                pane.applyCss();
                pane.layout();
                assertTrue(pane.lookupAll(".muted").stream().anyMatch(node -> node instanceof Label label
                        && label.getText().contains(BehaviorSignalSummary.CAUTION)));
                var table = table(pane);
                if (transport == 1) assertTrue(table.getItems().isEmpty());
                else {
                    assertEquals(1, table.getItems().size());
                    assertEquals(account.baselineStatus(), table.getItems().getFirst().baselineStatus());
                    assertEquals(scored ? 45 : "—", table.getColumns().get(1).getCellObservableValue(0).getValue());
                    assertEquals(account.trustedWindowCount() + "/30",
                            table.getColumns().get(3).getCellObservableValue(0).getValue());
                    if (!"READY".equals(account.baselineStatus())) assertFalse(pane.lookupAll(".baseline-gap").isEmpty());
                }
                if (transport == 2) assertTrue(pane.lookupAll(".error-text").stream()
                        .anyMatch(node -> node instanceof Label label && label.getText().contains("transport")));
            } finally { stage.close(); }
        });
    }

    @ParameterizedTest(name = "interaction-{0}")
    @MethodSource("interactions")
    void paginationAndRefreshPreserveTheActiveFilterAndSelection(int scenario) throws Exception {
        onFx(() -> {
            AtomicInteger refresh = new AtomicInteger();
            AtomicReference<String> selected = new AtomicReference<>();
            var pane = new AccountWatchPane(refresh::incrementAndGet, (id, detail) -> selected.set(id));
            Stage stage = stage(pane);
            try {
                int view = scenario % 3;
                ((ComboBox<?>) pane.lookup("#baseline-view-filter")).getSelectionModel().select(view);
                var a = account(1, false, "account-a-" + scenario);
                var b = account(3, true, "account-b-" + scenario);
                pane.accept(new SiemModels.Page<>(List.of(a, b), 0, 50, 500, 10, true));
                var table = table(pane);
                table.getSelectionModel().select(a);
                assertEquals(a.accountId(), selected.get());
                table.getSelectionModel().select(b);
                assertEquals(b.accountId(), pane.selectedAccountId());
                pane.loading();
                pane.accept(new SiemModels.Page<>(List.of(a, b), 0, 50, 500, 10, true));
                assertEquals(b.accountId(), pane.selectedAccountId());
                assertEquals(List.of("RISK", "BASELINE_GAPS", "ALL").get(view), pane.view());
                ((Button) pane.lookup("#watch-next-page")).fire();
                assertEquals(1, pane.page());
                pane.accept(new SiemModels.Page<>(List.of(a), 1, 50, 500, 10, true));
                ((Button) pane.lookup("#watch-previous-page")).fire();
                assertEquals(0, pane.page());
                assertTrue(refresh.get() >= 2);
                pane.accept(new SiemModels.Page<>(List.of(), 9, 50, 500, 10, false));
                assertTrue(((Button) pane.lookup("#watch-next-page")).isDisabled());
                assertFalse(((Button) pane.lookup("#watch-previous-page")).isDisabled());
            } finally { stage.close(); }
        });
    }

    @SuppressWarnings("unchecked")
    private static TableView<SiemModels.WatchAccount> table(AccountWatchPane pane) {
        return (TableView<SiemModels.WatchAccount>) pane.lookup("#account-watch-table");
    }

    private static SiemModels.WatchAccount account(int cohort, boolean scored, String id) {
        int count = new int[]{0, 1, 29, 30, 31, 0}[cohort];
        String status = cohort == 0 || cohort == 5 ? "NO_DATA"
                : count < 30 ? "INSUFFICIENT_HISTORY" : "READY";
        return new SiemModels.WatchAccount(id, scored ? 45 : 0, AT.minusMinutes(15), scored ? 1 : 0,
                status, count, 30, 14, AT, scored);
    }

    private static Stage stage(AccountWatchPane pane) {
        Stage stage = new Stage();
        Scene scene = new Scene(pane, 1440, 900);
        scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
        stage.setScene(scene);
        stage.show();
        pane.applyCss();
        pane.layout();
        return stage;
    }

    private static void onFx(Runnable action) throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Throwable> error = new AtomicReference<>();
        Platform.runLater(() -> { try { action.run(); } catch (Throwable problem) { error.set(problem); } finally { done.countDown(); } });
        assertTrue(done.await(15, TimeUnit.SECONDS), "FX interaction timed out");
        if (error.get() != null) throw new AssertionError("FX interaction failed", error.get());
    }
}
