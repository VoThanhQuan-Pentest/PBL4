package com.flarefitness.monitor.ui;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.FlareSecurityApp;
import com.flarefitness.monitor.model.SiemModels;
import java.awt.image.BufferedImage;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.image.WritableImage;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;

class AccountWatchVisualSmokeTest {
    @Test
    void rendersNeutralBaselineCoverageAndExportsOptionalQaScreenshot() throws Exception {
        assumeTrue(System.getenv("DISPLAY") != null, "A display is required for visual QA.");
        try { Platform.startup(() -> Platform.setImplicitExit(false)); }
        catch (IllegalStateException alreadyRunning) { Platform.setImplicitExit(false); }
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Throwable> failed = new AtomicReference<>();
        Platform.runLater(() -> {
            Stage stage = new Stage();
            try {
                LocalDateTime at = LocalDateTime.of(2026, 9, 30, 12, 0);
                var pane = new AccountWatchPane(() -> { }, (id, detail) -> detail.getChildren().setAll(
                        new Label("Customer " + id), new Label("Baseline snapshot: 30/09 12:00 UTC"),
                        new Label("Coverage gap is not evidence of compromise.")));
                Scene scene = new Scene(pane, 1440, 900);
                scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                stage.setScene(scene);
                stage.show();
                ((ComboBox<?>) pane.lookup("#baseline-view-filter")).getSelectionModel().select(1);
                var customers = List.of(
                        new SiemModels.WatchAccount("demo-no-history", 0, null, 0, "NO_DATA", 0, 30, 14, at, false),
                        new SiemModels.WatchAccount("demo-new-customer", 0, at.minusMinutes(15), 0, "INSUFFICIENT_HISTORY", 1, 30, 14, at, true),
                        new SiemModels.WatchAccount("demo-near-ready", 0, at.minusMinutes(15), 0, "INSUFFICIENT_HISTORY", 29, 30, 14, at, true));
                pane.accept(new SiemModels.Page<>(customers, 0, 50, 3, 1, false));
                ((TableView<?>) pane.lookup("#account-watch-table")).getSelectionModel().select(2);
                pane.applyCss();
                pane.layout();
                assertEquals("BASELINE_GAPS", pane.view());
                assertFalse(pane.lookupAll(".baseline-gap").isEmpty());
                String output = System.getProperty("flare.baseline.screenshot");
                if (output != null && !output.isBlank()) {
                    WritableImage snapshot = pane.snapshot(null, null);
                    BufferedImage image = new BufferedImage((int) snapshot.getWidth(), (int) snapshot.getHeight(), BufferedImage.TYPE_INT_ARGB);
                    for (int y = 0; y < image.getHeight(); y++) for (int x = 0; x < image.getWidth(); x++)
                        image.setRGB(x, y, snapshot.getPixelReader().getArgb(x, y));
                    assertTrue(ImageIO.write(image, "png", Path.of(output).toFile()));
                }
            } catch (Throwable problem) { failed.set(problem); }
            finally { stage.close(); done.countDown(); }
        });
        assertTrue(done.await(15, TimeUnit.SECONDS), "Visual QA timed out");
        if (failed.get() != null) throw new AssertionError("Baseline visual QA failed", failed.get());
    }
}
