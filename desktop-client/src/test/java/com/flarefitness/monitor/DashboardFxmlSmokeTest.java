package com.flarefitness.monitor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.model.SiemModels;
import com.flarefitness.monitor.ui.OverviewPane;
import java.awt.image.BufferedImage;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.ScrollPane;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.junit.jupiter.api.Test;

class DashboardFxmlSmokeTest {
    @Test
    void loadsFiveNavigationItemsAndPrioritizesWorkAboveCompactCharts() throws Exception {
        assumeTrue(System.getenv("DISPLAY") != null, "JavaFX rendering requires a display or xvfb-run");
        try {
            Platform.startup(() -> Platform.setImplicitExit(false));
        } catch (IllegalStateException alreadyRunning) {
            // The toolkit is shared by tests in the same JVM.
            Platform.setImplicitExit(false);
        }
        CountDownLatch finished = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Platform.runLater(() -> {
            Stage stage = null;
            try {
                FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/dashboard.fxml"));
                BorderPane root = loader.load();
                assertNotNull(loader.getController());
                VBox host = (VBox) root.getCenter();
                OverviewPane overview = new OverviewPane(ignored -> { }, ignored -> { }, () -> { }, () -> { });
                LocalDateTime now = LocalDateTime.now();
                overview.update(new SiemModels.DashboardSummary(now.minusDays(1), now,
                        22, 15, 2, 5,
                        Map.of("URGENT", 3L, "HIGH", 7L, "MEDIUM", 8L, "LOW", 4L),
                        Map.of("NEW", 9L, "IN_PROGRESS", 8L, "CLOSED", 5L),
                        Map.of("INVESTIGATE", 20L, "POTENTIAL_NOISE", 2L),
                        Map.of("L1", 14L, "L2", 8L),
                        Map.of("ELASTIC", 12L, "UEBA", 10L)), List.of());
                ScrollPane scroll = new ScrollPane(overview);
                scroll.setFitToWidth(true);
                host.getChildren().add(scroll);
                stage = new Stage();
                stage.setScene(new Scene(root, 1440, 1500));
                stage.getScene().getStylesheets().add(FlareSecurityApp.class
                        .getResource("/css/siem.css").toExternalForm());
                stage.show();
                root.applyCss();
                root.layout();
                assertEquals(5, root.lookupAll(".nav-button").size());
                assertEquals(java.util.Set.of("Dashboard","Incident queue","Block IP","History","GeoIP & IP intelligence"),
                        root.lookupAll(".nav-button").stream().map(node -> ((javafx.scene.control.Button)node).getText()).collect(java.util.stream.Collectors.toSet()));
                assertEquals(0, root.lookupAll(".donut-card").size());
                assertEquals(1, root.lookupAll(".bar-chart").size());
                assertEquals(4, root.lookupAll(".metric-card").size());
                var queue=root.lookup(".table-view");var chart=root.lookup(".bar-chart");
                assertTrue(queue.localToScene(queue.getBoundsInLocal()).getMinY()<chart.localToScene(chart.getBoundsInLocal()).getMinY(),"Priority queue must precede charts");
                String screenshot = System.getProperty("flare.soc.screenshot");
                if (screenshot != null && !screenshot.isBlank()) {
                    WritableImage snapshot = root.snapshot(null, null);
                    BufferedImage image = new BufferedImage((int) snapshot.getWidth(),
                            (int) snapshot.getHeight(), BufferedImage.TYPE_INT_ARGB);
                    for (int y = 0; y < image.getHeight(); y++) {
                        for (int x = 0; x < image.getWidth(); x++) {
                            image.setRGB(x, y, snapshot.getPixelReader().getArgb(x, y));
                        }
                    }
                    ImageIO.write(image, "png", Path.of(screenshot).toFile());
                }
            } catch (Throwable throwable) {
                failure.set(throwable);
            } finally {
                if (stage != null) stage.close();
                finished.countDown();
            }
        });
        assumeTrue(finished.await(30, TimeUnit.SECONDS), "JavaFX render timed out");
        if (failure.get() != null) throw new AssertionError("JavaFX dashboard render failed", failure.get());
    }
}
