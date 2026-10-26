package com.flarefitness.monitor.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.flarefitness.monitor.FlareSecurityApp;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class LoginOtpInteractionTest {
    @BeforeAll static void toolkit() {
        assumeTrue(System.getenv("DISPLAY") != null, "Run with xvfb-run.");
        try { Platform.startup(() -> Platform.setImplicitExit(false)); }
        catch (IllegalStateException alreadyStarted) { Platform.setImplicitExit(false); }
    }

    @Test void compactLoginWaitsForOtpAndRestartDiscardsThePendingProof() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/auth/csrf", exchange -> {
            byte[] body = "{\"token\":\"synthetic-csrf\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length); exchange.getResponseBody().write(body); exchange.close();
        });
        server.createContext("/api/auth/login", exchange -> {
            byte[] body = """
                    {"challenge_id":"12345678-1234-1234-1234-123456789012","expires_in":300,
                    "email_masked":"a***@example.test","channel":"EMAIL_OTP"}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(202, body.length); exchange.getResponseBody().write(body); exchange.close();
        });
        server.start();
        String previous = System.getProperty("flare.soc.serverOrigin");
        System.setProperty("flare.soc.serverOrigin", "http://127.0.0.1:" + server.getAddress().getPort());
        AtomicReference<Stage> stage = new AtomicReference<>();
        AtomicReference<Parent> root = new AtomicReference<>();
        AtomicBoolean authenticated = new AtomicBoolean();
        try {
            fx(() -> {
                FXMLLoader loader = new FXMLLoader(FlareSecurityApp.class.getResource("/fxml/login.fxml"));
                root.set(loader.load());
                ((LoginController) loader.getController()).setOnAuthenticated((api, user) -> authenticated.set(true));
                Stage window = new Stage(); stage.set(window);
                Scene scene = new Scene(root.get(), 640, 560);
                scene.getStylesheets().add(FlareSecurityApp.class.getResource("/css/siem.css").toExternalForm());
                window.setScene(scene); window.show();
                ((TextField) root.get().lookup("#username")).setText("synthetic-analyst");
                ((PasswordField) root.get().lookup("#password")).setText("Synthetic!Password1");
                ((Button) root.get().lookup("#loginButton")).fire();
                return null;
            });
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (!fx(() -> root.get().lookup("#otpCode").isVisible()) && System.nanoTime() < deadline) Thread.sleep(20);
            fx(() -> {
                assertFalse(authenticated.get());
                assertTrue(root.get().lookup("#otpCode").isVisible());
                assertFalse(root.get().lookup("#credentialsGroup").isManaged());
                assertEquals("", ((PasswordField) root.get().lookup("#password")).getText());
                root.get().applyCss(); root.get().layout();
                var bounds = root.get().lookup("#loginButton").localToScene(root.get().lookup("#loginButton").getBoundsInLocal());
                assertTrue(bounds.getMinY() >= 0 && bounds.getMaxY() <= stage.get().getScene().getHeight());
                ((TextField) root.get().lookup("#otpCode")).setText("123456");
                ((Button) root.get().lookup("#restartButton")).fire();
                assertFalse(root.get().lookup("#otpCode").isVisible());
                assertEquals("", ((TextField) root.get().lookup("#otpCode")).getText());
                assertTrue(root.get().lookup("#credentialsGroup").isManaged());
                assertFalse(root.get().lookup("#password").isDisabled());
                return null;
            });
        } finally {
            fx(() -> { if (stage.get() != null) stage.get().close(); return null; });
            server.stop(0);
            if (previous == null) System.clearProperty("flare.soc.serverOrigin");
            else System.setProperty("flare.soc.serverOrigin", previous);
        }
    }

    private static <T> T fx(java.util.concurrent.Callable<T> action) throws Exception {
        FutureTask<T> task = new FutureTask<>(action); Platform.runLater(task); return task.get(10, TimeUnit.SECONDS);
    }
}
