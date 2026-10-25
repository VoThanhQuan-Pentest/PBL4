package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SiemUebaGatewayTest {
    @TempDir Path temporary;

    @Test
    void validatesSchemaAndSendsOnlyNumericWindowsToTheInternalWorker() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Path token = temporary.resolve("worker.token");
        Files.writeString(token, "a".repeat(32), StandardCharsets.UTF_8);
        AtomicReference<String> receivedBody = new AtomicReference<>();
        AtomicReference<String> reportedLevel = new AtomicReference<>("VERY_UNUSUAL");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/health", exchange -> respond(exchange, mapper.writeValueAsString(Map.of(
                "feature_schema_version", 1,
                "feature_names", AccountBehaviorFeatures.NAMES,
                "model_available", true,
                "model_version", "model-test-1234"))));
        server.createContext("/internal/v1/score", exchange -> {
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, mapper.writeValueAsString(Map.of(
                    "available", true, "feature_schema_version", 1,
                    "feature_names", AccountBehaviorFeatures.NAMES,
                    "model_version", "model-test-1234",
                    "results", List.of(Map.of("raw_anomaly_score", 0.6,
                            "normal_percentile", 99.95, "level", reportedLevel.get())))));
        });
        server.start();
        try {
            SiemUebaGateway gateway = new SiemUebaGateway(true,
                    "http://127.0.0.1:" + server.getAddress().getPort(), token.toString(), mapper);
            assertThat(gateway.health().modelAvailable()).isTrue();
            SiemUebaGateway.ScoreBatch result = gateway.score(List.of(List.of(
                    1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0)));
            assertThat(result.available()).isTrue();
            assertThat(result.results().getFirst().level()).isEqualTo("VERY_UNUSUAL");
            var request = mapper.readTree(receivedBody.get());
            assertThat(request.has("vectors")).isTrue();
            assertThat(request.path("feature_schema_version").asInt()).isEqualTo(1);
            assertThat(request.has("account_id")).isFalse();
            assertThat(request.has("email")).isFalse();
            assertThat(request.has("source_ip")).isFalse();
            reportedLevel.set("NORMAL_RANGE");
            assertThatThrownBy(() -> gateway.score(List.of(List.of(
                    1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0))))
                    .isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void catalogueTransportContainsIdsOnlyAndRejectsWrongModelAcknowledgement() throws Exception {
        ObjectMapper mapper = new ObjectMapper(); Path token = temporary.resolve("catalog.token");
        Files.writeString(token, "b".repeat(32));
        AtomicReference<String> received = new AtomicReference<>();
        AtomicReference<String> acknowledged = new AtomicReference<>("catalog-model-1234");
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/v1/train-catalog", exchange -> {
            received.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = mapper.writeValueAsBytes(Map.of("job_id", "a".repeat(32), "status", "QUEUED", "model_version", acknowledged.get()));
            exchange.getResponseHeaders().set("Content-Type", "application/json"); exchange.sendResponseHeaders(202, bytes.length);
            try (var stream = exchange.getResponseBody()) { stream.write(bytes); }
        });
        server.start();
        try {
            var gateway = new SiemUebaGateway(true, "http://127.0.0.1:" + server.getAddress().getPort(), token.toString(), mapper);
            var queued = gateway.startCatalogTraining("catalog-model-1234", "owned-preview-recipe");
            assertThat(queued.status()).isEqualTo("QUEUED");
            var body = mapper.readTree(received.get()); assertThat(body.size()).isEqualTo(2);
            assertThat(body.path("recipe_id").asText()).isEqualTo("owned-preview-recipe");
            assertThat(body.has("samples")).isFalse(); assertThat(body.has("labels")).isFalse(); assertThat(body.has("path")).isFalse();
            acknowledged.set("different-model-1234");
            assertThatThrownBy(() -> gateway.startCatalogTraining("catalog-model-1234", "owned-preview-recipe"))
                    .isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
            assertThatThrownBy(() -> gateway.startCatalogTraining("catalog-model-1234", "../unregistered-file"))
                    .isInstanceOf(IllegalArgumentException.class);
        } finally { server.stop(0); }
    }

    @Test
    void shadowTransportIsIdempotentIdOnlyAndRequiresExactWindowAcknowledgements() throws Exception {
        var mapper = new ObjectMapper(); Path token = temporary.resolve("shadow.token"); Files.writeString(token, "c".repeat(32));
        String runId = "b".repeat(32); String version = "owned-shadow-model";
        var received = new AtomicReference<String>(); var correct = new java.util.concurrent.atomic.AtomicBoolean(true);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/v1/shadow-runs", exchange -> {
            received.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = mapper.writeValueAsBytes(Map.of("job_id", runId, "model_version", version, "status", "QUEUED"));
            exchange.sendResponseHeaders(202, bytes.length); try (var stream = exchange.getResponseBody()) { stream.write(bytes); }
        });
        server.createContext("/internal/v1/shadow-runs/" + runId + "/windows", exchange -> {
            received.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(exchange, mapper.writeValueAsString(Map.of("run_id", runId, "newly_scored_windows", 0,
                    "accepted_window_ids", List.of(correct.get() ? "owned-window-1234" : "wrong-window-1234"),
                    "candidate_side_effects", zeroEffects())));
        });
        server.start();
        try {
            var gateway = new SiemUebaGateway(true, "http://127.0.0.1:" + server.getAddress().getPort(), token.toString(), mapper);
            assertThat(gateway.startShadow(version, runId).status()).isEqualTo("QUEUED");
            var start = mapper.readTree(received.get()); assertThat(start.size()).isEqualTo(2);
            assertThat(start.path("request_id").asText()).isEqualTo(runId); assertThat(start.has("elapsed_seconds")).isFalse();
            Map<String, Object> window = Map.of("window_id", "owned-window-1234", "window_end_utc", "2026-01-01T00:15:00Z",
                    "baseline_established", false, "features", List.of(2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
            gateway.sendShadowWindows(runId, List.of(window));
            assertThat(mapper.readTree(received.get()).path("windows").get(0).has("account_id")).isFalse();
            var contextual = new java.util.ArrayList<Double>((List<Double>) window.get("features"));
            contextual.addAll(List.of(2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0));
            var contextWindow = new java.util.HashMap<String, Object>(window); contextWindow.put("features", contextual);
            gateway.sendShadowWindows(runId, List.of(contextWindow), 3);
            assertThat(mapper.readTree(received.get()).path("windows").get(0).path("features")).hasSize(25);
            assertThatThrownBy(() -> gateway.sendShadowWindows(runId, List.of(contextWindow))).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> gateway.sendShadowWindows(runId, List.of(window), 3)).isInstanceOf(IllegalArgumentException.class);
            correct.set(false);
            assertThatThrownBy(() -> gateway.sendShadowWindows(runId, List.of(window)))
                    .isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
            assertThatThrownBy(() -> gateway.sendShadowWindows(runId, List.of(window, window))).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> gateway.startShadow(version, "../fake")).isInstanceOf(IllegalArgumentException.class);
        } finally { server.stop(0); }
    }

    @Test
    void shadowStateRejectsTestClocksActionsAndPrematureCompletion() {
        var mapper = new ObjectMapper(); var gateway = new SiemUebaGateway(true, "http://127.0.0.1", "unused", mapper);
        String id = "d".repeat(32);
        var state = mapper.createObjectNode(); state.put("run_id", id); state.put("model_version", "owned-shadow-model");
        state.put("status", "RUNNING"); state.put("feature_schema_version", 2); state.put("clock_provenance", "REAL_SERVER_CLOCK");
        for (String key : List.of("model_sha256", "calibration_sha256", "policy_sha256", "dataset_sha256", "boot_sha256")) state.put(key, "a".repeat(64));
        state.put("started_at_utc", "2026-01-01T00:00:00Z"); state.put("started_monotonic", 10);
        state.put("last_heartbeat_monotonic", 70); state.put("elapsed_monotonic_seconds", 60); state.put("maximum_heartbeat_gap_seconds", 60);
        state.put("closed_windows", 1); state.set("candidate_side_effects", mapper.valueToTree(zeroEffects()));
        assertThat(gateway.validateShadowState(state, id)).isSameAs(state);
        state.put("feature_schema_version", 3);
        assertThat(gateway.validateShadowState(state, id)).isSameAs(state);
        state.put("feature_schema_version", 1);
        assertThatThrownBy(() -> gateway.validateShadowState(state, id)).isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
        state.put("feature_schema_version", 2);
        state.put("clock_provenance", "TEST_CLOCK_ONLY");
        assertThatThrownBy(() -> gateway.validateShadowState(state, id)).isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
        state.put("clock_provenance", "REAL_SERVER_CLOCK"); state.put("status", "COMPLETED"); state.put("ended_at_utc", "2026-01-02T00:00:00Z");
        assertThatThrownBy(() -> gateway.validateShadowState(state, id)).isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
        state.put("elapsed_monotonic_seconds", 86400); state.put("closed_windows", 600);
        assertThat(gateway.validateShadowState(state, id)).isSameAs(state);
        ((com.fasterxml.jackson.databind.node.ObjectNode) state.path("candidate_side_effects")).put("ip_blocks", 1);
        assertThatThrownBy(() -> gateway.validateShadowState(state, id)).isInstanceOf(com.flarefitness.backend.exception.ServiceUnavailableException.class);
    }

    private static Map<String, Integer> zeroEffects() {
        return Map.of("incidents", 0, "history", 0, "ip_lookups", 0, "ip_blocks", 0, "session_revocations", 0, "policy_publications", 0);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body)
            throws java.io.IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, payload.length);
        try (var output = exchange.getResponseBody()) {
            output.write(payload);
        }
    }
}
