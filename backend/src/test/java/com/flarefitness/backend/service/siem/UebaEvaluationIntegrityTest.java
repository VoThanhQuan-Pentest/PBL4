package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Engineered counters test gate integrity, not model accuracy or additional fitting. */
class UebaEvaluationIntegrityTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MODEL = "model-integrity-1234", MODEL_SHA = "a".repeat(64), DATA_SHA = "b".repeat(64);
    private final SiemUebaGateway gateway = new SiemUebaGateway(false, "http://ueba-worker:8091", "/unused/test.token", JSON);

    static Stream<Arguments> malformedResults() {
        return IntStream.range(0, 20).boxed().flatMap(population ->
                IntStream.range(0, 15).mapToObj(fault -> Arguments.of(population, fault)));
    }
    static IntStream validResults() { return IntStream.range(0, 20); }

    @ParameterizedTest(name = "population={0},fault={1}")
    @MethodSource("malformedResults")
    void cannotReplaceRealModelOnlyEvaluationWithForgedOrInconsistentMetadata(int population, int fault) {
        ObjectNode result = valid(population);
        switch (fault) {
            case 0 -> result.put("model_version", "model-other-1234");
            case 1 -> result.put("model_sha256", "c".repeat(64));
            case 2 -> result.put("evaluation_dataset_sha256", "d".repeat(64));
            case 3 -> result.put("scope", "MODEL_PLUS_RULES");
            case 4 -> result.put("evaluation_scope", "VALIDATION");
            case 5 -> result.put("data_provenance", "REAL");
            case 6 -> result.put("feature_schema_version", 1);
            case 7 -> result.put("percentile_threshold", 98);
            case 8 -> result.put("tp", -1);
            case 9 -> result.put("fp", result.path("fp").asInt() + 1);
            case 10 -> result.put("recall", 0.999);
            case 11 -> ((ObjectNode) result.path("families")).remove("endpoint_scan");
            case 12 -> result.remove("confidence_95");
            case 13 -> ((ObjectNode) result.path("confidence_95")).putArray("recall").add(-0.1).add(1.5);
            case 14 -> result.put("quality_gate", "FAIL");
            default -> throw new IllegalArgumentException();
        }
        assertThatThrownBy(() -> gateway.validateEvaluation(result, MODEL, MODEL_SHA, DATA_SHA, 2, 10000, 1000))
                .isInstanceOf(ServiceUnavailableException.class);
    }

    @ParameterizedTest
    @MethodSource("validResults")
    void returnsOnlyVerifiedAllowlistedMetrics(int population) {
        ObjectNode root = valid(population);
        root.put("password", "never-return-this");
        var result = gateway.validateEvaluation(root, MODEL, MODEL_SHA, DATA_SHA, 2, 10000, 1000);
        assertThat(result.get("quality_gate")).isEqualTo("PASS");
        assertThat(result).doesNotContainKey("password");
        assertThat(result.get("tp")).isEqualTo(900 + population);
    }

    static ObjectNode valid(int population) {
        ObjectNode root = JSON.createObjectNode();
        root.put("status", "SUCCEEDED"); root.put("model_version", MODEL); root.put("model_sha256", MODEL_SHA);
        root.put("evaluation_dataset_sha256", DATA_SHA); root.put("feature_schema_version", 2);
        root.put("scope", "MODEL_ONLY"); root.put("evaluation_scope", "FROZEN_HOLDOUT");
        root.put("data_provenance", "DEMO_ONLY"); root.put("percentile_threshold", 99);
        int tp = 900 + population, fp = 100 + population;
        root.put("tp", tp); root.put("fp", fp); root.put("fn", 1000 - tp); root.put("tn", 10000 - fp);
        root.put("recall", tp / 1000.0); root.put("false_positive_rate", fp / 10000.0);
        root.put("precision", (double) tp / (tp + fp)); root.put("minimum_sizes_met", true); root.put("quality_gate", "PASS");
        ObjectNode families = root.putObject("families");
        int index = 0;
        for (String family : List.of("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")) {
            int hits = 180 + (index++ == 0 ? population : 0);
            ObjectNode entry = families.putObject(family);
            entry.put("positive_samples", 200); entry.put("tp", hits); entry.put("fn", 200 - hits); entry.put("recall", hits / 200.0);
        }
        ObjectNode confidence = root.putObject("confidence_95");
        confidence.put("method", "account_day_cluster_bootstrap"); confidence.put("clusters", 1400); confidence.put("resamples", 2000);
        confidence.putArray("recall").add(tp / 1000.0 - 0.02).add(tp / 1000.0 + 0.02);
        confidence.putArray("false_positive_rate").add(fp / 10000.0 - 0.005).add(fp / 10000.0 + 0.005);
        return root;
    }
}
