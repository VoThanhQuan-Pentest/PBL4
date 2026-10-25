package com.flarefitness.backend.ops;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.AccountRiskEngine;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import com.flarefitness.backend.service.siem.UebaScorePolicy;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Offline numeric scoring replay through the real backend decision code; no DB/network/containment. */
public final class UebaRiskReplay {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final Set<String> ROOT_FIELDS = Set.of("feature_schema_version", "score_policy", "rows");
    private static final Set<String> ROW_FIELDS = Set.of("frame_id", "features", "baseline_established",
            "scoring_cohort", "raw_anomaly_score", "normal_percentile", "level");
    private UebaRiskReplay() { }

    public static void main(String[] args) {
        if (args.length != 1 || !"--demo-only".equals(args[0])) {
            System.err.println("Usage: UebaRiskReplay --demo-only < numeric-score-batches.ndjson");
            System.exit(2);
        }
        try {
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line;
            while ((line = boundedLine(input)) != null) {
                System.out.println(JSON.writeValueAsString(replay(JSON.readTree(line))));
                System.out.flush();
            }
        } catch (Exception failure) {
            // Never print input, pseudo-identities, labels, bodies or environment values.
            System.err.println("Numeric risk replay failed/refused: " + failure.getClass().getSimpleName());
            System.exit(2);
        }
    }

    static Map<String, Object> replay(JsonNode input) {
        fields(input, ROOT_FIELDS);
        int schema = input.path("feature_schema_version").asInt(-1);
        if (!input.path("feature_schema_version").isIntegralNumber() || !Set.of(2, 3, 4).contains(schema)) {
            throw new IllegalArgumentException("Strict numeric schema required");
        }
        UebaScorePolicy policy = UebaScorePolicy.fromWire(input.path("score_policy"), schema);
        if (!policy.strict()) throw new IllegalArgumentException("Strict policy required");
        JsonNode rows = input.path("rows");
        if (!rows.isArray() || rows.isEmpty() || rows.size() > 5000) throw new IllegalArgumentException("Bounded numeric batch required");
        List<Map<String, Object>> results = new ArrayList<>();
        Set<String> identities = new java.util.HashSet<>();
        for (JsonNode row : rows) {
            fields(row, ROW_FIELDS);
            JsonNode id = row.path("frame_id");
            if (!id.isTextual() || !id.asText().matches("[a-z0-9_-]{8,128}") || !identities.add(id.asText())) {
                throw new IllegalArgumentException("Unique pseudo frame required");
            }
            if (!row.path("baseline_established").isBoolean()) throw new IllegalArgumentException("Boolean coverage required");
            boolean ready = row.path("baseline_established").asBoolean();
            String cohort = row.path("scoring_cohort").asText();
            if (!cohort.equals(ready ? "READY" : "COLD")) throw new IllegalArgumentException("Actual coverage/cohort mismatch");
            var vector = features(row.path("features"), schema);
            List<Integer> personal = schema == 2 ? List.of(8, 9, 10, 11, 12) : List.of(8, 9, 10, 11, 12, 20, 21);
            if (!ready && personal.stream().anyMatch(index -> vector.values().get(index) != 0)) {
                throw new IllegalArgumentException("Cold coverage cannot fabricate personal evidence");
            }
            double raw = number(row, "raw_anomaly_score");
            double percentile = number(row, "normal_percentile");
            String level = row.path("level").asText();
            if (percentile < 0 || percentile > 100 || !level.equals(policy.level(percentile, cohort))) {
                throw new IllegalArgumentException("Model level differs from frozen score policy");
            }
            var score = new SiemUebaGateway.Score(raw, percentile, level, policy, cohort);
            var assessment = AccountRiskEngine.assess(vector.base(), score, ready);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("frame_id", id.asText());
            result.put("model_positive", "VERY_UNUSUAL".equals(level));
            result.put("siem_positive", assessment.createIncident());
            result.put("risk_score", assessment.riskScore());
            result.put("severity", assessment.severity().name());
            results.add(result);
        }
        return Map.of("feature_schema_version", schema, "policy_sha256", policy.sha256(), "results", results,
                "data_provenance", "DEMO_ONLY", "decision_code", "AccountRiskEngine");
    }

    private static AccountBehaviorFeatures.Vector features(JsonNode values, int schema) {
        if (!values.isArray() || values.size() != AccountBehaviorFeatures.names(schema).size()) throw new IllegalArgumentException("Compatible numeric feature shape required");
        List<Double> numbers = new ArrayList<>();
        for (JsonNode value : values) {
            if (!value.isNumber() || !Double.isFinite(value.asDouble()) || Math.abs(value.asDouble()) > 1_000_000) {
                throw new IllegalArgumentException("Bounded finite number required");
            }
            numbers.add(value.asDouble());
        }
        for (int index = 0; index < 8; index++) {
            double value = numbers.get(index);
            if (value < 0 || value != Math.floor(value)) throw new IllegalArgumentException("Nonnegative integer counts required");
        }
        for (int index = 8; index < 11; index++) {
            if (numbers.get(index) != 0 && numbers.get(index) != 1) throw new IllegalArgumentException("Binary flags required");
        }
        if (numbers.get(1) + numbers.get(2) > numbers.get(0) || numbers.get(6) > numbers.get(0) || numbers.get(6) > 9
                || Math.abs(numbers.get(11)) > 20 || Math.abs(numbers.get(12)) > 20
                || Math.abs(numbers.get(13) - numbers.get(1) / Math.max(1, numbers.get(0))) > 1e-9
                || Math.abs(numbers.get(14) - numbers.get(3) / Math.max(1, numbers.get(3) + numbers.get(4))) > 1e-9) {
            throw new IllegalArgumentException("Feature counts/rates differ from server contract");
        }
        if (schema >= 3) {
            for (int index : List.of(15, 18, 22, 23, 24)) {
                double value = numbers.get(index);
                if (value < 0 || value != Math.floor(value)) throw new IllegalArgumentException("Contextual counts must be nonnegative integers.");
            }
            if (numbers.get(15) > numbers.get(0) || numbers.get(18) > Math.max(0, numbers.get(0) - 1)
                    || numbers.get(22) > numbers.get(3) || numbers.get(23) > numbers.get(5) || numbers.get(24) > numbers.get(1)
                    || numbers.get(16) < 0 || numbers.get(16) >= 900 || numbers.get(17) < 0 || numbers.get(17) > 20
                    || Math.abs(numbers.get(20)) > 20 || Math.abs(numbers.get(21)) > 20
                    || Math.abs(numbers.get(19) - numbers.get(18) / Math.max(1, numbers.get(0) - 1)) > 1e-9) {
                throw new IllegalArgumentException("Contextual values differ from the source contract.");
            }
        }
        return new AccountBehaviorFeatures.Vector(schema, numbers);
    }

    private static double number(JsonNode row, String key) {
        JsonNode value = row.path(key);
        if (!value.isNumber() || !Double.isFinite(value.asDouble()) || Math.abs(value.asDouble()) > 1_000_000) {
            throw new IllegalArgumentException("Bounded finite score required");
        }
        return value.asDouble();
    }

    private static void fields(JsonNode node, Set<String> allowed) {
        if (!node.isObject() || node.size() != allowed.size()) throw new IllegalArgumentException("Numeric replay contract mismatch");
        node.fieldNames().forEachRemaining(key -> {
            if (!allowed.contains(key)) throw new IllegalArgumentException("Labels/raw/private fields must not enter decision replay");
        });
    }

    private static String boundedLine(BufferedReader input) throws java.io.IOException {
        StringBuilder line = new StringBuilder();
        int value;
        while ((value = input.read()) != -1 && value != '\n') {
            if (line.length() >= 8 * 1024 * 1024) throw new IllegalArgumentException("Numeric batch exceeds bound");
            line.append((char) value);
        }
        return value == -1 && line.isEmpty() ? null : line.toString();
    }
}
