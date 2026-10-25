package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

/** Exact canonical policy bytes/hash travel with the model, rather than duplicated percentile constants. */
public final class UebaScorePolicy {
    private static final ObjectMapper JSON = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final Set<Long> DETECTION_GRID = Set.of(99950000L, 99990000L, 99995000L, 99999000L,
            99999500L, 99999800L, 99999900L, 99999950L);
    private final String id;
    private final String checksum;
    private final String documentJson;
    private final JsonNode document;

    private UebaScorePolicy(String id, String checksum, String documentJson, JsonNode document) {
        this.id = id; this.checksum = checksum; this.documentJson = documentJson; this.document = document;
    }

    public static UebaScorePolicy fromWire(JsonNode wire, int featureSchema) {
        try {
            requireKeys(wire, Set.of("policy_id", "policy_sha256", "policy_document_json"));
            String raw = wire.path("policy_document_json").asText();
            String id = wire.path("policy_id").asText();
            String checksum = wire.path("policy_sha256").asText();
            if (!wire.path("policy_document_json").isTextual() || raw.getBytes(StandardCharsets.UTF_8).length > 8192
                    || !id.matches("[a-z0-9_-]{8,96}") || !checksum.matches("[a-f0-9]{64}")
                    || !checksum.equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))))) throw invalid();
            JsonNode doc = JSON.readTree(raw);
            int generation = integer(doc, "policy_schema_version");
            if (!Set.of(1, 2, 3, 4).contains(featureSchema) || generation == 1 && featureSchema >= 3) throw invalid();
            if (integer(doc, "feature_schema_version") != featureSchema || !id.equals(doc.path("policy_id").asText())) throw invalid();
            long warning = integer(doc, "warning_percentile_micro");
            JsonNode detections = doc.path("detection_percentile_micro");
            requireKeys(detections, Set.of("READY", "COLD"));
            long ready = integer(detections, "READY"), cold = integer(detections, "COLD");
            if (warning < 0 || warning >= ready || warning >= cold || ready > 100000000 || cold > 100000000) throw invalid();
            if (generation == 1) {
                requireKeys(doc, Set.of("policy_id", "policy_schema_version", "feature_schema_version", "telemetry_contract_version",
                        "warning_percentile_micro", "detection_percentile_micro", "positive_level"));
                if (!id.equals("legacy-v2a-schema" + featureSchema) || integer(doc, "telemetry_contract_version") != 1
                        || warning != 99000000 || ready != 99900000 || cold != 99900000
                        || !"UNUSUAL".equals(doc.path("positive_level").asText())) throw invalid();
            } else if (generation == 2) {
                requireKeys(doc, Set.of("policy_id", "policy_schema_version", "feature_schema_version", "telemetry_contract_version",
                        "warning_percentile_micro", "detection_percentile_micro", "positive_level", "quality", "risk", "shadow"));
                JsonNode risk = doc.path("risk");
                int rule = integer(risk, "rule_risk_threshold");
                requireKeys(risk, Set.of("very_unusual_creates_l1", "warning_creates_l1", "auto_containment", "rule_risk_threshold", "rule_min_signals"));
                String prefix = featureSchema == 2 ? "strict-v2b" : featureSchema == 3 ? "strict-v3c" : "strict-v4d";
                if (!Set.of(2, 3, 4).contains(featureSchema) || integer(doc, "telemetry_contract_version") != (featureSchema == 4 ? 3 : 2) || warning != 99900000
                        || !DETECTION_GRID.contains(ready) || !DETECTION_GRID.contains(cold) || !Set.of(45, 60, 70).contains(rule)
                        || !id.equals(prefix + "-r" + ready + "-c" + cold + "-rules" + rule)
                        || !"VERY_UNUSUAL".equals(doc.path("positive_level").asText())
                        || !bool(risk, "very_unusual_creates_l1") || bool(risk, "warning_creates_l1")
                        || bool(risk, "auto_containment") || integer(risk, "rule_min_signals") != 2) throw invalid();
                JsonNode quality = doc.path("quality");
                requireKeys(quality, Set.of("precision_min_ppm", "recall_min_ppm", "recall_strict", "fpr_max_ppm", "fpr_strict",
                        "minimum_normal", "minimum_positive", "minimum_family_positive", "slice_recall_min_ppm",
                        "alpha_numerator", "alpha_denominator", "global_comparisons", "cluster_resamples", "scopes"));
                if (integer(quality, "precision_min_ppm") != 998000 || integer(quality, "recall_min_ppm") != 990000
                        || !bool(quality, "recall_strict") || integer(quality, "fpr_max_ppm") != 1000 || !bool(quality, "fpr_strict")
                        || integer(quality, "minimum_normal") != 10000000 || integer(quality, "minimum_positive") != 10000
                        || integer(quality, "minimum_family_positive") != 2000 || integer(quality, "slice_recall_min_ppm") != 990000
                        || integer(quality, "alpha_numerator") != 1 || integer(quality, "alpha_denominator") != 20
                        || integer(quality, "global_comparisons") != 6 || integer(quality, "cluster_resamples") != 5000
                        || !quality.path("scopes").equals(JSON.readTree("[\"MODEL_ONLY\",\"SIEM_FINAL\"]"))) throw invalid();
                JsonNode shadow = doc.path("shadow");
                requireKeys(shadow, Set.of("minimum_elapsed_seconds", "maximum_heartbeat_gap_seconds", "minimum_closed_windows"));
                if (integer(shadow, "minimum_elapsed_seconds") != 86400 || integer(shadow, "maximum_heartbeat_gap_seconds") != 300
                        || integer(shadow, "minimum_closed_windows") != 600) throw invalid();
            } else throw invalid();
            return new UebaScorePolicy(id, checksum, raw, doc);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw invalid(); }
    }

    public boolean strict() { return document.path("policy_schema_version").asInt() == 2; }
    public String id() { return id; }
    public String sha256() { return checksum; }
    public String documentJson() { return documentJson; }
    public int featureSchema() { return document.path("feature_schema_version").asInt(); }
    public int ruleThreshold() { return strict() ? document.path("risk").path("rule_risk_threshold").asInt() : 45; }
    public String level(double percentile, String cohort) {
        if (!Double.isFinite(percentile) || percentile < 0 || percentile > 100 || !Set.of("READY", "COLD").contains(cohort)) throw invalid();
        if (percentile >= document.path("detection_percentile_micro").path(cohort).asDouble() / 1000000) return "VERY_UNUSUAL";
        if (percentile >= document.path("warning_percentile_micro").asDouble() / 1000000) return "UNUSUAL";
        return "NORMAL_RANGE";
    }
    private static int integer(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (!value.isIntegralNumber() || !value.canConvertToInt()) throw invalid();
        return value.asInt();
    }
    private static boolean bool(JsonNode node, String field) {
        if (!node.path(field).isBoolean()) throw invalid();
        return node.path(field).asBoolean();
    }
    private static void requireKeys(JsonNode node, Set<String> expected) {
        if (!node.isObject()) throw invalid();
        Set<String> keys = new HashSet<>(); node.fieldNames().forEachRemaining(keys::add);
        if (!keys.equals(expected)) throw invalid();
    }
    private static ServiceUnavailableException invalid() { return new ServiceUnavailableException("UEBA score policy failed integrity validation."); }
}
