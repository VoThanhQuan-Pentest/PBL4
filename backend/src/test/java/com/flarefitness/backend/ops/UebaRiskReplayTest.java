package com.flarefitness.backend.ops;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class UebaRiskReplayTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    private static ObjectNode input(double percentile, boolean cold) throws Exception {
        ObjectNode root = JSON.createObjectNode();
        root.put("feature_schema_version", 2);
        root.set("score_policy", JSON.readTree(UebaRiskReplayTest.class.getResourceAsStream("/ueba-score-policy-golden.json")));
        ObjectNode row = root.putArray("rows").addObject();
        row.put("frame_id", "owned-numeric-frame-0001");
        row.putArray("features").add(2).add(0).add(0).add(0).add(0).add(0).add(1).add(1)
                .add(0).add(0).add(0).add(0).add(0).add(0).add(0);
        row.put("baseline_established", !cold); row.put("scoring_cohort", cold ? "COLD" : "READY");
        row.put("raw_anomaly_score", 0.5); row.put("normal_percentile", percentile);
        row.put("level", percentile >= 99.995 ? "VERY_UNUSUAL" : percentile >= 99.9 ? "UNUSUAL" : "NORMAL_RANGE");
        return root;
    }

    @Test
    void genuineMlPositiveIsNotHiddenByUnrelatedRuleCorroboration() throws Exception {
        for (boolean cold : new boolean[]{false, true}) {
            var output = UebaRiskReplay.replay(input(100, cold));
            @SuppressWarnings("unchecked") var result = ((java.util.List<Map<String, Object>>) output.get("results")).getFirst();
            assertThat(result).containsEntry("model_positive", true).containsEntry("siem_positive", true).containsEntry("risk_score", 45);
            assertThat(output).containsEntry("decision_code", "AccountRiskEngine").containsEntry("data_provenance", "DEMO_ONLY");
        }
    }

    @Test
    void warningOnlyRemainsTelemetryAndCannotPretendToBeDetection() throws Exception {
        var output = UebaRiskReplay.replay(input(99.99, false));
        @SuppressWarnings("unchecked") var result = ((java.util.List<Map<String, Object>>) output.get("results")).getFirst();
        assertThat(result).containsEntry("model_positive", false).containsEntry("siem_positive", false).containsEntry("risk_score", 0);
    }

    @Test
    void labelledFramesForgedLevelsAndColdPersonalFeaturesAreRefused() throws Exception {
        ObjectNode labelled = input(100, false);
        ((ObjectNode) labelled.path("rows").get(0)).put("label", 1);
        assertThatThrownBy(() -> UebaRiskReplay.replay(labelled)).isInstanceOf(IllegalArgumentException.class);
        ObjectNode forged = input(50, false);
        ((ObjectNode) forged.path("rows").get(0)).put("level", "VERY_UNUSUAL");
        assertThatThrownBy(() -> UebaRiskReplay.replay(forged)).isInstanceOf(IllegalArgumentException.class);
        ObjectNode cold = input(100, true);
        ((com.fasterxml.jackson.databind.node.ArrayNode) cold.path("rows").get(0).path("features")).set(11, JSON.getNodeFactory().numberNode(1));
        assertThatThrownBy(() -> UebaRiskReplay.replay(cold)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void corruptNumericAndPhysicallyImpossibleFeaturesDoNotBecomeValidEvidence() throws Exception {
        for (int index = 0; index < 15; index++) {
            ObjectNode invalid = input(50, false);
            ((com.fasterxml.jackson.databind.node.ArrayNode) invalid.path("rows").get(0).path("features")).set(index, JSON.getNodeFactory().booleanNode(true));
            assertThatThrownBy(() -> UebaRiskReplay.replay(invalid)).isInstanceOf(IllegalArgumentException.class);
        }
        ObjectNode badRate = input(50, false);
        ((com.fasterxml.jackson.databind.node.ArrayNode) badRate.path("rows").get(0).path("features")).set(13, JSON.getNodeFactory().numberNode(0.5));
        assertThatThrownBy(() -> UebaRiskReplay.replay(badRate)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void contextualReplayStillUsesTheRealEngineAndCannotInventColdPersonalSignals() throws Exception {
        var root = input(100, true); root.put("feature_schema_version", 3);
        var wire = (ObjectNode) root.path("score_policy"); var doc = (ObjectNode) JSON.readTree(wire.path("policy_document_json").asText());
        String id = doc.path("policy_id").asText().replace("strict-v2b", "strict-v3c"); doc.put("policy_id", id); doc.put("feature_schema_version", 3);
        String raw = JSON.writeValueAsString(doc); wire.put("policy_id", id); wire.put("policy_document_json", raw);
        wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))));
        var features = (com.fasterxml.jackson.databind.node.ArrayNode) root.path("rows").get(0).path("features");
        for (double value : new double[]{2,0,0,0,0,0,0,0,0,0}) features.add(value);
        var result = UebaRiskReplay.replay(root);
        assertThat(result.get("feature_schema_version")).isEqualTo(3);
        @SuppressWarnings("unchecked") var row = ((java.util.List<Map<String,Object>>) result.get("results")).getFirst();
        assertThat(row).containsEntry("model_positive", true).containsEntry("siem_positive", true);
        features.set(20, JSON.getNodeFactory().numberNode(1));
        assertThatThrownBy(() -> UebaRiskReplay.replay(root)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void sessionEndpointReplayUsesActualEngineAndCannotBypassCoverageRules() throws Exception {
        var root = input(100, true); root.put("feature_schema_version", 4);
        var wire = (ObjectNode) root.path("score_policy"); var doc = (ObjectNode) JSON.readTree(wire.path("policy_document_json").asText());
        String id = doc.path("policy_id").asText().replace("strict-v2b", "strict-v4d");
        doc.put("policy_id", id); doc.put("feature_schema_version", 4); doc.put("telemetry_contract_version", 3);
        String raw = JSON.writeValueAsString(doc); wire.put("policy_id", id); wire.put("policy_document_json", raw);
        wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))));
        var features = (com.fasterxml.jackson.databind.node.ArrayNode) root.path("rows").get(0).path("features");
        for (double value : new double[]{2,0,0,0,0,0,0,0,0,0, 2,1,0,0,0,2,2,1,30,0,3,0.5}) features.add(value);
        var output = UebaRiskReplay.replay(root);
        assertThat(output.get("feature_schema_version")).isEqualTo(4);
        @SuppressWarnings("unchecked") var result = ((java.util.List<Map<String,Object>>) output.get("results")).getFirst();
        assertThat(result).containsEntry("model_positive", true).containsEntry("siem_positive", true);
        features.set(31, JSON.getNodeFactory().numberNode(3));
        assertThatThrownBy(() -> UebaRiskReplay.replay(root)).isInstanceOf(IllegalArgumentException.class);
    }
}
