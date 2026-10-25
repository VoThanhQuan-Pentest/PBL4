package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class UebaScorePolicyTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private ObjectNode fixture() throws Exception {
        try (var input = getClass().getResourceAsStream("/ueba-score-policy-golden.json")) {
            return (ObjectNode) JSON.readTree(input);
        }
    }

    @Test void pythonGoldenPolicyAndJavaUseIdenticalBytesThresholdsAndHash() throws Exception {
        ObjectNode wire = fixture();
        var policy = UebaScorePolicy.fromWire(wire, 2);
        assertThat(policy.strict()).isTrue();
        assertThat(policy.sha256()).isEqualTo(wire.path("policy_sha256").asText());
        assertThat(policy.level(99.9, "READY")).isEqualTo("UNUSUAL");
        assertThat(policy.level(99.994, "READY")).isEqualTo("UNUSUAL");
        assertThat(policy.level(99.995, "READY")).isEqualTo("VERY_UNUSUAL");
        assertThat(policy.level(100, "COLD")).isEqualTo("VERY_UNUSUAL");
    }

    @Test void lowerGatesOrExtraFieldsCannotBeSmuggledEvenWithARecomputedChecksum() throws Exception {
        for (String fault : new String[]{"hash", "gate", "auto-ban", "context", "extra"}) {
            ObjectNode wire = fixture();
            ObjectNode doc = (ObjectNode) JSON.readTree(wire.path("policy_document_json").asText());
            switch (fault) {
                case "hash" -> wire.put("policy_sha256", "a".repeat(64));
                case "gate" -> ((ObjectNode) doc.path("quality")).put("precision_min_ppm", 900000);
                case "auto-ban" -> ((ObjectNode) doc.path("risk")).put("auto_containment", true);
                case "context" -> ((ObjectNode) doc.path("detection_percentile_micro")).remove("COLD");
                case "extra" -> doc.put("model_upload_path", "/not-allowed");
                default -> throw new IllegalArgumentException();
            }
            if (!"hash".equals(fault)) {
                String raw = JSON.writeValueAsString(doc);
                wire.put("policy_document_json", raw);
                wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))));
            }
            assertThatThrownBy(() -> UebaScorePolicy.fromWire(wire, 2)).isInstanceOf(ServiceUnavailableException.class);
        }
    }

    @Test void strictDetectionCanOpenL1WithoutFabricatingRuleSignalsOrContainment() throws Exception {
        var policy = UebaScorePolicy.fromWire(fixture(), 2);
        var ordinary = new AccountBehaviorFeatures.Vector(1, java.util.List.of(4.0,0.0,0.0,0.0,1.0,0.0,1.0,1.0,0.0,0.0,0.0));
        var detected = AccountRiskEngine.assess(ordinary, new SiemUebaGateway.Score(0.7, 100, "VERY_UNUSUAL", policy, "READY"), true);
        assertThat(detected.createIncident()).isTrue();
        assertThat(detected.reasons()).anyMatch(reason -> reason.contains("human-reviewed L1"));
        var warning = AccountRiskEngine.assess(ordinary, new SiemUebaGateway.Score(0.6, 99.9, "UNUSUAL", policy, "READY"), true);
        assertThat(warning.createIncident()).isFalse();
        assertThat(warning.riskScore()).isZero();
        var cold = AccountRiskEngine.assess(ordinary, new SiemUebaGateway.Score(0.7, 100, "VERY_UNUSUAL", policy, "COLD"), false);
        assertThat(cold.createIncident()).isTrue();
        assertThat(cold.reasons()).anyMatch(reason -> reason.contains("GLOBAL_PROXY"));
    }

    @Test void contextualPolicyUsesTheSameStrictGatesButCannotMasqueradeAsSchema2() throws Exception {
        var wire = fixture(); var doc = (ObjectNode) JSON.readTree(wire.path("policy_document_json").asText());
        String id = doc.path("policy_id").asText().replace("strict-v2b", "strict-v3c");
        doc.put("policy_id", id); doc.put("feature_schema_version", 3);
        String raw = JSON.writeValueAsString(doc); wire.put("policy_id", id); wire.put("policy_document_json", raw);
        wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))));
        var policy = UebaScorePolicy.fromWire(wire, 3);
        assertThat(policy.featureSchema()).isEqualTo(3); assertThat(policy.strict()).isTrue();
        assertThat(policy.level(99.99, "COLD")).isEqualTo("UNUSUAL");
        assertThat(policy.sha256()).isEqualTo("045366abf75fa7035611ab2c58f459f368af2d0e1eef9c0ca2a945caed02a81f");
        assertThatThrownBy(() -> UebaScorePolicy.fromWire(wire, 2)).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void sessionEndpointPolicyRetainsAllQualityGatesAndRequiresTelemetry3() throws Exception {
        var wire = fixture(); var doc = (ObjectNode) JSON.readTree(wire.path("policy_document_json").asText());
        String id = doc.path("policy_id").asText().replace("strict-v2b", "strict-v4d");
        doc.put("policy_id", id); doc.put("feature_schema_version", 4); doc.put("telemetry_contract_version", 3);
        String raw = JSON.writeValueAsString(doc); wire.put("policy_id", id); wire.put("policy_document_json", raw);
        wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))));
        var actual = UebaScorePolicy.fromWire(wire, 4);
        assertThat(actual.strict()).isTrue(); assertThat(actual.featureSchema()).isEqualTo(4);
        assertThat(actual.level(99.99, "COLD")).isEqualTo("UNUSUAL");
        assertThat(actual.level(100, "COLD")).isEqualTo("VERY_UNUSUAL");
        assertThatThrownBy(() -> UebaScorePolicy.fromWire(wire, 3)).isInstanceOf(ServiceUnavailableException.class);
    }
}
