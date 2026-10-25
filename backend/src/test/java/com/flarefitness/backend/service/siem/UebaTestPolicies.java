package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Wire fixtures only; never a quality or shadow proof. */
public final class UebaTestPolicies {
    private UebaTestPolicies() { }

    public static ObjectNode contextual(ObjectMapper json) throws Exception {
        return strict(json, 3);
    }

    public static ObjectNode sessionEndpoint(ObjectMapper json) throws Exception {
        return strict(json, 4);
    }

    private static ObjectNode strict(ObjectMapper json, int schema) throws Exception {
        ObjectNode wire;
        try (var input = UebaTestPolicies.class.getResourceAsStream("/ueba-score-policy-golden.json")) {
            wire = (ObjectNode) json.readTree(input);
        }
        var doc = (ObjectNode) json.readTree(wire.path("policy_document_json").asText());
        String id = doc.path("policy_id").asText().replace("strict-v2b", schema == 4 ? "strict-v4d" : "strict-v3c");
        doc.put("policy_id", id); doc.put("feature_schema_version", schema);
        doc.put("telemetry_contract_version", schema == 4 ? 3 : 2);
        String raw = json.writeValueAsString(doc);
        wire.put("policy_id", id); wire.put("policy_document_json", raw);
        wire.put("policy_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(raw.getBytes(StandardCharsets.UTF_8))));
        return wire;
    }
}
