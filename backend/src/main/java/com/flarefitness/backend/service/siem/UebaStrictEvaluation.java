package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/** Validate both strict scopes and recompute gates; an upstream PASS is not authority. */
public final class UebaStrictEvaluation {
    private UebaStrictEvaluation() { }
    private static final Set<String> SCOPES = Set.of("MODEL_ONLY", "SIEM_FINAL");
    private static final Set<String> FAMILIES = Set.of("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst");
    private static final Set<String> COHORTS = Set.of("READY", "UNSEEN_READY", "COLD");

    /** Build the original immutable strict-training reference from the worker's private installer receipt. */
    public static UebaExperimentCatalog.StrictReference recoveredReference(JsonNode receipt) {
        JsonNode value = receipt.path("strict_reference");
        Set<String> expected = Set.of("recipe_id", "dataset_id", "data_provenance", "feature_schema_version",
                "training_windows", "calibration_windows", "from_utc", "to_utc", "completed_search_fits",
                "manifest_sha256", "policy_sha256", "blocked_holdout_split_sha256", "selected_model_sha256", "fold", "random_state",
                "selected_calibration_sha256", "model_state_sha256", "model_state_verifier_sha256",
                "model_state_format", "model_kind", "recipe_version", "recipe_sha256", "strict_proof_sha256",
                "selection_sha256", "source_label_manifest_sha256_by_fold", "zero_fit_recalibrations");
        if (!value.isObject() || !fields(value).equals(expected)
                || !"DEMO_ONLY".equals(value.path("data_provenance").asText())
                || value.path("feature_schema_version").asInt(-1) != 4
                || !UebaExperimentCatalog.HYBRID_MODEL_KIND.equals(value.path("model_kind").asText())
                || value.path("recipe_version").asInt(-1) != 1
                || !UebaExperimentCatalog.HYBRID_STATE_FORMAT.equals(value.path("model_state_format").asText())) throw invalid();
        for (String key : List.of("manifest_sha256", "policy_sha256", "blocked_holdout_split_sha256",
                "selected_model_sha256", "selected_calibration_sha256", "model_state_sha256",
                "model_state_verifier_sha256", "recipe_sha256", "strict_proof_sha256", "selection_sha256")) {
            if (!value.path(key).asText().matches("[a-f0-9]{64}")) throw invalid();
        }
        JsonNode labels = value.path("source_label_manifest_sha256_by_fold");
        requireKeys(labels, Set.of("1", "2", "3"));
        Map<String, String> labelShas = new LinkedHashMap<>();
        for (String fold : List.of("1", "2", "3")) {
            if (!labels.path(fold).asText().matches("[a-f0-9]{64}")) throw invalid();
            labelShas.put(fold, labels.path(fold).asText());
        }
        if (count(value, "training_windows", 50000) != 50000
                || count(value, "calibration_windows", 2000000) != 2000000
                || count(value, "fold", 3) != 3 || count(value, "random_state", 42) != 42
                || count(value, "completed_search_fits", 360) != 360
                || count(value, "zero_fit_recalibrations", 360) < 45
                || count(value, "zero_fit_recalibrations", 360) > 360) throw invalid();
        try {
            var descriptor = new com.flarefitness.backend.dto.siem.SiemDtos.UebaRecipe(
                    value.path("recipe_id").asText(), value.path("dataset_id").asText(), "DEMO_ONLY", 4,
                    50000, 2000000, utcDate(value.path("from_utc").asText()), utcDate(value.path("to_utc").asText()), 360);
            var hybrid = new UebaExperimentCatalog.HybridStrictReference(
                    value.path("strict_proof_sha256").asText(), value.path("selection_sha256").asText(),
                    Map.copyOf(labelShas), value.path("zero_fit_recalibrations").asInt());
            return new UebaExperimentCatalog.StrictReference(descriptor, value.path("manifest_sha256").asText(),
                    value.path("policy_sha256").asText(), "STRICT", value.path("blocked_holdout_split_sha256").asText(),
                    value.path("selected_model_sha256").asText(), value.path("selected_calibration_sha256").asText(),
                    value.path("model_state_sha256").asText(), value.path("model_state_verifier_sha256").asText(),
                    UebaExperimentCatalog.HYBRID_MODEL_KIND, 1, value.path("recipe_sha256").asText(),
                    UebaExperimentCatalog.HYBRID_STATE_FORMAT, null, hybrid);
        } catch (RuntimeException failure) {
            throw invalid();
        }
    }

    private static LocalDateTime utcDate(String text) {
        try { return OffsetDateTime.parse(text).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime(); }
        catch (java.time.format.DateTimeParseException ignored) {
            return LocalDateTime.parse(text);
        }
    }

    private static Set<String> fields(JsonNode node) {
        if (!node.isObject()) throw invalid();
        var names = new java.util.HashSet<String>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    public static Map<String, Object> validate(ObjectMapper json, JsonNode root, String version, String modelSha,
            UebaExperimentCatalog.StrictReference recipe) {
        int schema = recipe.descriptor().featureSchemaVersion();
        if (!Set.of(2, 3, 4).contains(schema)) throw invalid();
        if (!"STRICT".equals(recipe.mode()) || !"SUCCEEDED".equals(root.path("status").asText())
                || !version.equals(root.path("model_version").asText()) || !modelSha.equals(root.path("model_sha256").asText())
                || !recipe.expectedCalibrationSha256().equals(root.path("calibration_sha256").asText())
                || !recipe.policySha256().equals(root.path("policy_sha256").asText())
                || !recipe.manifestSha256().equals(root.path("dataset_sha256").asText())
                || !recipe.holdoutSplitSha256().equals(root.path("evaluation_identity").path("holdout_split_sha256").asText())
                || !"FROZEN_HOLDOUT".equals(root.path("evaluation_scope").asText())
                || !"DEMO_ONLY".equals(root.path("data_provenance").asText())
                || !root.path("raw_episode_audit_completed").isBoolean() || !root.path("raw_episode_audit_completed").asBoolean()
                || count(root, "actual_scored_episodes", 10010000) != 10010000
                || !root.path("feature_schema_version").isIntegralNumber() || root.path("feature_schema_version").asInt() != schema
                || !root.path("scored_journal_sha256").asText().matches("[a-f0-9]{64}")) throw invalid();
        if (recipe.expectedModelStateSha256() == null) {
            // Compatibility for an already bound binary reference. Newly
            // installed strict registries require numeric-state identity too.
            if (!UebaExperimentCatalog.IF_MODEL_KIND.equals(recipe.modelKind()) || !recipe.expectedModelSha256().equals(modelSha)) throw invalid();
        } else {
            JsonNode identity = root.path("evaluation_identity");
            if (!modelSha.equals(identity.path("model_sha256").asText())
                    || !recipe.expectedModelSha256().equals(identity.path("selected_reference_model_sha256").asText())
                    || !recipe.expectedModelStateSha256().equals(identity.path("model_state_sha256").asText())
                    || !recipe.modelStateVerifierSha256().equals(identity.path("model_state_verifier_sha256").asText())
                    || !UebaExperimentCatalog.stateFormat(recipe.modelKind()).equals(recipe.modelStateFormat())
                    || !recipe.modelStateFormat().equals(identity.path("model_state_format").asText())) throw invalid();
            if (recipe.recipeSha256() != null || !UebaExperimentCatalog.IF_MODEL_KIND.equals(recipe.modelKind())) {
                UebaExperimentCatalog.RecipeIdentity actual;
                try { actual = UebaExperimentCatalog.recipeIdentity(identity); }
                catch (RuntimeException failure) { throw invalid(); }
                if (!recipe.modelKind().equals(actual.modelKind()) || recipe.recipeVersion() != actual.recipeVersion()
                        || !java.util.Objects.equals(recipe.recipeSha256(), actual.recipeSha256())) throw invalid();
            }
            if (UebaExperimentCatalog.HYBRID_MODEL_KIND.equals(recipe.modelKind())
                    && !UebaExperimentCatalog.matchesHybridStrictProof(identity.path("hybrid_strict_proof"), recipe)) throw invalid();
        }
        requireKeys(root.path("scopes"), SCOPES);
        boolean pass = true;
        Map<String, Object> verifiedScopes = new LinkedHashMap<>();
        for (String scope : SCOPES) {
            JsonNode value = root.path("scopes").path(scope);
            pass &= scope(value, scope, recipe.policySha256(), schema);
            Counts counts = counts(value, 10010000);
            double accuracy = (double) (counts.tp() + counts.tn()) / 10010000;
            pass &= accuracy > 0.98;
            Map<String, Object> verified = json.convertValue(value, new com.fasterxml.jackson.core.type.TypeReference<>() { });
            verified.put("accuracy", accuracy);
            verifiedScopes.put(scope, verified);
        }
        String expectedGate = pass ? "PASS" : "FAIL";
        if (!expectedGate.equals(root.path("quality_gate").asText())) throw invalid();
        Map<String, Object> result = new LinkedHashMap<>();
        // Do not copy arbitrary upstream fields such as a forged shadow_gate.
        for (String key : List.of("status", "model_version", "model_sha256", "feature_schema_version", "calibration_sha256",
                "policy_sha256", "dataset_sha256", "evaluation_scope", "data_provenance", "evaluation_identity", "quality_math_binding",
                "actual_scored_episodes", "raw_episode_audit_completed", "scored_journal_sha256", "completed_at_utc")) {
            result.put(key, json.convertValue(root.path(key), Object.class));
        }
        result.put("scopes", verifiedScopes);
        result.put("quality_gate", expectedGate); result.put("catalogue_mode", "STRICT");
        result.put("dataset_id", recipe.descriptor().datasetId()); result.put("dataset_manifest_sha256", recipe.manifestSha256());
        result.put("frozen_holdout_split_sha256", recipe.holdoutSplitSha256());
        return result;
    }

    /** Validate the fresh post-selection holdout while preserving the original training identity. */
    public static Map<String, Object> validateRecovered(ObjectMapper json, JsonNode candidate,
            String version, UebaExperimentCatalog.StrictReference recipe, String adoptionReceiptSha256) {
        JsonNode metadata = candidate.path("metadata");
        JsonNode root = candidate.path("evaluation");
        JsonNode identity = candidate.path("evaluation_identity");
        JsonNode adoption = candidate.path("adoption_receipt");
        int schema = recipe.descriptor().featureSchemaVersion();
        String modelSha = metadata.path("sha256").asText();
        if (schema != 4 || !"STRICT".equals(recipe.mode())
                || !version.equals(candidate.path("model_version").asText())
                || !version.equals(metadata.path("model_version").asText())
                || !recipe.modelKind().equals(metadata.path("model_kind").asText())
                || !exactInt(metadata.path("recipe_version"), recipe.recipeVersion())
                || !java.util.Objects.equals(recipe.recipeSha256(), metadata.path("recipe_sha256").asText())
                || !"QUALIFIED".equals(candidate.path("status").asText())
                || !hexHash(candidate.path("adoption_receipt_sha256"))
                || !adoptionReceiptSha256.equals(candidate.path("adoption_receipt_sha256").asText())
                || !modelSha.equals(recipe.expectedModelSha256())
                || !modelSha.equals(adoption.path("model_sha256").asText())
                || !recipe.expectedCalibrationSha256().equals(metadata.path("calibration_sha256").asText())
                || !recipe.policySha256().equals(metadata.path("score_policy").path("policy_sha256").asText())
                || !recipe.manifestSha256().equals(metadata.path("dataset_manifest_sha256").asText())
                || !recipe.manifestSha256().equals(identity.path("original_training_manifest_sha256").asText())
                || !recipe.expectedModelSha256().equals(adoption.path("selected_reference_model_sha256").asText())
                || identity.path("fresh_holdout_manifest_sha256").asText().equals(recipe.manifestSha256())
                || identity.path("holdout_split_sha256").asText().equals(recipe.holdoutSplitSha256())
                || !recipe.expectedModelStateSha256().equals(identity.path("model_state_sha256").asText())
                || !recipe.modelStateVerifierSha256().equals(identity.path("model_state_verifier_sha256").asText())
                || !recipe.modelStateFormat().equals(identity.path("model_state_format").asText())
                || !recipe.policySha256().equals(identity.path("policy_sha256").asText())
                || !recipe.expectedCalibrationSha256().equals(identity.path("calibration_sha256").asText())
                || !recipe.manifestSha256().equals(root.path("dataset_sha256").asText())
                || !identity.path("fresh_holdout_manifest_sha256").asText().equals(adoption.path("fresh_holdout_manifest_sha256").asText())
                || !identity.path("holdout_split_sha256").asText().equals(adoption.path("holdout_split_sha256").asText())
                || !identity.path("frozen_selection_receipt_sha256").asText().equals(adoption.path("selection_receipt_sha256").asText())
                || !matchesHybridRecoveryProof(identity.path("hybrid_strict_proof"), recipe)
                || !"SUCCEEDED".equals(root.path("status").asText())
                || !version.equals(root.path("model_version").asText())
                || !modelSha.equals(root.path("model_sha256").asText())
                || !recipe.expectedCalibrationSha256().equals(root.path("calibration_sha256").asText())
                || !recipe.policySha256().equals(root.path("policy_sha256").asText())
                || !"FROZEN_HOLDOUT".equals(root.path("evaluation_scope").asText())
                || !"DEMO_ONLY".equals(root.path("data_provenance").asText())
                || !identity.equals(root.path("evaluation_identity"))
                || !root.path("raw_episode_audit_completed").isBoolean()
                || !root.path("raw_episode_audit_completed").asBoolean()
                || count(root, "actual_scored_episodes", 10010000) != 10010000
                || !root.path("scored_journal_sha256").asText().matches("[a-f0-9]{64}")) {
            throw invalid();
        }
        var provenance = adoption.path("selection_proof");
        if (!exactInt(provenance.path("actual_composite_trials"), 360)
                || !exactInt(provenance.path("actual_component_fit_calls"), 720)
                || !exactInt(provenance.path("validation_runs"), 360)
                || !provenance.path("zero_fit_recalibrations").canConvertToInt()
                || provenance.path("zero_fit_recalibrations").asInt() < 45
                || provenance.path("zero_fit_recalibrations").asInt() > 360
                || !provenance.path("holdout_scored").isBoolean()
                || provenance.path("holdout_scored").asBoolean()) throw invalid();

        requireKeys(root.path("scopes"), SCOPES);
        boolean pass = true;
        Map<String, Object> verifiedScopes = new LinkedHashMap<>();
        for (String scopeName : SCOPES) {
            JsonNode scope = root.path("scopes").path(scopeName);
            pass &= scope(scope, scopeName, recipe.policySha256(), schema);
            Counts counts = counts(scope, 10010000);
            double accuracy = (double) (counts.tp() + counts.tn()) / 10010000;
            pass &= accuracy > 0.98;
            Map<String, Object> verified = json.convertValue(scope, new com.fasterxml.jackson.core.type.TypeReference<>() { });
            verified.put("accuracy", accuracy);
            verifiedScopes.put(scopeName, verified);
        }
        String expectedGate = pass ? "PASS" : "FAIL";
        if (!expectedGate.equals(root.path("quality_gate").asText())) throw invalid();
        Map<String, Object> result = new LinkedHashMap<>();
        for (String key : List.of("status", "model_version", "model_sha256", "feature_schema_version",
                "calibration_sha256", "policy_sha256", "dataset_sha256", "evaluation_scope",
                "data_provenance", "actual_scored_episodes", "raw_episode_audit_completed",
                "scored_journal_sha256", "completed_at_utc", "quality_math_binding")) {
            result.put(key, json.convertValue(root.path(key), Object.class));
        }
        result.put("evaluation_identity", json.convertValue(identity, Object.class));
        result.put("scopes", verifiedScopes);
        result.put("quality_gate", expectedGate);
        result.put("catalogue_mode", "STRICT_FRESH_RECOVERY");
        result.put("dataset_id", adoption.path("fresh_holdout_dataset_id").asText());
        result.put("dataset_manifest_sha256", recipe.manifestSha256());
        result.put("frozen_holdout_split_sha256", adoption.path("holdout_split_sha256").asText());
        result.put("execution_origin", "OPERATOR_ADOPTED");
        result.put("adoption_receipt_sha256", adoptionReceiptSha256);
        return result;
    }

    private static boolean matchesHybridRecoveryProof(JsonNode value, UebaExperimentCatalog.StrictReference recipe) {
        return UebaExperimentCatalog.HYBRID_MODEL_KIND.equals(recipe.modelKind())
                && UebaExperimentCatalog.matchesHybridStrictProof(value, recipe);
    }

    private static boolean exactInt(JsonNode value, int expected) {
        return value.isIntegralNumber() && value.canConvertToInt() && value.asInt() == expected;
    }

    private static boolean scope(JsonNode value, String name, String policySha, int schema) {
        if (!name.equals(value.path("scope").asText()) || !"FROZEN_HOLDOUT".equals(value.path("evaluation_scope").asText())
                || !"DEMO_ONLY".equals(value.path("data_provenance").asText())) throw invalid();
        var envelope = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
        for (String key : List.of("policy_id", "policy_sha256", "policy_document_json")) envelope.set(key, value.path(key));
        var policy = UebaScorePolicy.fromWire(envelope, schema);
        // Metrics carry the policy fields at their root, rather than a separate envelope.
        if (!policy.strict() || !policySha.equals(policy.sha256())) throw invalid();
        Counts counts = counts(value, 10010000);
        if (counts.normal() != 10000000 || counts.positive() != 10000
                || count(value, "normal_samples", 10000000) != counts.normal()
                || count(value, "positive_samples", 10000) != counts.positive()) throw invalid();
        checkRate(value, "precision", counts.precision()); checkRate(value, "recall", counts.recall()); checkRate(value, "false_positive_rate", counts.fpr());
        double accuracy = (double) (counts.tp() + counts.tn()) / 10010000;
        boolean pass = accuracy > 0.98 && counts.precision() != null
                && counts.precision() >= 0.998 && counts.recall() > 0.99 && counts.fpr() < 0.001;
        JsonNode confidence = value.path("confidence");
        if (!"exact_binomial_and_account_day_cluster_bootstrap".equals(confidence.path("method").asText())
                || !confidence.path("cluster_available").isBoolean() || !confidence.path("cluster_available").asBoolean()
                || count(confidence, "comparisons", 6) != 6 || count(confidence, "resamples", 5000) != 5000
                || count(confidence, "clusters", 10010000) < 2
                || !confidence.path("cluster_counter_sha256").asText().matches("[a-f0-9]{64}")) throw invalid();
        if (Math.abs(probability(confidence.path("familywise_confidence")) - 0.95) > 1e-12
                || Math.abs(probability(confidence.path("one_sided_alpha")) - 0.05 / 6) > 1e-12) throw invalid();
        JsonNode conservative = confidence.path("conservative");
        for (String metric : List.of("precision", "recall", "false_positive_rate")) {
            JsonNode exact = confidence.path("exact").path(metric), cluster = confidence.path("cluster").path(metric);
            boolean exactAvailable = bounds(exact), clusterAvailable = bounds(cluster);
            boolean conservativeAvailable = bounds(conservative.path(metric));
            if (conservativeAvailable != (exactAvailable && clusterAvailable)) throw invalid();
            pass &= conservativeAvailable;
            if (Math.abs(conservative.path(metric).path("lower").asDouble() - Math.min(exact.path("lower").asDouble(), cluster.path("lower").asDouble())) > 1e-12
                    || Math.abs(conservative.path(metric).path("upper").asDouble() - Math.max(exact.path("upper").asDouble(), cluster.path("upper").asDouble())) > 1e-12) throw invalid();
        }
        pass &= conservative.path("precision").path("lower").asDouble() >= 0.998
                && conservative.path("recall").path("lower").asDouble() > 0.99
                && conservative.path("false_positive_rate").path("upper").asDouble() < 0.001;
        requireKeys(value.path("families"), FAMILIES);
        long positives = 0, familyTp = 0, familyFn = 0;
        for (String family : FAMILIES) {
            Counts row = counts(value.path("families").path(family), 10000); positives += row.positive();
            familyTp += row.tp(); familyFn += row.fn();
            if (row.normal() != 0 || row.positive() < 2000) throw invalid();
            pass &= row.recall() > 0.99;
        }
        if (positives != counts.positive() || familyTp != counts.tp() || familyFn != counts.fn()) throw invalid();
        requireKeys(value.path("cohorts"), COHORTS);
        long normal = 0, cohortTp = 0, cohortFn = 0, cohortFp = 0, cohortTn = 0; positives = 0;
        for (String cohort : COHORTS) {
            Counts row = counts(value.path("cohorts").path(cohort), 10010000); normal += row.normal(); positives += row.positive();
            cohortTp += row.tp(); cohortFn += row.fn(); cohortFp += row.fp(); cohortTn += row.tn();
            if (row.positive() == 0) throw invalid();
            pass &= row.recall() > 0.99;
        }
        if (normal != counts.normal() || positives != counts.positive() || cohortTp != counts.tp() || cohortFn != counts.fn()
                || cohortFp != counts.fp() || cohortTn != counts.tn()
                || !(pass ? "PASS" : "FAIL").equals(value.path("quality_gate").asText())) throw invalid();
        return pass;
    }

    private static boolean bounds(JsonNode value) {
        if (!value.path("available").isBoolean()
                || probability(value.path("lower")) > probability(value.path("upper"))) throw invalid();
        return value.path("available").asBoolean();
    }
    private static boolean hexHash(JsonNode value) {
        return value.isTextual() && value.asText().matches("[a-f0-9]{64}");
    }
    private static Counts counts(JsonNode value, long maximum) {
        return new Counts(count(value, "tp", maximum), count(value, "fn", maximum), count(value, "fp", maximum), count(value, "tn", maximum));
    }
    private static long count(JsonNode value, String key, long maximum) {
        JsonNode number = value.path(key);
        if (!number.isIntegralNumber() || !number.canConvertToLong() || number.asLong() < 0 || number.asLong() > maximum) throw invalid();
        return number.asLong();
    }
    private static Double probability(JsonNode value) {
        if (!value.isNumber() || !Double.isFinite(value.asDouble()) || value.asDouble() < 0 || value.asDouble() > 1) throw invalid();
        return value.asDouble();
    }
    private static void checkRate(JsonNode value, String name, Double expected) {
        if (expected == null ? !value.path(name).isNull() : Math.abs(probability(value.path(name)) - expected) > 1e-9) throw invalid();
    }
    private static void requireKeys(JsonNode value, Set<String> expected) {
        Set<String> actual = new java.util.HashSet<>(); value.fieldNames().forEachRemaining(actual::add);
        if (!value.isObject() || !actual.equals(expected)) throw invalid();
    }
    private record Counts(long tp, long fn, long fp, long tn) {
        long positive() { return tp + fn; } long normal() { return fp + tn; }
        Double precision() { return tp + fp == 0 ? null : (double) tp / (tp + fp); }
        double recall() { return positive() == 0 ? 0 : (double) tp / positive(); }
        double fpr() { return normal() == 0 ? 0 : (double) fp / normal(); }
    }
    private static ServiceUnavailableException invalid() { return new ServiceUnavailableException("Strict UEBA evaluation failed integrity or gate validation."); }
}
