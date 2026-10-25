package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Counter/wire contract fixtures only; these are NOT actual scored benchmark results. */
class UebaStrictEvaluationTest {
    final ObjectMapper json = new ObjectMapper();
    ObjectNode policy;
    UebaExperimentCatalog.StrictReference recipe;
    @BeforeEach void setup() throws Exception {
        policy = (ObjectNode) json.readTree(getClass().getResourceAsStream("/ueba-score-policy-golden.json"));
        recipe = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe("owned-strict-recipe", "owned-strict-data", "DEMO_ONLY",
                2, 50000, 2000000, LocalDateTime.of(2026, 1, 1, 0, 0), LocalDateTime.of(2026, 2, 1, 0, 0), 360),
                "b".repeat(64), policy.path("policy_sha256").asText(), "STRICT", "d".repeat(64), "a".repeat(64), "c".repeat(64));
    }
    @Test void validatesBothScopesAndDoesNotImportAnUpstreamShadowPass() {
        var root = result(); root.put("shadow_gate", "PASS");
        var value = validate(root); assertThat(value.get("quality_gate")).isEqualTo("PASS");
        assertThat(value).doesNotContainKey("shadow_gate"); assertThat(value.get("catalogue_mode")).isEqualTo("STRICT");
    }
    @Test void staleBindingMissingScopeOrCounterConservationCannotMasqueradeAsPass() {
        var changed = result(); changed.put("model_sha256", "f".repeat(64)); rejects(changed);
        changed = result(); changed.withObject("scopes").remove("MODEL_ONLY"); rejects(changed);
        changed = result(); changed.withObject("/scopes/MODEL_ONLY/cohorts/COLD").put("tp", 999); rejects(changed);
        changed = result(); changed.withObject("/scopes/MODEL_ONLY/families/endpoint_scan").put("tp", 1999).put("fn", 1); rejects(changed);
    }
    @Test void pointPassCannotHideFailingConfidenceAndBothDecisionLayersAreRequired() {
        var root = result(); var confidence = root.withObject("/scopes/MODEL_ONLY/confidence");
        for (String kind : List.of("exact", "cluster", "conservative")) confidence.withObject("/" + kind + "/precision").put("lower", 0.997);
        root.withObject("/scopes/MODEL_ONLY").put("quality_gate", "FAIL"); root.put("quality_gate", "FAIL");
        assertThat(validate(root).get("quality_gate")).isEqualTo("FAIL");
        root.put("quality_gate", "PASS"); rejects(root);
        root = result(); root.withObject("/scopes/SIEM_FINAL/confidence/conservative/precision").put("lower", 0.9999); rejects(root);
    }
    @Test void refittedFileShaRemainsBoundWhileNumericIdentityMatchesTheFrozenReference() {
        recipe = new UebaExperimentCatalog.StrictReference(recipe.descriptor(), recipe.manifestSha256(), recipe.policySha256(),
                "STRICT", recipe.holdoutSplitSha256(), "f".repeat(64), recipe.expectedCalibrationSha256(), "e".repeat(64), "b".repeat(64));
        var root = result(); var identity = root.withObject("/evaluation_identity");
        identity.put("model_sha256", "a".repeat(64)); identity.put("selected_reference_model_sha256", "f".repeat(64));
        identity.put("model_state_sha256", "e".repeat(64)); identity.put("model_state_verifier_sha256", "b".repeat(64));
        identity.put("model_state_format", "SKLEARN_NUMERIC_STATE_V2");
        assertThat(validate(root).get("quality_gate")).isEqualTo("PASS");
        for (String field : List.of("model_sha256", "selected_reference_model_sha256", "model_state_sha256", "model_state_verifier_sha256", "model_state_format")) {
            var changed = root.deepCopy(); changed.withObject("/evaluation_identity").put(field, "changed"); rejects(changed);
        }
        var changed = root.deepCopy(); changed.put("model_sha256", "f".repeat(64)); rejects(changed);
    }
    @Test void availableConservativeBoundsCannotHideMissingExactOrClusterEvidence() {
        for (String scope : List.of("MODEL_ONLY", "SIEM_FINAL")) {
            for (String kind : List.of("exact", "cluster")) {
                for (String metric : List.of("precision", "recall", "false_positive_rate")) {
                    var changed = result();
                    changed.withObject("/scopes/" + scope + "/confidence/" + kind + "/" + metric).put("available", false);
                    rejects(changed);
                }
            }
        }
    }

    @Test void recoveredEvaluationUsesFreshHoldoutAndOriginalTrainingIdentity() throws Exception {
        policy = UebaTestPolicies.sessionEndpoint(json);
        Map<String, String> labelShas = Map.of("1", "1".repeat(64), "2", "2".repeat(64), "3", "3".repeat(64));
        var proof = new UebaExperimentCatalog.HybridStrictReference("8".repeat(64), "9".repeat(64), labelShas, 45);
        var descriptor = new SiemDtos.UebaRecipe("owned-strict-recipe", "owned-strict-data", "DEMO_ONLY",
                4, 50000, 2000000, LocalDateTime.of(2026, 1, 1, 0, 0),
                LocalDateTime.of(2026, 2, 1, 0, 0), 360);
        recipe = new UebaExperimentCatalog.StrictReference(descriptor, "b".repeat(64),
                policy.path("policy_sha256").asText(), "STRICT", "d".repeat(64), "a".repeat(64),
                "c".repeat(64), "e".repeat(64), "f".repeat(64),
                UebaExperimentCatalog.HYBRID_MODEL_KIND, 1, "9".repeat(64),
                UebaExperimentCatalog.HYBRID_STATE_FORMAT, null, proof);

        ObjectNode root = result();
        root.put("model_version", "recovered-model");
        ObjectNode identity = root.withObject("evaluation_identity");
        identity.put("model_sha256", "a".repeat(64));
        identity.put("model_state_sha256", "e".repeat(64));
        identity.put("model_state_verifier_sha256", "f".repeat(64));
        identity.put("model_state_format", UebaExperimentCatalog.HYBRID_STATE_FORMAT);
        identity.put("policy_sha256", recipe.policySha256());
        identity.put("calibration_sha256", "c".repeat(64));
        identity.put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND);
        identity.put("recipe_version", 1);
        identity.put("recipe_sha256", "9".repeat(64));
        identity.put("original_training_manifest_sha256", "b".repeat(64));
        identity.put("fresh_holdout_manifest_sha256", "6".repeat(64));
        identity.put("holdout_split_sha256", "7".repeat(64));
        identity.put("frozen_selection_receipt_sha256", "5".repeat(64));
        ObjectNode strictProof = identity.putObject("hybrid_strict_proof");
        strictProof.put("format", "HYBRID_STRICT_PROOF_V1").put("proof_sha256", proof.proofSha256())
                .put("selection_sha256", proof.selectionSha256()).put("actual_composite_trials", 360)
                .put("actual_component_fit_calls", 720).put("validation_runs", 360).put("zero_fit_recalibrations", 45);
        ObjectNode labels = strictProof.putObject("source_label_manifests");
        labelShas.forEach((fold, sha) -> labels.putObject(fold).put("artifact_id", "labels-fold" + fold).put("manifest_sha256", sha));
        root.set("evaluation_identity", identity.deepCopy());

        ObjectNode candidate = json.createObjectNode(); candidate.put("status", "QUALIFIED");
        candidate.put("model_version", "recovered-model"); candidate.put("adoption_receipt_sha256", "4".repeat(64));
        candidate.set("evaluation", root);
        ObjectNode metadata = candidate.putObject("metadata");
        metadata.put("model_version", "recovered-model").put("sha256", "a".repeat(64)).put("feature_schema_version", 4)
                .put("calibration_scope", "STRICT").put("calibration_sha256", "c".repeat(64))
                .put("dataset_manifest_sha256", "b".repeat(64)).put("model_state_sha256", "e".repeat(64))
                .put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND)
                .put("recipe_version", 1).put("recipe_sha256", "9".repeat(64))
                .putObject("score_policy").put("policy_sha256", policy.path("policy_sha256").asText());
        candidate.set("evaluation_identity", identity.deepCopy());
        ObjectNode adoption = candidate.putObject("adoption_receipt");
        adoption.put("recipe_id", "owned-strict-recipe").put("original_dataset_id", "owned-strict-data")
                .put("original_training_manifest_sha256", "b".repeat(64)).put("model_sha256", "a".repeat(64))
                .put("selected_reference_model_sha256", "a".repeat(64)).put("model_state_sha256", "e".repeat(64))
                .put("fresh_holdout_dataset_id", "fresh-holdout-run1")
                .put("fresh_holdout_manifest_sha256", "6".repeat(64)).put("holdout_split_sha256", "7".repeat(64))
                .put("selection_receipt_sha256", "5".repeat(64));
        adoption.putObject("selection_proof").put("actual_composite_trials", 360).put("actual_component_fit_calls", 720)
                .put("validation_runs", 360).put("zero_fit_recalibrations", 45).put("holdout_scored", false);

        var accepted = UebaStrictEvaluation.validateRecovered(json, candidate, "recovered-model", recipe, "4".repeat(64));
        assertThat(accepted.get("quality_gate")).isEqualTo("PASS");
        assertThat(accepted.get("execution_origin")).isEqualTo("OPERATOR_ADOPTED");
        assertThat(accepted.get("frozen_holdout_split_sha256")).isEqualTo("7".repeat(64));
        assertThat(((Map<?, ?>) accepted.get("scopes")).get("MODEL_ONLY")).isInstanceOf(Map.class);

        var oldSplit = candidate.deepCopy();
        oldSplit.withObject("/evaluation_identity").put("holdout_split_sha256", recipe.holdoutSplitSha256());
        oldSplit.withObject("/evaluation").withObject("/evaluation_identity").put("holdout_split_sha256", recipe.holdoutSplitSha256());
        oldSplit.withObject("/adoption_receipt").put("holdout_split_sha256", recipe.holdoutSplitSha256());
        assertThatThrownBy(() -> UebaStrictEvaluation.validateRecovered(json, oldSplit,
                "recovered-model", recipe, "4".repeat(64))).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void contextualEvaluationRequiresMatchingRegisteredSchemaAndBothPolicyScopes() throws Exception {
        policy = UebaTestPolicies.contextual(json);
        var old = recipe.descriptor();
        recipe = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe(old.recipeId(), old.datasetId(), old.dataProvenance(),
                3, old.trainingWindows(), old.calibrationWindows(), old.from(), old.to(), old.completedSearchFits()),
                recipe.manifestSha256(), policy.path("policy_sha256").asText(), recipe.mode(), recipe.holdoutSplitSha256(),
                recipe.expectedModelSha256(), recipe.expectedCalibrationSha256());
        var root = result(); assertThat(validate(root).get("feature_schema_version")).isEqualTo(3);
        var changed = root.deepCopy(); changed.put("feature_schema_version", 2); rejects(changed);
        changed = root.deepCopy();
        var legacy = json.readTree(getClass().getResourceAsStream("/ueba-score-policy-golden.json"));
        ObjectNode scope = changed.withObject("/scopes/SIEM_FINAL");
        legacy.fields().forEachRemaining(field -> scope.set(field.getKey(), field.getValue()));
        rejects(changed);
    }

    @Test void strictTypedEvaluationDispatchesSupportAndHybridStateAndRequiresHybridProof() throws Exception {
        policy = UebaTestPolicies.sessionEndpoint(json);
        var descriptor = recipe.descriptor();
        for (String kind : List.of(UebaExperimentCatalog.SUPPORT_MODEL_KIND, UebaExperimentCatalog.HYBRID_MODEL_KIND)) {
            var proof = new UebaExperimentCatalog.HybridStrictReference("7".repeat(64), "6".repeat(64),
                    java.util.Map.of("1", "1".repeat(64), "2", "2".repeat(64), "3", "8".repeat(64)), 45);
            recipe = new UebaExperimentCatalog.StrictReference(new SiemDtos.UebaRecipe(descriptor.recipeId(), descriptor.datasetId(), "DEMO_ONLY", 4,
                    50000, 2000000, descriptor.from(), descriptor.to(), 360), "b".repeat(64), policy.path("policy_sha256").asText(), "STRICT",
                    "d".repeat(64), "f".repeat(64), "c".repeat(64), "e".repeat(64), "b".repeat(64), kind, 1, "9".repeat(64),
                    UebaExperimentCatalog.stateFormat(kind), null, kind.equals(UebaExperimentCatalog.HYBRID_MODEL_KIND) ? proof : null);
            var root = result(); var identity = root.withObject("/evaluation_identity");
            identity.put("model_sha256", "a".repeat(64)).put("selected_reference_model_sha256", "f".repeat(64)).put("model_state_sha256", "e".repeat(64))
                    .put("model_state_verifier_sha256", "b".repeat(64)).put("model_state_format", recipe.modelStateFormat())
                    .put("model_kind", kind).put("recipe_version", 1).put("recipe_sha256", "9".repeat(64));
            if (kind.equals(UebaExperimentCatalog.HYBRID_MODEL_KIND)) {
                rejects(root);
                var summary = identity.putObject("hybrid_strict_proof").put("format", "HYBRID_STRICT_PROOF_V1").put("proof_sha256", proof.proofSha256())
                        .put("selection_sha256", proof.selectionSha256()).put("actual_composite_trials", 360).put("actual_component_fit_calls", 720)
                        .put("validation_runs", 360).put("zero_fit_recalibrations", 45);
                var sources = summary.putObject("source_label_manifests");
                proof.sourceManifestSha256ByFold().forEach((fold, sha) -> sources.putObject(fold).put("artifact_id", "labels-fold" + fold).put("manifest_sha256", sha));
                var changed = root.deepCopy(); changed.withObject("/evaluation_identity/hybrid_strict_proof").put("proof_sha256", "0".repeat(64)); rejects(changed);
                changed = root.deepCopy(); changed.withObject("/evaluation_identity/hybrid_strict_proof/source_label_manifests/3").put("manifest_sha256", "0".repeat(64)); rejects(changed);
                changed = root.deepCopy(); changed.withObject("/evaluation_identity/hybrid_strict_proof").put("actual_component_fit_calls", 360); rejects(changed);
            }
            assertThat(validate(root).get("quality_gate")).isEqualTo("PASS");
            var changed = root.deepCopy(); changed.withObject("/evaluation_identity").put("model_state_format", UebaExperimentCatalog.IF_STATE_FORMAT); rejects(changed);
            for (String name : List.of("model_kind", "recipe_version", "recipe_sha256")) {
                changed = root.deepCopy(); changed.withObject("/evaluation_identity").remove(name); rejects(changed);
            }
        }
    }
    private void rejects(ObjectNode value) { assertThatThrownBy(() -> validate(value)).isInstanceOf(ServiceUnavailableException.class); }
    private java.util.Map<String, Object> validate(ObjectNode value) { return UebaStrictEvaluation.validate(json, value, "owned-strict-model", "a".repeat(64), recipe); }
    private ObjectNode result() {
        ObjectNode root = json.createObjectNode(); root.put("status", "SUCCEEDED"); root.put("model_version", "owned-strict-model");
        root.put("model_sha256", "a".repeat(64)); root.put("dataset_sha256", "b".repeat(64)); root.put("calibration_sha256", "c".repeat(64));
        root.put("policy_sha256", recipe.policySha256()); root.put("feature_schema_version", recipe.descriptor().featureSchemaVersion()); root.put("evaluation_scope", "FROZEN_HOLDOUT");
        root.put("data_provenance", "DEMO_ONLY"); root.put("raw_episode_audit_completed", true); root.put("actual_scored_episodes", 10010000);
        root.put("scored_journal_sha256", "e".repeat(64)); root.put("quality_gate", "PASS");
        root.putObject("evaluation_identity").put("holdout_split_sha256", recipe.holdoutSplitSha256());
        for (String scope : List.of("MODEL_ONLY", "SIEM_FINAL")) {
            ObjectNode entry = root.withObject("scopes").putObject(scope); counts(entry, 10000, 10000000);
            entry.put("scope", scope); entry.put("evaluation_scope", "FROZEN_HOLDOUT"); entry.put("data_provenance", "DEMO_ONLY"); entry.put("quality_gate", "PASS");
            policy.fields().forEachRemaining(field -> entry.set(field.getKey(), field.getValue()));
            ObjectNode confidence = entry.putObject("confidence"); confidence.put("method", "exact_binomial_and_account_day_cluster_bootstrap");
            confidence.put("cluster_available", true); confidence.put("comparisons", 6); confidence.put("resamples", 5000); confidence.put("clusters", 1000);
            confidence.put("cluster_counter_sha256", "f".repeat(64)); confidence.put("familywise_confidence", 0.95); confidence.put("one_sided_alpha", 0.05 / 6);
            for (String kind : List.of("exact", "cluster", "conservative")) {
                ObjectNode group = confidence.putObject(kind);
                for (String metric : List.of("precision", "recall", "false_positive_rate")) {
                    ObjectNode bound = group.putObject(metric); bound.put("available", true);
                    bound.put("lower", metric.equals("false_positive_rate") ? 0 : 0.9995);
                    bound.put("upper", metric.equals("false_positive_rate") ? 0.000001 : 1);
                }
            }
            for (String family : List.of("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")) counts(entry.withObject("families").putObject(family), 2000, 0);
            counts(entry.withObject("cohorts").putObject("READY"), 7000, 7000000);
            counts(entry.withObject("cohorts").putObject("UNSEEN_READY"), 2000, 2000000);
            counts(entry.withObject("cohorts").putObject("COLD"), 1000, 1000000);
        }
        return root;
    }
    private void counts(ObjectNode value, int positives, int normals) {
        value.put("tp", positives); value.put("fn", 0); value.put("fp", 0); value.put("tn", normals);
        value.put("normal_samples", normals); value.put("positive_samples", positives); value.put("precision", 1); value.put("recall", 1); value.put("false_positive_rate", 0);
    }
}
