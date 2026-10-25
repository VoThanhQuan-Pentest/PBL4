package com.flarefitness.backend.service.siem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Operator-installed immutable numeric datasets. Public clients supply IDs, never files or labels. */
@Component
public class UebaExperimentCatalog {
    static final String IF_MODEL_KIND = "isolation_forest";
    static final String SUPPORT_MODEL_KIND = "normal_support_distance";
    static final String HYBRID_MODEL_KIND = "normal_plus_incident_research";
    static final String IF_STATE_FORMAT = "SKLEARN_NUMERIC_STATE_V2";
    static final String SUPPORT_STATE_FORMAT = "NORMAL_SUPPORT_NUMERIC_STATE_V1";
    static final String HYBRID_STATE_FORMAT = "HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1";
    private final Path root;
    private final ObjectMapper json;

    public UebaExperimentCatalog(@Value("${siem.ueba.experiment-catalog-dir:/run/ueba-catalog}") String directory,
                                  ObjectMapper json) {
        this.root = Path.of(directory).toAbsolutePath().normalize();
        this.json = json;
    }

    public List<SiemDtos.UebaRecipe> recipes() {
        if (!Files.exists(root.resolve("catalog.json"))) return List.of();
        List<SiemDtos.UebaRecipe> result = new ArrayList<>();
        for (JsonNode entry : entries()) result.add(descriptor(entry));
        for (JsonNode entry : strictEntries()) result.add(strictReference(entry).descriptor());
        return List.copyOf(result);
    }

    public StrictReference strictRecipeOrNull(String id) {
        if (id == null || !id.matches("[a-z0-9_-]{8,96}")) throw new BadRequestException("Invalid UEBA recipe ID.");
        for (JsonNode entry : strictEntries()) if (id.equals(entry.path("recipe_id").asText())) return strictReference(entry);
        return null;
    }

    private List<JsonNode> strictEntries() {
        if (!Files.exists(root.resolve("catalog.json"))) return List.of();
        JsonNode values = read(root.resolve("catalog.json"), 1024 * 1024, null).path("strict_entries");
        if (values.isMissingNode()) return List.of();
        if (!values.isArray() || values.size() > 4) throw unavailable();
        List<JsonNode> result = new ArrayList<>(); Set<String> ids = new HashSet<>();
        for (JsonNode entry : values) {
            String id = entry.path("recipe_id").asText();
            if (!id.matches("[a-z0-9_-]{8,96}") || !ids.add(id)) throw unavailable();
            result.add(entry);
        }
        return result;
    }

    private StrictReference strictReference(JsonNode entry) {
        RecipeIdentity identity = recipeIdentity(entry);
        Path directory = datasetDirectory(entry);
        String mode = entry.path("mode").asText("STRICT");
        boolean hybridStrict = HYBRID_MODEL_KIND.equals(identity.modelKind()) && "STRICT".equals(mode);
        JsonNode manifest = hybridStrict
                ? protectedTrainingRead(directory.resolve("manifest.json"), entry.path("manifest_sha256").asText(), 8 * 1024 * 1024)
                : read(directory.resolve("manifest.json"), 8 * 1024 * 1024, entry.path("manifest_sha256").asText());
        if (hybridStrict) {
            JsonNode installed = protectedTrainingRead(root.resolve("catalog.json"), null, 1024 * 1024).path("strict_entries");
            int matches = 0; for (JsonNode registered : installed) if (registered.equals(entry)) matches++;
            if (matches != 1) throw unavailable();
        }
        int fold = entry.path("fold").asInt();
        int schema = manifest.path("feature_schema_version").asInt(-1);
        if (!Set.of("STRICT", "PILOT").contains(mode) || !mode.equals(manifest.path("stage").asText())
                || fold < 1 || fold > 3 || manifest.path("catalog_schema_version").asInt() != 2
                || !Set.of(2, 3, 4).contains(schema) || manifest.path("telemetry_contract_version").asInt() != (schema == 4 ? 3 : 2)
                || !entry.path("dataset_id").asText().equals(manifest.path("dataset_id").asText())
                || !"DEMO_ONLY".equals(manifest.path("data_provenance").asText())) throw unavailable();
        if (Set.of(SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND).contains(identity.modelKind()) && schema != 4) throw unavailable();
        if (identity.recipeSha256() != null) validateRecipeConfig(entry, identity);
        UebaScorePolicy policy;
        try { policy = UebaScorePolicy.fromWire(entry.path("score_policy"), schema); }
        catch (IllegalArgumentException failure) { throw unavailable(); }
        if (!policy.strict()) throw unavailable();
        JsonNode fit = manifest.path("splits").path("fold" + fold + "-fit");
        JsonNode ready = manifest.path("splits").path("fold" + fold + "-calibration-ready");
        JsonNode cold = manifest.path("splits").path("fold" + fold + "-calibration-cold");
        int fitCount = fit.path("records").asInt();
        int readyCount = ready.path("records").asInt(), coldCount = cold.path("records").asInt();
        if (fitCount < 500 || fitCount > 50000 || readyCount < 100 || readyCount > 2000000 || coldCount < 100 || coldCount > 2000000
                || fit.path("positive").asInt(-1) != 0 || ready.path("positive").asInt(-1) != 0 || cold.path("positive").asInt(-1) != 0
                || fit.path("cohorts").path("READY").asInt() != fitCount || ready.path("cohorts").path("READY").asInt() != readyCount
                || cold.path("cohorts").path("COLD").asInt() != coldCount) throw unavailable();
        HybridTrainingReference labeledTraining = null;
        if (HYBRID_MODEL_KIND.equals(identity.modelKind())) {
            labeledTraining = hybridStrict ? hybridStrictTrainingReference(entry, fit, ready, cold) : hybridTrainingReference(entry, fit, ready, cold);
        }
        HybridStrictReference strictProof = null;
        int completed = 0;
        String holdoutSha = null, selectedModelSha = null, selectedCalibrationSha = null;
        String selectedStateSha = null, stateVerifierSha = null;
        if ("STRICT".equals(mode)) {
            String selectionName = switch (identity.modelKind()) {
                case SUPPORT_MODEL_KIND -> "support-selection.json";
                case HYBRID_MODEL_KIND -> "hybrid-selection.json";
                default -> "strict-selection.json";
            };
            JsonNode selection = hybridStrict ? protectedTrainingRead(directory.resolve(selectionName), entry.path("selection_sha256").asText(), 1024 * 1024)
                    : read(directory.resolve(selectionName), 1024 * 1024, entry.path("selection_sha256").asText());
            if (!"SELECTED".equals(selection.path("status").asText()) || selection.path("actual_fits_completed").asInt() != 360
                    || selection.path("validation_runs_completed").asInt() != 360 || selection.path("completed_recalibrations").asInt() < 45
                    || !entry.path("manifest_sha256").asText().equals(selection.path("dataset_sha256").asText())
                    || !policy.sha256().equals(selection.path("policy_sha256").asText()) || fitCount != 50000
                    || readyCount != 1000000 || coldCount != 1000000 || fold != 3
                    || selection.path("additional_fit_calls_in_recalibration").asInt(-1) != 0
                    || !selection.path("model_sha256").asText().equals(entry.path("expected_model_sha256").asText())
                    || !selection.path("calibration_sha256").asText().equals(entry.path("expected_calibration_sha256").asText())
                    || !identity.equals(recipeIdentity(selection))) throw unavailable();
            JsonNode holdout = manifest.path("splits").path("holdout");
            holdoutSha = holdout.path("sha256").asText(); selectedModelSha = selection.path("model_sha256").asText();
            selectedCalibrationSha = selection.path("calibration_sha256").asText();
            selectedStateSha = entry.path("expected_model_state_sha256").asText();
            stateVerifierSha = entry.path("model_state_verifier_sha256").asText();
            if (holdout.path("normal").asInt() != 10000000 || holdout.path("positive").asInt() != 10000
                    || !holdoutSha.matches("[a-f0-9]{64}") || !selectedModelSha.matches("[a-f0-9]{64}")
                    || !selectedCalibrationSha.matches("[a-f0-9]{64}") || !selectedStateSha.matches("[a-f0-9]{64}")
                    || !stateVerifierSha.matches("[a-f0-9]{64}")
                    || !stateFormat(identity.modelKind()).equals(entry.path("model_state_format").asText())) throw unavailable();
            completed = 360;
            if (hybridStrict) {
                if (!integerChoice(manifest, "feature_schema_version", Set.of(4)) || !integerChoice(manifest, "telemetry_contract_version", Set.of(3))
                        || !integerChoice(fit, "records", Set.of(50000)) || !integerChoice(fit, "normal", Set.of(50000)) || !integerChoice(fit, "positive", Set.of(0))
                        || !integerChoice(ready, "records", Set.of(1000000)) || !integerChoice(ready, "normal", Set.of(1000000)) || !integerChoice(ready, "positive", Set.of(0))
                        || !integerChoice(cold, "records", Set.of(1000000)) || !integerChoice(cold, "normal", Set.of(1000000)) || !integerChoice(cold, "positive", Set.of(0))
                        || !integerChoice(holdout, "normal", Set.of(10000000)) || !integerChoice(holdout, "positive", Set.of(10000))
                        || !integerChoice(entry, "fold", Set.of(3)) || !integerChoice(entry.path("config"), "random_state", Set.of(42))
                        || !entry.path("config").equals(selection.path("model_config")) || !entry.path("score_policy").equals(selection.path("policy"))
                        || !selectedStateSha.equals(selection.path("model_state_sha256").asText())
                        || !stateVerifierSha.equals(selection.path("model_state_verifier_sha256").asText())
                        || !HYBRID_STATE_FORMAT.equals(selection.path("model_state_format").asText())
                        || !integerChoice(selection, "actual_fits_completed", Set.of(360))
                        || !integerChoice(selection, "validation_runs_completed", Set.of(360))
                        || !integerChoice(selection, "additional_fit_calls_in_recalibration", Set.of(0))) throw unavailable();
                for (String name : List.of("selection_sha256", "expected_model_sha256", "expected_calibration_sha256", "expected_model_state_sha256", "model_state_verifier_sha256")) {
                    if (!hexHash(entry.path(name))) throw unavailable();
                }
                strictProof = hybridStrictReference(entry, directory, selection, labeledTraining);
            }
        }
        LocalDateTime from = utc(fit.path("from").asText());
        LocalDateTime to = utc(ready.path("to").asText()).isAfter(utc(cold.path("to").asText()))
                ? utc(ready.path("to").asText()).plusMinutes(15) : utc(cold.path("to").asText()).plusMinutes(15);
        return new StrictReference(new SiemDtos.UebaRecipe(entry.path("recipe_id").asText(), entry.path("dataset_id").asText(),
                "DEMO_ONLY", schema, fitCount, readyCount + coldCount, from, to, completed), entry.path("manifest_sha256").asText(), policy.sha256(), mode,
                holdoutSha, selectedModelSha, selectedCalibrationSha, selectedStateSha, stateVerifierSha,
                identity.modelKind(), identity.recipeVersion(), identity.recipeSha256(), stateFormat(identity.modelKind()), labeledTraining, strictProof);
    }

    record RecipeIdentity(String modelKind, int recipeVersion, String recipeSha256) { }

    static RecipeIdentity recipeIdentity(JsonNode value) {
        boolean kind = value.has("model_kind"), revision = value.has("recipe_version"), hash = value.has("recipe_sha256");
        if (!kind && !revision && !hash) return new RecipeIdentity(IF_MODEL_KIND, 1, null);
        if (!kind || !revision || !hash || !value.path("model_kind").isTextual()
                || !Set.of(IF_MODEL_KIND, SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND).contains(value.path("model_kind").asText())
                || !value.path("recipe_version").isIntegralNumber() || !value.path("recipe_version").canConvertToInt()
                || value.path("recipe_version").asInt(-1) != 1
                || !value.path("recipe_sha256").isTextual() || !value.path("recipe_sha256").asText().matches("[a-f0-9]{64}")) throw unavailable();
        return new RecipeIdentity(value.path("model_kind").asText(), 1, value.path("recipe_sha256").asText());
    }

    static String stateFormat(String modelKind) {
        if (modelKind == null) throw unavailable();
        return switch (modelKind) {
            case IF_MODEL_KIND -> IF_STATE_FORMAT;
            case SUPPORT_MODEL_KIND -> SUPPORT_STATE_FORMAT;
            case HYBRID_MODEL_KIND -> HYBRID_STATE_FORMAT;
            default -> throw unavailable();
        };
    }

    private void validateRecipeConfig(JsonNode entry, RecipeIdentity identity) {
        validateRecipeConfig(json, entry.path("config"), identity);
    }

    static void validateRecipeConfig(ObjectMapper json, JsonNode config, RecipeIdentity identity) {
        // Only operator-owned scalar configuration is accepted. It never enters
        // the public train request, which remains recipe-ID-only.
        if (!config.isObject()) throw unavailable();
        if (Set.of(SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND).contains(identity.modelKind())) {
            Set<String> fields = new HashSet<>(); config.fieldNames().forEachRemaining(fields::add);
            if (!config.path("random_state").isIntegralNumber() || !config.path("random_state").canConvertToInt()
                    || !Set.of(11, 23, 42, 73, 101).contains(config.path("random_state").asInt())) throw unavailable();
            var encoded = json.createObjectNode(); var parameters = encoded.putObject("config");
            if (SUPPORT_MODEL_KIND.equals(identity.modelKind())) {
                if (!fields.equals(Set.of("neighbor_count", "reference_count", "metric", "random_state"))
                        || !integerChoice(config, "neighbor_count", Set.of(1, 4, 8))
                        || !integerChoice(config, "reference_count", Set.of(128, 256, 512, 1024))
                        || !config.path("metric").isTextual() || !Set.of("euclidean", "manhattan").contains(config.path("metric").asText())) throw unavailable();
                parameters.put("metric", config.path("metric").asText()); parameters.put("neighbor_count", config.path("neighbor_count").asInt());
                parameters.put("random_state", config.path("random_state").asInt()); parameters.put("reference_count", config.path("reference_count").asInt());
            } else {
                if (!fields.equals(Set.of("max_iter", "max_leaf_nodes", "l2_regularization", "random_state"))
                        || !integerChoice(config, "max_iter", Set.of(100, 200, 400))
                        || !integerChoice(config, "max_leaf_nodes", Set.of(15, 31, 63, 127))
                        || !integerChoice(config, "l2_regularization", Set.of(0, 1))) throw unavailable();
                parameters.put("l2_regularization", config.path("l2_regularization").asInt()); parameters.put("max_iter", config.path("max_iter").asInt());
                parameters.put("max_leaf_nodes", config.path("max_leaf_nodes").asInt()); parameters.put("random_state", config.path("random_state").asInt());
            }
            encoded.put("model_kind", identity.modelKind()); encoded.put("recipe_version", identity.recipeVersion());
            try {
                String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(json.writeValueAsString(encoded).getBytes(StandardCharsets.UTF_8)));
                if (!actual.equals(identity.recipeSha256())) throw unavailable();
            } catch (ServiceUnavailableException failure) { throw failure; }
            catch (Exception failure) { throw unavailable(); }
        }
    }

    private static boolean integerChoice(JsonNode config, String field, Set<Integer> choices) {
        return config.path(field).isIntegralNumber() && config.path(field).canConvertToInt()
                && choices.contains(config.path(field).asInt());
    }

    private HybridTrainingReference hybridStrictTrainingReference(JsonNode entry, JsonNode fit, JsonNode ready, JsonNode cold) {
        String checksum = entry.path("labeled_training_manifest_sha256").asText();
        if (!"labels-fold3".equals(entry.path("labeled_training_artifact_id").asText())
                || !integerChoice(entry, "fold", Set.of(3)) || !hexHash(entry.path("labeled_training_manifest_sha256"))) throw unavailable();
        Path directory = root.resolve("labels-fold3");
        JsonNode training = protectedTrainingRead(directory.resolve("manifest.private.json"), checksum);
        JsonNode source = training.path("source_identity_before");
        if (!"HYBRID_STRICT_LABELED_SOURCE_V1".equals(training.path("format").asText())
                || !"STRICT_SOURCE".equals(training.path("stage").asText()) || !"FULL_STRICT_SOURCE".equals(training.path("scope").asText())
                || !"NOT_EVALUATED".equals(training.path("quality_gate").asText()) || !integerChoice(training, "fold", Set.of(3))
                || !integerChoice(training, "fit_or_score_calls", Set.of(0)) || !integerChoice(training, "holdout_numeric_records_read", Set.of(0))
                || !entry.path("manifest_sha256").equals(training.path("standard_manifest_sha256"))
                || !fit.equals(training.path("standard_fit")) || !source.isObject() || source.isEmpty()
                || !source.equals(training.path("source_identity_after")) || !hexHash(training.path("predeclared_sha256"))) throw unavailable();
        JsonNode declaration = protectedTrainingRead(directory.resolve("predeclared.private.json"), training.path("predeclared_sha256").asText());
        if (!source.equals(declaration.path("source_identity")) || !"FULL_STRICT_SOURCE".equals(declaration.path("scope").asText())
                || !integerChoice(declaration, "fold", Set.of(3)) || !integerChoice(declaration, "new_frames_generated_before_declaration", Set.of(0))
                || !training.path("standard_manifest_sha256").equals(declaration.path("standard_manifest_sha256"))) throw unavailable();
        JsonNode isolation = training.path("isolation_proof");
        for (String name : List.of("calibration_frame_overlap", "calibration_account_hour_overlap", "validation_frame_overlap",
                "validation_account_hour_overlap", "unseen_validation_training_account_overlap")) {
            if (!integerChoice(isolation, name, Set.of(0))) throw unavailable();
        }
        for (String name : List.of("matching_fold_gaps_gt14days", "actual_score_only_splits_scanned")) {
            if (!isolation.path(name).isBoolean() || !isolation.path(name).asBoolean()) throw unavailable();
        }
        if (!isolation.path("numeric_holdout_opened").isBoolean() || isolation.path("numeric_holdout_opened").asBoolean()
                || !fields(training.path("sections")).equals(Set.of("normal", "supplement"))) throw unavailable();
        Set<String> ids = new HashSet<>(), paths = new HashSet<>();
        LocalDateTime calibrationFirst = utc(ready.path("from").asText());
        if (utc(cold.path("from").asText()).isBefore(calibrationFirst)) calibrationFirst = utc(cold.path("from").asText());
        validateStrictTrainingSection(training.path("sections").path("normal"), "normal", ids, paths, calibrationFirst,
                Map.of("normal", 50000), Map.of("READY", 50000));
        validateStrictTrainingSection(training.path("sections").path("supplement"), "supplement", ids, paths, calibrationFirst,
                Map.of("normal", 21500, "request_burst", 2000, "endpoint_scan", 2000, "auth_failure_burst", 2000,
                        "sensitive_action_burst", 2000, "http_error_burst", 2000), Map.of("READY", 7050, "UNSEEN_READY", 16300, "COLD", 8150));
        JsonNode originals = fit.path("shards"), normal = training.path("sections").path("normal").path("shards");
        if (!originals.isArray() || originals.size() != normal.size()) throw unavailable();
        for (int index = 0; index < originals.size(); index++) {
            var copied = originals.get(index).deepCopy();
            if (!copied.isObject()) throw unavailable();
            ((com.fasterxml.jackson.databind.node.ObjectNode) copied).put("path", "normal/" + originals.get(index).path("id").asText() + ".json");
            if (!copied.equals(normal.get(index))) throw unavailable();
        }
        String splitSha = canonicalSha(json, training.path("sections"));
        if (!hexHash(entry.path("normal_fit_split_sha256")) || !entry.path("normal_fit_split_sha256").equals(fit.path("sha256"))
                || !hexHash(entry.path("labeled_training_split_sha256")) || !splitSha.equals(entry.path("labeled_training_split_sha256").asText())
                || !integerChoice(entry, "labeled_training_windows", Set.of(81500))
                || !json.valueToTree(Map.of("0", 71500, "1", 8000, "2", 2000)).equals(entry.path("labeled_class_windows"))) throw unavailable();
        return new HybridTrainingReference("labels-fold3", checksum, 81500, Map.of("0", 71500, "1", 8000, "2", 2000), fit.path("sha256").asText(), splitSha);
    }

    private void validateStrictTrainingSection(JsonNode section, String role, Set<String> ids, Set<String> paths,
            LocalDateTime calibrationFirst, Map<String, Integer> expectedFamilies, Map<String, Integer> expectedCohorts) {
        JsonNode shards = section.path("shards");
        if (!fields(section).equals(Set.of("shards")) || !shards.isArray() || shards.isEmpty() || shards.size() > 1000) throw unavailable();
        Map<String, Integer> families = new HashMap<>(), cohorts = new HashMap<>();
        int records = 0;
        for (JsonNode shard : shards) {
            if (!fields(shard).equals(Set.of("id", "path", "sha256", "records", "normal", "positive", "families", "cohorts", "from", "to"))
                    || !shard.path("id").isTextual() || !shard.path("id").asText().matches("[a-z0-9_-]{8,128}")
                    || !shard.path("path").isTextual() || !shard.path("path").asText().equals(role + "/" + shard.path("id").asText() + ".json")
                    || !ids.add(shard.path("id").asText()) || !paths.add(shard.path("path").asText()) || !hexHash(shard.path("sha256"))) throw unavailable();
            for (String name : List.of("records", "normal", "positive")) {
                JsonNode value = shard.path(name);
                if (!value.isIntegralNumber() || !value.canConvertToInt() || value.asInt() < 0 || value.asInt() > 5000) throw unavailable();
            }
            int count = shard.path("records").asInt();
            if (count < 1 || count != shard.path("normal").asInt() + shard.path("positive").asInt()
                    || shard.path("families").path("normal").asInt() != shard.path("normal").asInt()) throw unavailable();
            mergePopulation(shard.path("families"), expectedFamilies.keySet(), count, families);
            mergePopulation(shard.path("cohorts"), expectedCohorts.keySet(), count, cohorts);
            LocalDateTime first = utc(shard.path("from").asText()), last = utc(shard.path("to").asText());
            if (last.isBefore(first) || !calibrationFirst.isAfter(last.plusDays(14))) throw unavailable();
            records += count;
        }
        if (records != expectedFamilies.values().stream().mapToInt(Integer::intValue).sum()
                || !families.equals(expectedFamilies) || !cohorts.equals(expectedCohorts)) throw unavailable();
    }

    private HybridStrictReference hybridStrictReference(JsonNode entry, Path directory, JsonNode selection, HybridTrainingReference labeled) {
        if (!hexHash(entry.path("strict_proof_sha256"))) throw unavailable();
        JsonNode proof = protectedTrainingRead(directory.resolve("hybrid-strict-proof.json"), entry.path("strict_proof_sha256").asText(), 4 * 1024 * 1024);
        if (!fields(proof).equals(Set.of("format", "dataset_sha256", "selection_sha256", "model_sha256", "calibration_sha256",
                "model_state_sha256", "files", "source_label_manifests", "archive_model_sha256"))
                || !"HYBRID_STRICT_PROOF_V1".equals(proof.path("format").asText())
                || !entry.path("manifest_sha256").equals(proof.path("dataset_sha256"))
                || !entry.path("selection_sha256").equals(proof.path("selection_sha256"))
                || !entry.path("expected_model_sha256").equals(proof.path("model_sha256"))
                || !entry.path("expected_calibration_sha256").equals(proof.path("calibration_sha256"))
                || !entry.path("expected_model_state_sha256").equals(proof.path("model_state_sha256"))) throw unavailable();
        JsonNode files = proof.path("files");
        if (!files.isObject() || files.size() < 769 || files.size() > 1084
                || !entry.path("selection_sha256").equals(files.path("hybrid-selection.json"))) throw unavailable();
        Map<String, Integer> roles = new HashMap<>();
        for (var iterator = files.fields(); iterator.hasNext();) {
            var file = iterator.next(); String name = file.getKey();
            if (!name.matches("(?:hybrid-(?:selection|campaign\\.progress)\\.json|hybrid-(?:runs|validations|top-recalibrations)/[a-z0-9_-]{8,128}\\.json|hybrid-models/[a-z0-9_-]{8,96}\\.(?:json|joblib))")
                    || !hexHash(file.getValue())) throw unavailable();
            roles.merge(name.contains("/") ? name.substring(0, name.indexOf('/')) : name, 1, Integer::sum);
        }
        JsonNode recalibrations = selection.path("completed_recalibrations");
        if (!recalibrations.isIntegralNumber() || !recalibrations.canConvertToInt() || recalibrations.asInt() < 45 || recalibrations.asInt() > 360
                || !roles.equals(Map.of("hybrid-selection.json", 1, "hybrid-campaign.progress.json", 1, "hybrid-models", 2,
                        "hybrid-runs", 360, "hybrid-validations", 360, "hybrid-top-recalibrations", recalibrations.asInt()))) throw unavailable();
        JsonNode archive = proof.path("archive_model_sha256");
        if (!archive.isObject() || archive.size() != 360) throw unavailable();
        for (var iterator = archive.fields(); iterator.hasNext();) {
            var run = iterator.next(); JsonNode hashes = run.getValue();
            if (!run.getKey().matches("[a-z0-9_-]{8,128}") || !fields(hashes).equals(Set.of("source_model_sha256", "model_sha256"))
                    || !hexHash(hashes.path("source_model_sha256")) || !hexHash(hashes.path("model_sha256"))) throw unavailable();
        }
        JsonNode labels = proof.path("source_label_manifests");
        if (!fields(labels).equals(Set.of("1", "2", "3"))) throw unavailable();
        Map<String, String> sources = new HashMap<>();
        for (String fold : List.of("1", "2", "3")) {
            JsonNode source = labels.path(fold);
            if (!fields(source).equals(Set.of("artifact_id", "manifest_sha256")) || !("labels-fold" + fold).equals(source.path("artifact_id").asText())
                    || !hexHash(source.path("manifest_sha256"))) throw unavailable();
            sources.put(fold, source.path("manifest_sha256").asText());
        }
        if (!labeled.manifestSha256().equals(sources.get("3"))) throw unavailable();
        return new HybridStrictReference(entry.path("strict_proof_sha256").asText(), entry.path("selection_sha256").asText(), Map.copyOf(sources), recalibrations.asInt());
    }

    static boolean matchesHybridStrictProof(JsonNode summary, StrictReference recipe) {
        HybridStrictReference expected = recipe.strictProof();
        if (expected == null || !summary.isObject() || !fields(summary).equals(Set.of("format", "proof_sha256", "selection_sha256", "actual_composite_trials",
                "actual_component_fit_calls", "validation_runs", "zero_fit_recalibrations", "source_label_manifests"))
                || !"HYBRID_STRICT_PROOF_V1".equals(summary.path("format").asText()) || !hexHash(summary.path("proof_sha256")) || !hexHash(summary.path("selection_sha256"))
                || !expected.proofSha256().equals(summary.path("proof_sha256").asText())
                || !expected.selectionSha256().equals(summary.path("selection_sha256").asText())
                || !integerChoice(summary, "actual_composite_trials", Set.of(360)) || !integerChoice(summary, "actual_component_fit_calls", Set.of(720))
                || !integerChoice(summary, "validation_runs", Set.of(360)) || !integerChoice(summary, "zero_fit_recalibrations", Set.of(expected.recalibrations()))) return false;
        JsonNode labels = summary.path("source_label_manifests");
        if (!labels.isObject() || !fields(labels).equals(Set.of("1", "2", "3"))) return false;
        for (var fold : expected.sourceManifestSha256ByFold().entrySet()) {
            JsonNode source = labels.path(fold.getKey());
            if (!source.isObject() || !fields(source).equals(Set.of("artifact_id", "manifest_sha256"))
                    || !("labels-fold" + fold.getKey()).equals(source.path("artifact_id").asText()) || !hexHash(source.path("manifest_sha256"))
                    || !fold.getValue().equals(source.path("manifest_sha256").asText())) return false;
        }
        return true;
    }

    private static boolean hexHash(JsonNode value) { return value.isTextual() && value.asText().matches("[a-f0-9]{64}"); }

    private static String canonicalSha(ObjectMapper json, JsonNode value) {
        try {
            byte[] bytes = json.writer().with(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                    .writeValueAsBytes(json.convertValue(value, Object.class));
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception failure) { throw unavailable(); }
    }

    private HybridTrainingReference hybridTrainingReference(JsonNode entry, JsonNode fit, JsonNode ready, JsonNode cold) {
        String artifactId = entry.path("labeled_training_artifact_id").asText();
        String checksum = entry.path("labeled_training_manifest_sha256").asText();
        if (!entry.path("labeled_training_artifact_id").isTextual() || !artifactId.matches("[a-z0-9_-]{8,32}")
                || !entry.path("labeled_training_manifest_sha256").isTextual() || !checksum.matches("[a-f0-9]{64}")
                || !HYBRID_STATE_FORMAT.equals(entry.path("model_state_format").asText())) throw unavailable();
        Path directory = root.resolve(artifactId).normalize();
        if (!directory.getParent().equals(root) || Files.isSymbolicLink(root) || Files.isSymbolicLink(directory)) throw unavailable();
        JsonNode training = protectedTrainingRead(directory.resolve("manifest.private.json"), checksum);
        JsonNode source = training.path("source_identity_before");
        if (!integerChoice(training, "hybrid_bulk_training_schema_version", Set.of(1))
                || !integerChoice(training, "feature_schema_version", Set.of(4))
                || !integerChoice(training, "telemetry_contract_version", Set.of(3))
                || !integerChoice(training, "fit_or_score_calls", Set.of(0))
                || !integerChoice(training, "holdout_numeric_records_read", Set.of(0))
                || !training.path("artifact_id").isTextual() || !training.path("dataset_id").isTextual()
                || !artifactId.equals(training.path("artifact_id").asText()) || !artifactId.equals(training.path("dataset_id").asText())
                || !"BULK_PILOT".equals(training.path("stage").asText()) || !"DEMO_ONLY".equals(training.path("data_provenance").asText())
                || !"NOT_APPLICABLE".equals(training.path("quality_gate").asText())
                || !json.valueToTree(AccountBehaviorFeatures.names(4)).equals(training.path("feature_names"))
                || !training.path("confirmed_attack_target_available").isBoolean() || training.path("confirmed_attack_target_available").asBoolean()
                || !source.isObject() || source.isEmpty() || !source.equals(training.path("source_identity_after"))) throw unavailable();
        if (!json.valueToTree(Map.of("normal", 0, "request_burst", 1, "endpoint_scan", 1,
                "auth_failure_burst", 1, "sensitive_action_burst", 1, "http_error_burst", 2)).equals(training.path("class_targets"))
                || !json.valueToTree(Map.of("0", "NORMAL", "1", "SIMULATED_SECURITY_BEHAVIOR_CONTEXT",
                "2", "SIMULATED_OPERATIONAL_FAILURE_CONTEXT")).equals(training.path("class_target_names"))) throw unavailable();
        if (!training.path("predeclared_identity_sha256").isTextual()) throw unavailable();
        JsonNode declaration = protectedTrainingRead(directory.resolve("predeclared.private.json"), training.path("predeclared_identity_sha256").asText());
        if (!source.equals(declaration.path("source_identity")) || !integerChoice(declaration, "new_frames_generated_before_declaration", Set.of(0))) throw unavailable();
        JsonNode proof = training.path("isolation_proofs");
        for (String field : List.of("unseen_validation_accounts_disjoint", "all_training_before_calibration_by_more_than14days")) {
            if (!proof.path(field).isBoolean() || !proof.path(field).asBoolean()) throw unavailable();
        }
        for (String field : List.of("calibration_frame_overlap", "calibration_account_hour_overlap", "validation_frame_overlap", "validation_account_hour_overlap")) {
            if (!integerChoice(proof, field, Set.of(0))) throw unavailable();
        }
        JsonNode sections = training.path("training_sections");
        Set<String> sectionNames = new HashSet<>(); sections.fieldNames().forEachRemaining(sectionNames::add);
        if (!sections.isObject() || !sectionNames.equals(Set.of("NORMAL_COMPONENT", "SUPPLEMENT"))) throw unavailable();
        JsonNode normal = sections.path("NORMAL_COMPONENT"), supplement = sections.path("SUPPLEMENT");
        // Full split equality binds actual normal shard IDs, paths, hashes and
        // temporal/statistical descriptors. Never inflate an old 2k FIT source.
        if (!normal.equals(fit) || !integerChoice(normal, "records", Set.of(50000))
                || !integerChoice(normal, "normal", Set.of(50000)) || !integerChoice(normal, "positive", Set.of(0))
                || !json.valueToTree(Map.of("normal", 50000)).equals(normal.path("families"))
                || !json.valueToTree(Map.of("READY", 50000)).equals(normal.path("cohorts"))
                || !integerChoice(supplement, "records", Set.of(31500)) || !integerChoice(supplement, "normal", Set.of(21500))
                || !integerChoice(supplement, "positive", Set.of(10000))
                || !json.valueToTree(Map.of("normal", 21500, "request_burst", 2000, "endpoint_scan", 2000,
                "auth_failure_burst", 2000, "sensitive_action_burst", 2000, "http_error_burst", 2000)).equals(supplement.path("families"))
                || !json.valueToTree(Map.of("READY", 7050, "UNSEEN_READY", 16300, "COLD", 8150)).equals(supplement.path("cohorts"))) throw unavailable();
        Set<String> shardIds = new HashSet<>(), shardPaths = new HashSet<>();
        validateHybridSection(normal, shardIds, shardPaths);
        validateHybridSection(supplement, shardIds, shardPaths);
        LocalDateTime trainingLast = utc(normal.path("to").asText());
        if (utc(supplement.path("to").asText()).isAfter(trainingLast)) trainingLast = utc(supplement.path("to").asText());
        if (!utc(ready.path("from").asText()).isAfter(trainingLast.plusDays(14))
                || !utc(cold.path("from").asText()).isAfter(trainingLast.plusDays(14))) throw unavailable();
        return new HybridTrainingReference(artifactId, checksum, 81500, Map.of("0", 71500, "1", 8000, "2", 2000));
    }

    private void validateHybridSection(JsonNode section, Set<String> ids, Set<String> paths) {
        if (!fields(section).equals(Set.of("records", "normal", "positive", "families", "cohorts", "from", "to", "shards", "sha256"))) throw unavailable();
        JsonNode shards = section.path("shards");
        if (!section.path("sha256").isTextual() || !section.path("sha256").asText().matches("[a-f0-9]{64}") || !shards.isArray() || shards.isEmpty() || shards.size() > 700) throw unavailable();
        int records = 0, normals = 0, positives = 0;
        Map<String, Integer> families = new HashMap<>(), cohorts = new HashMap<>();
        LocalDateTime first = null, last = null;
        for (JsonNode shard : shards) {
            if (!fields(shard).equals(Set.of("id", "path", "sha256", "records", "normal", "positive", "families", "cohorts", "from", "to"))) throw unavailable();
            String id = shard.path("id").asText(), path = shard.path("path").asText();
            if (!shard.path("id").isTextual() || !shard.path("path").isTextual()
                    || !path.matches("shards/bulk-(?:normal-ready|supplement)-(?:ready|unseen|cold|normal)-b[0-9]{6}-[0-9]{3}\\.json")
                    || !path.equals("shards/" + id + ".json") || !ids.add(id) || !paths.add(path)
                    || !shard.path("sha256").isTextual() || !shard.path("sha256").asText().matches("[a-f0-9]{64}")) throw unavailable();
            for (String field : List.of("records", "normal", "positive")) {
                JsonNode value = shard.path(field);
                if (!value.isIntegralNumber() || !value.canConvertToInt() || value.asInt() < 0 || value.asInt() > 5000) throw unavailable();
            }
            int count = shard.path("records").asInt();
            if (count < 1 || count != shard.path("normal").asInt() + shard.path("positive").asInt()
                    || shard.path("families").path("normal").asInt() != shard.path("normal").asInt()) throw unavailable();
            mergePopulation(shard.path("families"), Set.of("normal", "request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst"), count, families);
            mergePopulation(shard.path("cohorts"), Set.of("READY", "UNSEEN_READY", "COLD"), count, cohorts);
            LocalDateTime from = utc(shard.path("from").asText()), to = utc(shard.path("to").asText());
            if (to.isBefore(from)) throw unavailable();
            if (first == null || from.isBefore(first)) first = from;
            if (last == null || to.isAfter(last)) last = to;
            records += count; normals += shard.path("normal").asInt(); positives += shard.path("positive").asInt();
        }
        if (records != section.path("records").asInt() || normals != section.path("normal").asInt() || positives != section.path("positive").asInt()
                || !json.valueToTree(families).equals(section.path("families")) || !json.valueToTree(cohorts).equals(section.path("cohorts"))
                || !utc(section.path("from").asText()).equals(first) || !utc(section.path("to").asText()).equals(last)) throw unavailable();
    }

    private static Set<String> fields(JsonNode value) {
        if (!value.isObject()) throw unavailable();
        Set<String> result = new HashSet<>(); value.fieldNames().forEachRemaining(result::add); return result;
    }

    private static void mergePopulation(JsonNode population, Set<String> allowed, int expected, Map<String, Integer> merged) {
        if (!population.isObject() || !allowed.containsAll(fields(population))) throw unavailable();
        int sum = 0;
        for (var iterator = population.fields(); iterator.hasNext();) {
            var item = iterator.next(); JsonNode value = item.getValue();
            if (!value.isIntegralNumber() || !value.canConvertToInt() || value.asInt() < 1 || value.asInt() > expected) throw unavailable();
            sum += value.asInt(); merged.merge(item.getKey(), value.asInt(), Integer::sum);
        }
        if (sum != expected) throw unavailable();
    }

    private JsonNode protectedTrainingRead(Path path, String checksum) {
        return protectedTrainingRead(path, checksum, 2 * 1024 * 1024);
    }

    private JsonNode protectedTrainingRead(Path path, String checksum, int maximum) {
        try {
            if (!path.startsWith(root) || checksum != null && !checksum.matches("[a-f0-9]{64}")) throw unavailable();
            for (Path parent = path; parent != null; parent = parent.getParent()) if (Files.isSymbolicLink(parent)) throw unavailable();
            var owner = Files.getOwner(root, LinkOption.NOFOLLOW_LINKS);
            for (Path directory = path.getParent(); directory != null && directory.startsWith(root); directory = directory.getParent()) {
                if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                        || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rwx------"))
                        || !owner.equals(Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS))) throw unavailable();
            }
            BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!before.isRegularFile() || before.size() < 1 || before.size() > maximum
                    || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rw-------"))
                    || !owner.equals(Files.getOwner(path, LinkOption.NOFOLLOW_LINKS))) throw unavailable();
            byte[] bytes;
            try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { bytes = stream.readNBytes(maximum + 1); }
            BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!after.isRegularFile() || bytes.length != before.size() || !java.util.Objects.equals(before.fileKey(), after.fileKey())
                    || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(PosixFilePermissions.fromString("rw-------"))
                    || !owner.equals(Files.getOwner(path, LinkOption.NOFOLLOW_LINKS))
                    || checksum != null && !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(checksum)) throw unavailable();
            return json.readTree(bytes);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw unavailable(); }
    }

    public Dataset recipe(String id) {
        JsonNode entry = find("recipe_id", id);
        return load(entry, true);
    }

    public Dataset evaluation(String id) {
        JsonNode entry = find("dataset_id", id);
        return load(entry, false);
    }

    private JsonNode find(String field, String id) {
        if (id == null || !id.matches("[a-z0-9_-]{8,96}")) throw new BadRequestException("Invalid UEBA dataset/recipe ID.");
        for (JsonNode entry : entries()) if (id.equals(entry.path(field).asText())) return entry;
        throw new BadRequestException("UEBA dataset/recipe is not registered by the operator.");
    }

    private List<JsonNode> entries() {
        JsonNode entries = read(root.resolve("catalog.json"), 1024 * 1024, null).path("entries");
        if (!entries.isArray() || entries.size() > 4) throw unavailable();
        List<JsonNode> result = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        for (JsonNode entry : entries) {
            String recipe = entry.path("recipe_id").asText();
            String dataset = entry.path("dataset_id").asText();
            if (!recipe.matches("[a-z0-9_-]{8,96}") || !dataset.matches("[a-z0-9_-]{8,64}")
                    || !identities.add(recipe)) throw unavailable();
            result.add(entry);
        }
        return result;
    }

    private SiemDtos.UebaRecipe descriptor(JsonNode entry) {
        JsonNode manifest = manifest(entry);
        JsonNode selection = read(datasetDirectory(entry).resolve("selection.json"), 1024 * 1024,
                entry.path("selection_sha256").asText());
        if (!"SELECTED".equals(selection.path("status").asText()) || selection.path("completed_fits").asInt() != 360
                || !entry.path("manifest_sha256").asText().equals(selection.path("dataset_manifest_sha256").asText())) throw unavailable();
        return new SiemDtos.UebaRecipe(entry.path("recipe_id").asText(), entry.path("dataset_id").asText(),
                "DEMO_ONLY", 2, manifest.path("splits").path("fold3-fit").path("windows").asInt(),
                manifest.path("splits").path("fold3-calibration").path("windows").asInt(),
                utc(manifest.path("splits").path("fold3-fit").path("from").asText()),
                utc(manifest.path("splits").path("fold3-calibration").path("to").asText()).plusMinutes(15), 360);
    }

    private JsonNode manifest(JsonNode entry) {
        JsonNode manifest = read(datasetDirectory(entry).resolve("manifest.json"), 1024 * 1024,
                entry.path("manifest_sha256").asText());
        if (!entry.path("dataset_id").asText().equals(manifest.path("dataset_id").asText())
                || !"DEMO_ONLY".equals(manifest.path("data_provenance").asText())
                || manifest.path("feature_schema_version").asInt() != 2) throw unavailable();
        return manifest;
    }

    private Dataset load(JsonNode entry, boolean includeTraining) {
        SiemDtos.UebaRecipe descriptor = descriptor(entry);
        JsonNode manifest = manifest(entry);
        JsonNode selection = read(datasetDirectory(entry).resolve("selection.json"), 1024 * 1024,
                entry.path("selection_sha256").asText());
        JsonNode config = selection.path("selected").path("candidate").path("config");
        int trees = config.path("n_estimators").asInt(), samples = config.path("max_samples").asInt();
        double features = config.path("max_features").asDouble();
        if (!Set.of(200, 400, 600).contains(trees) || !Set.of(128, 256, 512, 1024).contains(samples)
                || !Set.of(0.75, 1.0).contains(features) || config.path("random_state").asInt() != 42
                || selection.path("selected").path("candidate").path("fold").asInt() != 3) throw unavailable();
        List<Row> fit = includeTraining ? rows(entry, manifest, "fold3-fit", 10000, 50000, true) : List.of();
        List<Row> calibration = includeTraining ? rows(entry, manifest, "fold3-calibration", 2000, 10000, true) : List.of();
        List<Row> holdout = rows(entry, manifest, "holdout", 11000, 20000, false);
        String payloadV1 = entry.path("holdout_payload_sha256_v1").asText();
        String payloadV2 = entry.path("holdout_payload_sha256_v2").asText();
        if (!payloadV1.matches("[a-f0-9]{64}") || !payloadV2.matches("[a-f0-9]{64}")) throw unavailable();
        Set<String> holdoutIds = new HashSet<>();
        holdout.forEach(row -> holdoutIds.add(row.id()));
        if (fit.stream().anyMatch(row -> holdoutIds.contains(row.id()))
                || calibration.stream().anyMatch(row -> holdoutIds.contains(row.id()))) throw unavailable();
        if (includeTraining) {
            Set<String> fitIds = new HashSet<>(); fit.forEach(row -> fitIds.add(row.id()));
            if (calibration.stream().anyMatch(row -> fitIds.contains(row.id()))) throw unavailable();
            LocalDateTime fitLast = fit.stream().map(Row::start).max(LocalDateTime::compareTo).orElseThrow();
            LocalDateTime calFirst = calibration.stream().map(Row::start).min(LocalDateTime::compareTo).orElseThrow();
            LocalDateTime calLast = calibration.stream().map(Row::start).max(LocalDateTime::compareTo).orElseThrow();
            LocalDateTime holdoutFirst = holdout.stream().map(Row::start).min(LocalDateTime::compareTo).orElseThrow();
            if (calFirst.isBefore(fitLast.plusMinutes(30)) || holdoutFirst.isBefore(calLast.plusMinutes(30))) throw unavailable();
        }
        return new Dataset(descriptor, entry.path("manifest_sha256").asText(),
                manifest.path("splits").path("holdout").path("sha256").asText(), fit, calibration, holdout,
                Map.of("n_estimators", trees, "max_samples", samples, "max_features", features, "random_state", 42), payloadV1, payloadV2);
    }

    private List<Row> rows(JsonNode entry, JsonNode manifest, String name, int minimum, int maximum, boolean normalOnly) {
        JsonNode split = manifest.path("splits").path(name);
        if (!(name + ".json").equals(split.path("path").asText())) throw unavailable();
        JsonNode payload = read(datasetDirectory(entry).resolve(name + ".json"), 64 * 1024 * 1024, split.path("sha256").asText());
        JsonNode records = payload.path("records");
        if (!"DEMO_ONLY".equals(payload.path("data_provenance").asText()) || payload.path("feature_schema_version").asInt() != 2
                || !name.equals(payload.path("split_name").asText()) || !records.isArray()
                || records.size() < minimum || records.size() > maximum || records.size() != split.path("windows").asInt()) throw unavailable();
        List<Row> result = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        Set<String> windows = new HashSet<>();
        for (JsonNode row : records) {
            String id = row.path("frame_id").asText(), account = row.path("account_id").asText();
            if (!id.matches("[a-z0-9_-]{8,128}") || !account.matches("[a-z0-9_-]{8,64}") || !ids.add(id)
                    || !row.path("baseline_established").isBoolean() || !row.path("baseline_established").asBoolean()
                    || !row.path("label").isIntegralNumber() || !Set.of(0, 1).contains(row.path("label").asInt())) throw unavailable();
            int label = row.path("label").asInt();
            String family = row.path("family").asText();
            if (normalOnly && (label != 0 || !"normal".equals(family))) throw unavailable();
            if (!normalOnly && !(label == 0 && "normal".equals(family) || label == 1 && Set.of("request_burst", "endpoint_scan",
                    "auth_failure_burst", "sensitive_action_burst", "http_error_burst").contains(family))) throw unavailable();
            List<Double> vector = new ArrayList<>();
            if (!row.path("features").isArray()) throw unavailable();
            for (JsonNode value : row.path("features")) {
                if (!value.isNumber() || !Double.isFinite(value.asDouble()) || Math.abs(value.asDouble()) > 1_000_000) throw unavailable();
                vector.add(value.asDouble());
            }
            try { new AccountBehaviorFeatures.Vector(2, vector); }
            catch (IllegalArgumentException failure) { throw unavailable(); }
            LocalDateTime at = utc(row.path("window_start").asText());
            if (at.getMinute() % 15 != 0 || at.getSecond() != 0 || at.getNano() != 0 || !windows.add(account + "/" + at)) throw unavailable();
            result.add(new Row(id, account, at, List.copyOf(vector), label, family));
        }
        return List.copyOf(result);
    }

    private Path datasetDirectory(JsonNode entry) {
        String directory = entry.path("dataset_id").asText();
        if (!directory.matches("[a-z0-9_-]{8,64}")) throw unavailable();
        Path resolved = root.resolve(directory).normalize();
        if (!resolved.getParent().equals(root) || Files.isSymbolicLink(resolved) || Files.isSymbolicLink(root)) throw unavailable();
        return resolved;
    }

    private JsonNode read(Path path, long maximum, String checksum) {
        try {
            if (!Files.isRegularFile(path) || Files.isSymbolicLink(path) || Files.size(path) > maximum) throw unavailable();
            byte[] bytes = Files.readAllBytes(path);
            if (checksum != null && (!checksum.matches("[a-f0-9]{64}")
                    || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(checksum))) throw unavailable();
            return json.readTree(bytes);
        } catch (ServiceUnavailableException failure) { throw failure; }
        catch (Exception failure) { throw unavailable(); }
    }

    private static LocalDateTime utc(String value) {
        try { return LocalDateTime.ofInstant(Instant.parse(value), ZoneOffset.UTC); }
        catch (Exception failure) { throw unavailable(); }
    }
    private static ServiceUnavailableException unavailable() {
        return new ServiceUnavailableException("UEBA operator catalogue is unavailable or failed integrity validation.");
    }

    public record Row(String id, String accountId, LocalDateTime start, List<Double> features, int label, String family) { }
    public record HybridTrainingReference(String artifactId, String manifestSha256, int labeledWindows, Map<String, Integer> classWindows,
                                           String normalFitSplitSha256, String labeledTrainingSplitSha256) {
        public HybridTrainingReference(String artifactId, String manifestSha256, int labeledWindows, Map<String, Integer> classWindows) {
            this(artifactId, manifestSha256, labeledWindows, classWindows, null, null);
        }
    }
    public record HybridStrictReference(String proofSha256, String selectionSha256, Map<String, String> sourceManifestSha256ByFold, int recalibrations) { }
    public record StrictReference(SiemDtos.UebaRecipe descriptor, String manifestSha256, String policySha256, String mode,
                                   String holdoutSplitSha256, String expectedModelSha256, String expectedCalibrationSha256,
                                   String expectedModelStateSha256, String modelStateVerifierSha256,
                                   String modelKind, int recipeVersion, String recipeSha256, String modelStateFormat, HybridTrainingReference labeledTraining,
                                   HybridStrictReference strictProof) {
        public StrictReference(SiemDtos.UebaRecipe descriptor, String manifestSha256, String policySha256, String mode,
                               String holdoutSplitSha256, String expectedModelSha256, String expectedCalibrationSha256,
                               String expectedModelStateSha256, String modelStateVerifierSha256,
                               String modelKind, int recipeVersion, String recipeSha256, String modelStateFormat, HybridTrainingReference labeledTraining) {
            this(descriptor, manifestSha256, policySha256, mode, holdoutSplitSha256, expectedModelSha256, expectedCalibrationSha256,
                    expectedModelStateSha256, modelStateVerifierSha256, modelKind, recipeVersion, recipeSha256, modelStateFormat, labeledTraining, null);
        }
        public StrictReference(SiemDtos.UebaRecipe descriptor, String manifestSha256, String policySha256, String mode,
                               String holdoutSplitSha256, String expectedModelSha256, String expectedCalibrationSha256,
                               String expectedModelStateSha256, String modelStateVerifierSha256,
                               String modelKind, int recipeVersion, String recipeSha256, String modelStateFormat) {
            this(descriptor, manifestSha256, policySha256, mode, holdoutSplitSha256, expectedModelSha256, expectedCalibrationSha256,
                    expectedModelStateSha256, modelStateVerifierSha256, modelKind, recipeVersion, recipeSha256, modelStateFormat, null);
        }
        public StrictReference(SiemDtos.UebaRecipe descriptor, String manifestSha256, String policySha256, String mode,
                               String holdoutSplitSha256, String expectedModelSha256, String expectedCalibrationSha256,
                               String expectedModelStateSha256, String modelStateVerifierSha256) {
            this(descriptor, manifestSha256, policySha256, mode, holdoutSplitSha256, expectedModelSha256,
                    expectedCalibrationSha256, expectedModelStateSha256, modelStateVerifierSha256,
                    IF_MODEL_KIND, 1, null, IF_STATE_FORMAT);
        }
        public StrictReference(SiemDtos.UebaRecipe descriptor, String manifestSha256, String policySha256, String mode,
                               String holdoutSplitSha256, String expectedModelSha256, String expectedCalibrationSha256) {
            this(descriptor, manifestSha256, policySha256, mode, holdoutSplitSha256, expectedModelSha256,
                    expectedCalibrationSha256, null, null);
        }
    }
    public record Dataset(SiemDtos.UebaRecipe descriptor, String manifestSha256, String holdoutSplitSha256,
                           List<Row> fit, List<Row> calibration, List<Row> holdout, Map<String, Object> config,
                           String payloadSha256V1, String payloadSha256V2) {
        public String payloadSha256(int schema) {
            if (schema == 1) return payloadSha256V1;
            if (schema == 2) return payloadSha256V2;
            throw new BadRequestException("Unsupported model evaluation schema.");
        }
    }
}
