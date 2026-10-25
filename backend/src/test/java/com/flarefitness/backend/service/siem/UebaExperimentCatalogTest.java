package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UebaExperimentCatalogTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir Path root;

    @Test void registersOnlyCompletedRecipesAndLoadsPrivateFrozenRows() throws Exception {
        fixture();
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        assertThat(catalog.recipes()).hasSize(1);
        var data = catalog.recipe("fixture-dataset-champion");
        assertThat(data.fit()).hasSize(10000);
        assertThat(data.calibration()).hasSize(2000);
        assertThat(data.holdout()).hasSize(11000);
        assertThat(data.config().get("random_state")).isEqualTo(42);
        assertThat(data.payloadSha256(2)).hasSize(64);
    }

    @Test void checksumCorruptionCannotBecomeAUsableTrainingRecipe() throws Exception {
        fixture();
        Path split = root.resolve("fixture-dataset/holdout.json");
        Files.writeString(split, Files.readString(split) + "\n");
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipe("fixture-dataset-champion"))
                .isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void clientsCannotSupplyDatasetPathsOrPrivateFiles() throws Exception {
        fixture();
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        assertThatThrownBy(() -> catalog.recipe("../private-file")).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> catalog.recipe("unknown-recipe")).isInstanceOf(BadRequestException.class);
        ObjectNode registered = (ObjectNode) JSON.readTree(root.resolve("catalog.json").toFile());
        ((ObjectNode) registered.path("entries").get(0)).put("dataset_id", "../escape");
        JSON.writeValue(root.resolve("catalog.json").toFile(), registered);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void shardedRecipesExposeScalarDescriptorsWithoutLoadingLargeVectors() throws Exception {
        shardedFixture();
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        assertThat(catalog.recipes()).hasSize(1);
        var recipe = catalog.strictRecipeOrNull("fixture-sharded-preview");
        assertThat(recipe).isNotNull();
        assertThat(recipe.descriptor().trainingWindows()).isEqualTo(600);
        assertThat(recipe.descriptor().calibrationWindows()).isEqualTo(600);
        assertThat(recipe.descriptor().completedSearchFits()).isZero();
        assertThat(recipe.mode()).isEqualTo("PILOT");
        assertThat(recipe.policySha256()).hasSize(64);
        assertThat(catalog.strictRecipeOrNull("unregistered-recipe")).isNull();
    }

    @Test void previewScopeCannotBeRelabelledAsFullStrictSelection() throws Exception {
        shardedFixture();
        Path registry = root.resolve("catalog.json");
        ObjectNode document = (ObjectNode) JSON.readTree(registry.toFile());
        ((ObjectNode) document.path("strict_entries").get(0)).put("mode", "STRICT");
        JSON.writeValue(registry.toFile(), document);
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes())
                .isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void contextualRecipeBindsPolicyAndDescriptorToItsActualSchema() throws Exception {
        shardedFixture();
        Path file = root.resolve("fixture-sharded-data/manifest.json");
        ObjectNode manifest = (ObjectNode) JSON.readTree(file.toFile());
        manifest.put("feature_schema_version", 3); JSON.writeValue(file.toFile(), manifest);
        Path registry = root.resolve("catalog.json"); ObjectNode document = (ObjectNode) JSON.readTree(registry.toFile());
        ObjectNode entry = (ObjectNode) document.path("strict_entries").get(0);
        entry.put("manifest_sha256", digest(file)); JSON.writeValue(registry.toFile(), document);
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        entry.set("score_policy", UebaTestPolicies.contextual(JSON)); JSON.writeValue(registry.toFile(), document);
        var reference = catalog.strictRecipeOrNull("fixture-sharded-preview");
        assertThat(reference.descriptor().featureSchemaVersion()).isEqualTo(3);
        assertThat(reference.mode()).isEqualTo("PILOT");
        assertThat(reference.descriptor().completedSearchFits()).isZero();
    }

    @Test void supportPreviewHasExplicitTypedIdentityWhileLegacyRecipesDefaultToIf() throws Exception {
        shardedFixture();
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        assertThat(catalog.strictRecipeOrNull("fixture-sharded-preview").modelKind()).isEqualTo("isolation_forest");
        assertThat(catalog.strictRecipeOrNull("fixture-sharded-preview").modelStateFormat()).isEqualTo("SKLEARN_NUMERIC_STATE_V2");
        supportFixture();
        var recipe = catalog.strictRecipeOrNull("fixture-sharded-preview");
        assertThat(recipe.modelKind()).isEqualTo("normal_support_distance");
        assertThat(recipe.recipeVersion()).isEqualTo(1);
        assertThat(recipe.recipeSha256()).hasSize(64);
        assertThat(recipe.modelStateFormat()).isEqualTo("NORMAL_SUPPORT_NUMERIC_STATE_V1");
        assertThat(recipe.mode()).isEqualTo("PILOT");
        assertThat(recipe.descriptor().completedSearchFits()).isZero();
    }

    @Test void supportRecipeRejectsPartialIdentityUnknownRevisionAndChangedConfiguration() throws Exception {
        shardedFixture(); supportFixture();
        Path registry = root.resolve("catalog.json"); ObjectNode original = (ObjectNode) JSON.readTree(registry.toFile());
        for (String field : new String[]{"model_kind", "recipe_version", "recipe_sha256"}) {
            ObjectNode changed = original.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0)).remove(field);
            JSON.writeValue(registry.toFile(), changed);
            assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        }
        for (String field : new String[]{"model_kind", "recipe_sha256"}) {
            ObjectNode changed = original.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0)).put(field, "invalid");
            JSON.writeValue(registry.toFile(), changed);
            assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        }
        for (long revision : new long[]{2, 4294967297L}) {
            ObjectNode changed = original.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0)).put("recipe_version", revision);
            JSON.writeValue(registry.toFile(), changed);
            assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        }
        ObjectNode changed = original.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0).path("config")).put("reference_count", 512);
        JSON.writeValue(registry.toFile(), changed);
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void hybridTypedConfigUsesWorkerCanonicalHashAndRejectsInvalidScalarGrid() throws Exception {
        ObjectNode config = JSON.createObjectNode().put("max_iter", 200).put("max_leaf_nodes", 31).put("l2_regularization", 1).put("random_state", 42);
        ObjectNode identity = JSON.createObjectNode().put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND).put("recipe_version", 1).put("recipe_sha256", hybridHash());
        var recipe = UebaExperimentCatalog.recipeIdentity(identity);
        UebaExperimentCatalog.validateRecipeConfig(JSON, config, recipe);
        assertThat(UebaExperimentCatalog.stateFormat(recipe.modelKind())).isEqualTo("HYBRID_WORKER_CALIBRATED_NUMERIC_STATE_V1");
        for (String malformed : new String[]{
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":0}",
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":1.0,\"random_state\":42}",
                "{\"max_iter\":true,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":42}",
                "{\"max_iter\":201,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":42}",
                "{\"max_iter\":200,\"max_leaf_nodes\":32,\"l2_regularization\":1,\"random_state\":42}",
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":2,\"random_state\":42}",
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":4294967338}",
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"l2_regularization\":1,\"random_state\":42,\"labels\":[]}",
                "{\"max_iter\":200,\"max_leaf_nodes\":31,\"random_state\":42}"}) {
            assertThatThrownBy(() -> UebaExperimentCatalog.validateRecipeConfig(JSON, JSON.readTree(malformed), recipe)).isInstanceOf(ServiceUnavailableException.class);
        }
        ObjectNode changed = config.deepCopy().put("max_iter", 100);
        assertThatThrownBy(() -> UebaExperimentCatalog.validateRecipeConfig(JSON, changed, recipe)).isInstanceOf(ServiceUnavailableException.class);
        for (String field : new String[]{"model_kind", "recipe_version", "recipe_sha256"}) {
            ObjectNode partial = identity.deepCopy(); partial.remove(field);
            assertThatThrownBy(() -> UebaExperimentCatalog.recipeIdentity(partial)).isInstanceOf(ServiceUnavailableException.class);
        }
        assertThatThrownBy(() -> UebaExperimentCatalog.recipeIdentity(identity.deepCopy().put("model_kind", "unknown_hybrid"))).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void hybridPilotRequiresActualNormalAndProtectedIndependentLabeledSources() throws Exception {
        hybridFixture();
        var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        var recipe = catalog.strictRecipeOrNull("fixture-sharded-preview");
        assertThat(recipe.modelKind()).isEqualTo(UebaExperimentCatalog.HYBRID_MODEL_KIND);
        assertThat(recipe.descriptor().trainingWindows()).isEqualTo(50000);
        assertThat(recipe.descriptor().completedSearchFits()).isZero();
        assertThat(recipe.labeledTraining().labeledWindows()).isEqualTo(81500);
        assertThat(recipe.labeledTraining().classWindows()).containsExactlyInAnyOrderEntriesOf(Map.of("0", 71500, "1", 8000, "2", 2000));
        assertThat(recipe.mode()).isEqualTo("PILOT");
        Path registryFile = root.resolve("catalog.json"); ObjectNode original = (ObjectNode) JSON.readTree(registryFile.toFile());
        Path manifestFile = root.resolve("fixture-sharded-data/manifest.json"); ObjectNode originalManifest = (ObjectNode) JSON.readTree(manifestFile.toFile());
        ObjectNode wrongSchema = originalManifest.deepCopy().put("feature_schema_version", 3).put("telemetry_contract_version", 2);
        JSON.writeValue(manifestFile.toFile(), wrongSchema); ObjectNode schemaRegistry = original.deepCopy();
        ((ObjectNode) schemaRegistry.path("strict_entries").get(0)).put("manifest_sha256", digest(manifestFile)); JSON.writeValue(registryFile.toFile(), schemaRegistry);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        JSON.writeValue(manifestFile.toFile(), originalManifest); JSON.writeValue(registryFile.toFile(), original);
        for (String field : new String[]{"labeled_training_artifact_id", "labeled_training_manifest_sha256", "model_state_format"}) {
            ObjectNode changed = original.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0)).remove(field); JSON.writeValue(registryFile.toFile(), changed);
            assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        }
        JSON.writeValue(registryFile.toFile(), original);
        ObjectNode manifest = (ObjectNode) JSON.readTree(manifestFile.toFile());
        ObjectNode fit = (ObjectNode) manifest.path("splits").path("fold1-fit");
        fit.put("records", 2000); fit.put("normal", 2000); fit.putObject("cohorts").put("READY", 2000); fit.putObject("families").put("normal", 2000);
        JSON.writeValue(manifestFile.toFile(), manifest); ((ObjectNode) original.path("strict_entries").get(0)).put("manifest_sha256", digest(manifestFile)); JSON.writeValue(registryFile.toFile(), original);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void hybridProtectedProofCannotBeLaunderedAsStrictOrChangeIsolationAndContextTargets() throws Exception {
        hybridFixture();
        Path registryFile = root.resolve("catalog.json"), trainingFile = root.resolve("hybrid-labeled-data/manifest.private.json");
        ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile()), training = (ObjectNode) JSON.readTree(trainingFile.toFile());
        for (String field : new String[]{"calibration_frame_overlap", "validation_account_hour_overlap"}) {
            ObjectNode changed = training.deepCopy(); ((ObjectNode) changed.path("isolation_proofs")).put(field, 1); JSON.writeValue(trainingFile.toFile(), changed);
            ((ObjectNode) registry.path("strict_entries").get(0)).put("labeled_training_manifest_sha256", digest(trainingFile)); JSON.writeValue(registryFile.toFile(), registry);
            assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        }
        ObjectNode changed = training.deepCopy(); ((ObjectNode) changed.path("class_targets")).put("http_error_burst", 1); JSON.writeValue(trainingFile.toFile(), changed);
        ((ObjectNode) registry.path("strict_entries").get(0)).put("labeled_training_manifest_sha256", digest(trainingFile)); JSON.writeValue(registryFile.toFile(), registry);
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        JSON.writeValue(trainingFile.toFile(), training); ((ObjectNode) registry.path("strict_entries").get(0)).put("labeled_training_manifest_sha256", digest(trainingFile)); JSON.writeValue(registryFile.toFile(), registry);
        Files.setPosixFilePermissions(trainingFile, PosixFilePermissions.fromString("rw-r--r--"));
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
        Files.setPosixFilePermissions(trainingFile, PosixFilePermissions.fromString("rw-------"));
        Path normalFile = root.resolve("fixture-sharded-data/manifest.json"); ObjectNode normal = (ObjectNode) JSON.readTree(normalFile.toFile()); normal.put("stage", "STRICT"); JSON.writeValue(normalFile.toFile(), normal);
        ObjectNode entry = (ObjectNode) registry.path("strict_entries").get(0); entry.put("mode", "STRICT"); entry.put("manifest_sha256", digest(normalFile)); JSON.writeValue(registryFile.toFile(), registry);
        assertThatThrownBy(() -> new UebaExperimentCatalog(root.toString(), JSON).recipes()).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void hybridStrictAdmissionReadsProtectedDescriptorsWithoutNumericOrBinaryEvidence() throws Exception {
        hybridStrictFixture();
        var recipe = new UebaExperimentCatalog(root.toString(), JSON).strictRecipeOrNull("fixture-sharded-preview");
        assertThat(recipe.mode()).isEqualTo("STRICT"); assertThat(recipe.descriptor().completedSearchFits()).isEqualTo(360);
        assertThat(recipe.labeledTraining().artifactId()).isEqualTo("labels-fold3");
        assertThat(recipe.labeledTraining().labeledWindows()).isEqualTo(81500);
        assertThat(recipe.labeledTraining().classWindows()).containsExactlyInAnyOrderEntriesOf(Map.of("0", 71500, "1", 8000, "2", 2000));
        assertThat(recipe.strictProof().proofSha256()).isEqualTo(digest(root.resolve("fixture-sharded-data/hybrid-strict-proof.json")));
        assertThat(recipe.strictProof().recalibrations()).isEqualTo(45);
        // These descriptor fixtures do not establish a real completed campaign.
        assertThat(root.resolve("fixture-sharded-data/shards")).doesNotExist();
        assertThat(root.resolve("fixture-sharded-data/hybrid-models")).doesNotExist();
    }

    @Test void hybridStrictRequiresIndependentSourceScopeProofPinAndSelectedStateHeaders() throws Exception {
        hybridStrictFixture(); var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        Path registryFile = root.resolve("catalog.json"); ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile());
        for (String name : new String[]{"strict_proof_sha256", "labeled_training_manifest_sha256", "normal_fit_split_sha256", "labeled_training_split_sha256"}) {
            ObjectNode changed = registry.deepCopy(); ((ObjectNode) changed.path("strict_entries").get(0)).put(name, "0".repeat(64));
            JSON.writeValue(registryFile.toFile(), changed);
            assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        }
        JSON.writeValue(registryFile.toFile(), registry);
        Path sourceFile = root.resolve("labels-fold3/manifest.private.json"); ObjectNode source = (ObjectNode) JSON.readTree(sourceFile.toFile());
        for (String name : new String[]{"scope", "stage", "standard_manifest_sha256"}) {
            ObjectNode changed = source.deepCopy().put(name, "invalid-source"); JSON.writeValue(sourceFile.toFile(), changed);
            ObjectNode updated = registry.deepCopy(); ((ObjectNode) updated.path("strict_entries").get(0)).put("labeled_training_manifest_sha256", digest(sourceFile));
            JSON.writeValue(registryFile.toFile(), updated);
            assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        }
        JSON.writeValue(sourceFile.toFile(), source); JSON.writeValue(registryFile.toFile(), registry);
        Path selectedFile = root.resolve("fixture-sharded-data/hybrid-selection.json"); ObjectNode selected = (ObjectNode) JSON.readTree(selectedFile.toFile());
        ObjectNode changed = selected.deepCopy().put("model_state_sha256", "0".repeat(64)); JSON.writeValue(selectedFile.toFile(), changed);
        ((ObjectNode) registry.path("strict_entries").get(0)).put("selection_sha256", digest(selectedFile)); JSON.writeValue(registryFile.toFile(), registry);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
    }

    @Test void hybridStrictProtectedFilesDirectoriesAndProofInventoryCannotBeRelaxed() throws Exception {
        hybridStrictFixture(); var catalog = new UebaExperimentCatalog(root.toString(), JSON);
        for (String name : new String[]{"catalog.json", "fixture-sharded-data/manifest.json", "fixture-sharded-data/hybrid-selection.json",
                "fixture-sharded-data/hybrid-strict-proof.json", "labels-fold3/manifest.private.json", "labels-fold3/predeclared.private.json"}) {
            Path file = root.resolve(name); Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
            assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
        for (Path directory : new Path[]{root, root.resolve("fixture-sharded-data"), root.resolve("labels-fold3")}) {
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-x---"));
            assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        }
        Path proofFile = root.resolve("fixture-sharded-data/hybrid-strict-proof.json"), saved = root.resolve("fixture-proof-copy.json");
        Files.move(proofFile, saved); Files.createSymbolicLink(proofFile, saved);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
        Files.delete(proofFile); Files.move(saved, proofFile); // Private metadata fixture only.
        ObjectNode proof = (ObjectNode) JSON.readTree(proofFile.toFile()); ((ObjectNode) proof.path("files")).remove("hybrid-runs/fixture-run-000000.json");
        JSON.writeValue(proofFile.toFile(), proof);
        Path registryFile = root.resolve("catalog.json"); ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile());
        ((ObjectNode) registry.path("strict_entries").get(0)).put("strict_proof_sha256", digest(proofFile)); JSON.writeValue(registryFile.toFile(), registry);
        assertThatThrownBy(catalog::recipes).isInstanceOf(ServiceUnavailableException.class);
    }

    private void hybridStrictFixture() throws Exception {
        // Header/topology fixtures only. Deep numeric campaign verification belongs to the worker.
        shardedFixture(); supportFixture();
        Path directory = root.resolve("fixture-sharded-data"), manifestFile = directory.resolve("manifest.json"), registryFile = root.resolve("catalog.json");
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        ObjectNode manifest = (ObjectNode) JSON.readTree(manifestFile.toFile()); manifest.put("stage", "STRICT");
        ObjectNode normal = trainingSection(50000, Map.of("normal", 50000), Map.of("READY", 50000), "normal-ready-normal");
        ObjectNode splits = (ObjectNode) manifest.path("splits"); splits.set("fold3-fit", normal);
        for (String cohort : new String[]{"ready", "cold"}) {
            ObjectNode split = splits.putObject("fold3-calibration-" + cohort); split.put("records", 1000000).put("normal", 1000000).put("positive", 0);
            split.putObject("cohorts").put(cohort.equals("cold") ? "COLD" : "READY", 1000000);
            split.put("from", "2026-02-01T00:00:00Z").put("to", "2026-02-01T00:00:00Z").put("sha256", "5".repeat(64));
        }
        splits.putObject("holdout").put("normal", 10000000).put("positive", 10000).put("sha256", "f".repeat(64));
        JSON.writeValue(manifestFile.toFile(), manifest); Files.setPosixFilePermissions(manifestFile, PosixFilePermissions.fromString("rw-------"));
        Path labeled = Files.createDirectory(root.resolve("labels-fold3")); Files.setPosixFilePermissions(labeled, PosixFilePermissions.fromString("rwx------"));
        ObjectNode source = JSON.createObjectNode().put("frozen_source_sha256", "1".repeat(64));
        ObjectNode declaration = JSON.createObjectNode().put("fold", 3).put("scope", "FULL_STRICT_SOURCE").put("standard_manifest_sha256", digest(manifestFile)).put("new_frames_generated_before_declaration", 0);
        declaration.set("source_identity", source); Path declaredFile = labeled.resolve("predeclared.private.json"); JSON.writeValue(declaredFile.toFile(), declaration);
        Files.setPosixFilePermissions(declaredFile, PosixFilePermissions.fromString("rw-------"));
        ObjectNode training = JSON.createObjectNode().put("format", "HYBRID_STRICT_LABELED_SOURCE_V1").put("stage", "STRICT_SOURCE").put("scope", "FULL_STRICT_SOURCE")
                .put("quality_gate", "NOT_EVALUATED").put("fold", 3).put("standard_manifest_sha256", digest(manifestFile)).put("predeclared_sha256", digest(declaredFile))
                .put("fit_or_score_calls", 0).put("holdout_numeric_records_read", 0);
        training.set("standard_fit", normal); training.set("source_identity_before", source); training.set("source_identity_after", source);
        ObjectNode sections = training.putObject("sections"); var normalShards = sections.putObject("normal").putArray("shards");
        for (var shard : normal.path("shards")) normalShards.add(((ObjectNode) shard.deepCopy()).put("path", "normal/" + shard.path("id").asText() + ".json"));
        ObjectNode supplement = trainingSection(31500, Map.of("normal", 21500, "request_burst", 2000, "endpoint_scan", 2000,
                "auth_failure_burst", 2000, "sensitive_action_burst", 2000, "http_error_burst", 2000), Map.of("READY", 7050, "UNSEEN_READY", 16300, "COLD", 8150), "supplement-ready");
        var supplementShards = sections.putObject("supplement").putArray("shards");
        for (var shard : supplement.path("shards")) supplementShards.add(((ObjectNode) shard.deepCopy()).put("path", "supplement/" + shard.path("id").asText() + ".json"));
        ObjectNode isolation = training.putObject("isolation_proof");
        for (String name : new String[]{"calibration_frame_overlap", "calibration_account_hour_overlap", "validation_frame_overlap", "validation_account_hour_overlap", "unseen_validation_training_account_overlap"}) isolation.put(name, 0);
        isolation.put("matching_fold_gaps_gt14days", true).put("actual_score_only_splits_scanned", true).put("numeric_holdout_opened", false);
        Path trainingFile = labeled.resolve("manifest.private.json"); JSON.writeValue(trainingFile.toFile(), training); Files.setPosixFilePermissions(trainingFile, PosixFilePermissions.fromString("rw-------"));
        ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile()), entry = (ObjectNode) registry.path("strict_entries").get(0);
        entry.put("mode", "STRICT").put("fold", 3).put("manifest_sha256", digest(manifestFile)).put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND).put("recipe_sha256", hybridHash());
        entry.put("model_state_format", UebaExperimentCatalog.HYBRID_STATE_FORMAT).put("expected_model_sha256", "a".repeat(64)).put("expected_calibration_sha256", "c".repeat(64))
                .put("expected_model_state_sha256", "e".repeat(64)).put("model_state_verifier_sha256", "b".repeat(64));
        entry.put("labeled_training_artifact_id", "labels-fold3").put("labeled_training_manifest_sha256", digest(trainingFile)).put("normal_fit_split_sha256", normal.path("sha256").asText());
        byte[] sectionBytes = JSON.writer().with(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS).writeValueAsBytes(JSON.convertValue(sections, Object.class));
        entry.put("labeled_training_split_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(sectionBytes))).put("labeled_training_windows", 81500);
        entry.set("labeled_class_windows", JSON.valueToTree(Map.of("0", 71500, "1", 8000, "2", 2000)));
        entry.putObject("config").put("max_iter", 200).put("max_leaf_nodes", 31).put("l2_regularization", 1).put("random_state", 42);
        ObjectNode selection = JSON.createObjectNode().put("status", "SELECTED").put("actual_fits_completed", 360).put("validation_runs_completed", 360)
                .put("completed_recalibrations", 45).put("additional_fit_calls_in_recalibration", 0).put("dataset_sha256", digest(manifestFile))
                .put("policy_sha256", entry.path("score_policy").path("policy_sha256").asText()).put("model_version", "fixture-selected-model");
        for (String name : new String[]{"model_kind", "recipe_version", "recipe_sha256", "model_state_format", "model_state_verifier_sha256"}) selection.set(name, entry.path(name));
        selection.put("model_sha256", "a".repeat(64)).put("calibration_sha256", "c".repeat(64)).put("model_state_sha256", "e".repeat(64));
        selection.set("model_config", entry.path("config")); selection.set("policy", entry.path("score_policy"));
        Path selectionFile = directory.resolve("hybrid-selection.json"); JSON.writeValue(selectionFile.toFile(), selection); Files.setPosixFilePermissions(selectionFile, PosixFilePermissions.fromString("rw-------"));
        entry.put("selection_sha256", digest(selectionFile));
        ObjectNode proof = JSON.createObjectNode().put("format", "HYBRID_STRICT_PROOF_V1").put("dataset_sha256", digest(manifestFile)).put("selection_sha256", digest(selectionFile))
                .put("model_sha256", "a".repeat(64)).put("calibration_sha256", "c".repeat(64)).put("model_state_sha256", "e".repeat(64));
        ObjectNode files = proof.putObject("files"); files.put("hybrid-selection.json", digest(selectionFile)).put("hybrid-campaign.progress.json", "1".repeat(64));
        files.put("hybrid-models/fixture-selected-model.json", "1".repeat(64)).put("hybrid-models/fixture-selected-model.joblib", "a".repeat(64));
        ObjectNode archive = proof.putObject("archive_model_sha256");
        for (int index = 0; index < 360; index++) {
            String id = "fixture-run-" + String.format("%06d", index); files.put("hybrid-runs/" + id + ".json", "1".repeat(64)).put("hybrid-validations/" + id + ".json", "1".repeat(64));
            archive.putObject(id).put("source_model_sha256", "1".repeat(64)).put("model_sha256", "2".repeat(64));
            if (index < 45) files.put("hybrid-top-recalibrations/" + id + ".json", "1".repeat(64));
        }
        ObjectNode labels = proof.putObject("source_label_manifests");
        for (int fold = 1; fold <= 3; fold++) labels.putObject(Integer.toString(fold)).put("artifact_id", "labels-fold" + fold).put("manifest_sha256", fold == 3 ? digest(trainingFile) : "8".repeat(64));
        Path proofFile = directory.resolve("hybrid-strict-proof.json"); JSON.writeValue(proofFile.toFile(), proof); Files.setPosixFilePermissions(proofFile, PosixFilePermissions.fromString("rw-------"));
        entry.put("strict_proof_sha256", digest(proofFile)); JSON.writeValue(registryFile.toFile(), registry); Files.setPosixFilePermissions(registryFile, PosixFilePermissions.fromString("rw-------"));
    }

    private void hybridFixture() throws Exception {
        shardedFixture(); supportFixture();
        Path normalFile = root.resolve("fixture-sharded-data/manifest.json"); ObjectNode manifest = (ObjectNode) JSON.readTree(normalFile.toFile());
        ObjectNode normal = trainingSection(50000, Map.of("normal", 50000), Map.of("READY", 50000), "normal-ready-normal");
        ((ObjectNode) manifest.path("splits")).set("fold1-fit", normal.deepCopy()); JSON.writeValue(normalFile.toFile(), manifest);
        Path directory = Files.createDirectory(root.resolve("hybrid-labeled-data")); Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        ObjectNode source = JSON.createObjectNode().put("frozen_source_sha256", "1".repeat(64));
        ObjectNode declaration = JSON.createObjectNode(); declaration.set("source_identity", source); declaration.put("new_frames_generated_before_declaration", 0);
        Path declaredFile = directory.resolve("predeclared.private.json"); JSON.writeValue(declaredFile.toFile(), declaration); Files.setPosixFilePermissions(declaredFile, PosixFilePermissions.fromString("rw-------"));
        ObjectNode training = JSON.createObjectNode(); training.put("artifact_id", "hybrid-labeled-data"); training.put("dataset_id", "hybrid-labeled-data");
        training.put("hybrid_bulk_training_schema_version", 1); training.put("feature_schema_version", 4); training.put("telemetry_contract_version", 3);
        training.put("stage", "BULK_PILOT"); training.put("data_provenance", "DEMO_ONLY"); training.put("quality_gate", "NOT_APPLICABLE");
        training.put("fit_or_score_calls", 0); training.put("holdout_numeric_records_read", 0); training.put("confirmed_attack_target_available", false);
        training.set("feature_names", JSON.valueToTree(AccountBehaviorFeatures.names(4)));
        training.set("class_targets", JSON.valueToTree(Map.of("normal", 0, "request_burst", 1, "endpoint_scan", 1, "auth_failure_burst", 1, "sensitive_action_burst", 1, "http_error_burst", 2)));
        training.set("class_target_names", JSON.valueToTree(Map.of("0", "NORMAL", "1", "SIMULATED_SECURITY_BEHAVIOR_CONTEXT", "2", "SIMULATED_OPERATIONAL_FAILURE_CONTEXT")));
        training.set("source_identity_before", source); training.set("source_identity_after", source.deepCopy()); training.put("predeclared_identity_sha256", digest(declaredFile));
        ObjectNode proof = training.putObject("isolation_proofs"); proof.put("unseen_validation_accounts_disjoint", true); proof.put("all_training_before_calibration_by_more_than14days", true);
        for (String field : new String[]{"calibration_frame_overlap", "calibration_account_hour_overlap", "validation_frame_overlap", "validation_account_hour_overlap"}) proof.put(field, 0);
        ObjectNode sections = training.putObject("training_sections"); sections.set("NORMAL_COMPONENT", normal);
        sections.set("SUPPLEMENT", trainingSection(31500, Map.of("normal", 21500, "request_burst", 2000, "endpoint_scan", 2000,
                "auth_failure_burst", 2000, "sensitive_action_burst", 2000, "http_error_burst", 2000), Map.of("READY", 7050, "UNSEEN_READY", 16300, "COLD", 8150), "supplement-ready"));
        Path trainingFile = directory.resolve("manifest.private.json"); JSON.writeValue(trainingFile.toFile(), training); Files.setPosixFilePermissions(trainingFile, PosixFilePermissions.fromString("rw-------"));
        Path registryFile = root.resolve("catalog.json"); ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile()); ObjectNode entry = (ObjectNode) registry.path("strict_entries").get(0);
        entry.put("manifest_sha256", digest(normalFile)); entry.put("model_kind", UebaExperimentCatalog.HYBRID_MODEL_KIND); entry.put("recipe_sha256", hybridHash());
        entry.put("model_state_format", UebaExperimentCatalog.HYBRID_STATE_FORMAT); entry.put("labeled_training_artifact_id", "hybrid-labeled-data"); entry.put("labeled_training_manifest_sha256", digest(trainingFile));
        ObjectNode config = entry.putObject("config"); config.put("max_iter", 200); config.put("max_leaf_nodes", 31); config.put("l2_regularization", 1); config.put("random_state", 42);
        JSON.writeValue(registryFile.toFile(), registry);
    }

    private ObjectNode trainingSection(int records, Map<String, Integer> families, Map<String, Integer> cohorts, String prefix) {
        ObjectNode section = JSON.createObjectNode(); section.put("records", records); section.put("normal", families.getOrDefault("normal", 0)); section.put("positive", records - families.getOrDefault("normal", 0));
        section.set("families", JSON.valueToTree(families)); section.set("cohorts", JSON.valueToTree(cohorts)); section.put("from", "2026-01-01T00:00:00Z"); section.put("to", "2026-01-01T00:00:00Z"); section.put("sha256", "3".repeat(64));
        var shards = section.putArray("shards"); Map<String, Integer> familyRemaining = new LinkedHashMap<>(families), cohortRemaining = new LinkedHashMap<>(cohorts);
        for (int offset = 0, index = 0; offset < records; offset += 5000, index++) {
            int count = Math.min(5000, records - offset); String id = "bulk-" + prefix + "-b" + String.format("%06d", index) + "-000";
            ObjectNode shard = shards.addObject(); shard.put("id", id); shard.put("path", "shards/" + id + ".json"); shard.put("sha256", "4".repeat(64)); shard.put("records", count);
            Map<String, Integer> family = takePopulation(familyRemaining, count), cohort = takePopulation(cohortRemaining, count);
            shard.put("normal", family.getOrDefault("normal", 0)); shard.put("positive", count - family.getOrDefault("normal", 0)); shard.set("families", JSON.valueToTree(family)); shard.set("cohorts", JSON.valueToTree(cohort));
            shard.put("from", "2026-01-01T00:00:00Z"); shard.put("to", "2026-01-01T00:00:00Z");
        }
        return section;
    }

    private static Map<String, Integer> takePopulation(Map<String, Integer> remaining, int count) {
        Map<String, Integer> result = new LinkedHashMap<>();
        for (var entry : remaining.entrySet()) {
            int taken = Math.min(count, entry.getValue()); if (taken > 0) result.put(entry.getKey(), taken);
            entry.setValue(entry.getValue() - taken); count -= taken;
        }
        return result;
    }

    private static String hybridHash() throws Exception {
        String canonical = "{\"config\":{\"l2_regularization\":1,\"max_iter\":200,\"max_leaf_nodes\":31,\"random_state\":42},\"model_kind\":\"normal_plus_incident_research\",\"recipe_version\":1}";
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private void supportFixture() throws Exception {
        Path manifestFile = root.resolve("fixture-sharded-data/manifest.json");
        ObjectNode manifest = (ObjectNode) JSON.readTree(manifestFile.toFile());
        manifest.put("feature_schema_version", 4); manifest.put("telemetry_contract_version", 3);
        JSON.writeValue(manifestFile.toFile(), manifest);
        Path registryFile = root.resolve("catalog.json"); ObjectNode registry = (ObjectNode) JSON.readTree(registryFile.toFile());
        ObjectNode entry = (ObjectNode) registry.path("strict_entries").get(0);
        entry.put("manifest_sha256", digest(manifestFile)); entry.set("score_policy", UebaTestPolicies.sessionEndpoint(JSON));
        entry.put("model_kind", "normal_support_distance"); entry.put("recipe_version", 1);
        ObjectNode config = entry.putObject("config");
        config.put("neighbor_count", 8); config.put("reference_count", 256); config.put("metric", "euclidean"); config.put("random_state", 42);
        String canonical = "{\"config\":{\"metric\":\"euclidean\",\"neighbor_count\":8,\"random_state\":42,\"reference_count\":256},\"model_kind\":\"normal_support_distance\",\"recipe_version\":1}";
        entry.put("recipe_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8))));
        JSON.writeValue(registryFile.toFile(), registry);
    }

    private void shardedFixture() throws Exception {
        Path directory = Files.createDirectory(root.resolve("fixture-sharded-data"));
        ObjectNode manifest = JSON.createObjectNode();
        manifest.put("dataset_id", "fixture-sharded-data"); manifest.put("data_provenance", "DEMO_ONLY");
        manifest.put("catalog_schema_version", 2); manifest.put("feature_schema_version", 2);
        manifest.put("telemetry_contract_version", 2); manifest.put("stage", "PILOT");
        ObjectNode splits = manifest.putObject("splits");
        for (String name : new String[]{"fold1-fit", "fold1-calibration-ready", "fold1-calibration-cold"}) {
            ObjectNode split = splits.putObject(name); int count = name.endsWith("-fit") ? 600 : 300;
            split.put("records", count); split.put("positive", 0);
            split.putObject("cohorts").put(name.endsWith("-cold") ? "COLD" : "READY", count);
            split.put("from", name.endsWith("-fit") ? "2026-01-01T00:00:00Z" : "2026-02-01T00:00:00Z");
            split.put("to", name.endsWith("-fit") ? "2026-01-01T00:00:00Z" : "2026-02-01T00:00:00Z");
        }
        JSON.writeValue(directory.resolve("manifest.json").toFile(), manifest);
        ObjectNode registry = JSON.createObjectNode(); registry.putArray("entries");
        ObjectNode entry = registry.putArray("strict_entries").addObject();
        entry.put("recipe_id", "fixture-sharded-preview"); entry.put("dataset_id", "fixture-sharded-data");
        entry.put("mode", "PILOT"); entry.put("fold", 1); entry.put("manifest_sha256", digest(directory.resolve("manifest.json")));
        entry.set("score_policy", JSON.readTree(getClass().getResourceAsStream("/ueba-score-policy-golden.json")));
        JSON.writeValue(root.resolve("catalog.json").toFile(), registry);
    }

    private void fixture() throws Exception {
        Path directory = Files.createDirectory(root.resolve("fixture-dataset"));
        ObjectNode manifest = JSON.createObjectNode();
        manifest.put("dataset_id", "fixture-dataset"); manifest.put("data_provenance", "DEMO_ONLY"); manifest.put("feature_schema_version", 2);
        ObjectNode splits = manifest.putObject("splits");
        writeSplit(directory, splits, "fold3-fit", 10000, Instant.parse("2026-08-01T00:00:00Z"), false);
        writeSplit(directory, splits, "fold3-calibration", 2000, Instant.parse("2026-08-10T00:00:00Z"), false);
        writeSplit(directory, splits, "holdout", 11000, Instant.parse("2026-08-15T00:00:00Z"), true);
        JSON.writeValue(directory.resolve("manifest.json").toFile(), manifest);
        ObjectNode selection = JSON.createObjectNode();
        selection.put("status", "SELECTED"); selection.put("completed_fits", 360);
        selection.put("dataset_manifest_sha256", digest(directory.resolve("manifest.json")));
        ObjectNode candidate = selection.putObject("selected").putObject("candidate");
        candidate.put("fold", 3);
        ObjectNode config = candidate.putObject("config");
        config.put("n_estimators", 200); config.put("max_samples", 256); config.put("max_features", 1.0); config.put("random_state", 42);
        JSON.writeValue(directory.resolve("selection.json").toFile(), selection);
        ObjectNode catalog = JSON.createObjectNode();
        ObjectNode entry = catalog.putArray("entries").addObject();
        entry.put("recipe_id", "fixture-dataset-champion"); entry.put("dataset_id", "fixture-dataset");
        entry.put("manifest_sha256", digest(directory.resolve("manifest.json")));
        entry.put("selection_sha256", digest(directory.resolve("selection.json")));
        entry.put("holdout_payload_sha256_v1", "a".repeat(64)); entry.put("holdout_payload_sha256_v2", "b".repeat(64));
        JSON.writeValue(root.resolve("catalog.json").toFile(), catalog);
    }

    private void writeSplit(Path directory, ObjectNode manifest, String name, int count, Instant start, boolean holdout) throws Exception {
        ObjectNode payload = JSON.createObjectNode();
        payload.put("split_name", name); payload.put("data_provenance", "DEMO_ONLY"); payload.put("feature_schema_version", 2);
        var records = payload.putArray("records");
        for (int index = 0; index < count; index++) {
            ObjectNode row = records.addObject();
            row.put("frame_id", name + "-frame-" + index); row.put("account_id", "fixture-account-" + index % 150);
            row.put("window_start", start.plusSeconds(index / 150 * 900L).toString());
            row.put("baseline_established", true); row.put("label", holdout && index >= 10000 ? 1 : 0);
            row.put("family", holdout && index >= 10000 ? new String[]{"request_burst", "endpoint_scan", "auth_failure_burst",
                    "sensitive_action_burst", "http_error_burst"}[index % 5] : "normal");
            var features = row.putArray("features");
            for (double value : new double[]{1,0,0,0,1,0,1,1,0,0,0,0,0,0,0}) features.add(value);
        }
        Path file = directory.resolve(name + ".json");
        JSON.writeValue(file.toFile(), payload);
        ObjectNode split = manifest.putObject(name);
        split.put("path", file.getFileName().toString()); split.put("sha256", digest(file)); split.put("windows", count);
        split.put("from", start.toString()); split.put("to", start.plusSeconds((count - 1) / 150 * 900L).toString());
    }

    private static String digest(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
