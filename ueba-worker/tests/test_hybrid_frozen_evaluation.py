"""Mocked strict inventories/transport test guards, never qualification evidence."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
from itertools import product
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.catalog_evaluation import evaluate_recipe
from app.contract import HYBRID_MODEL_KIND, campaign_runs, recipe_binding
from app.frozen_evaluation import (_hybrid_read, evaluate, evaluate_bound, verify_hybrid_strict_proof,
                                   HYBRID_PROOF_FILE, HYBRID_PROOF_FORMAT)
from app.model_state_dispatch import HYBRID_FORMAT
from app.policy import DETECTION_GRID, ScorePolicy, canonical
from app.strict_metrics import Confusion, FAMILIES


class Fixture:
    """Only virtual receipt readback is mocked; no corpus or fits are created."""
    def __init__(self, root):
        self.root = root / "standard"; self.root.mkdir(mode=0o700); root.chmod(0o700)
        self.sha = "a" * 64; self.model_sha = "b" * 64; self.cal_sha = "c" * 64; self.state_sha = "d" * 64
        self.code = {"sources": {"fixture": "counter-only"}}
        self.runs = campaign_runs(HYBRID_MODEL_KIND)
        self.run = next(run for run in self.runs if run["fold"] == 3 and run["config"].random_state == 42)
        self.config = self.run["config"]; self.policy = ScorePolicy.strict(schema=4)
        self.identity = {"dataset_manifest_sha256": self.sha, "fit_code_fingerprint": self.code,
                         "model_kind": HYBRID_MODEL_KIND, "recipe_version": 1, "production_classes": {}}
        self.dataset = SimpleNamespace(root=self.root, sha256=self.sha,
                                       manifest={"stage": "STRICT", "feature_schema_version": 4},
                                       split=self.split, iter_shards=self.no_rows)
        self.fold_manifests = {fold: {"scope": "FULL_STRICT_SOURCE", "fold": fold,
                                      "sections": {"normal": {"fixture": fold}, "supplement": {"fixture": fold}}}
                               for fold in (1, 2, 3)}
        self.labels = {str(fold): {"artifact_id": f"labels-fold{fold}", "manifest_sha256": str(fold) * 64} for fold in (1, 2, 3)}
        self.implementation = {"scorer": "mocked-boundary-only"}
        label = self.label_binding(3)
        self.metadata = {"model_version": "hybrid_selected_fixture", "sha256": self.model_sha,
                         "feature_schema_version": 4, "dataset_manifest_sha256": self.sha,
                         "model_config": asdict(self.config), "score_policy": self.policy.wire(), "fold": 3,
                         "calibration_sha256": self.cal_sha, "calibration_scope": "STRICT",
                         "model_state_sha256": self.state_sha, "model_state_format": HYBRID_FORMAT,
                         "model_state_verifier_sha256": "e" * 64, "scoring_implementation": self.implementation,
                         "training_windows": 50000,
                         "actual_component_fit_counts": {"normal_component_fit_calls": 1, "labeled_component_fit_calls": 1},
                         "labeled_training_scope": "CALLER_VERIFIED_SEPARATE_CHRONOLOGICAL_TRAINING_ONLY",
                         "normal_training_scope": "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED",
                         "data_provenance": "DEMO_ONLY", "confirmed_attack_target_available": False,
                         **label, **recipe_binding(self.config)}
        self.payload = {"model": object()}
        self.selected = {"status": "SELECTED", "actual_fits_completed": 360, "validation_runs_completed": 360,
                         "completed_recalibrations": 45, "additional_fit_calls_in_recalibration": 0,
                         "selection_identity": self.identity, "model_version": self.metadata["model_version"],
                         "model_sha256": self.model_sha, "calibration_sha256": self.cal_sha,
                         "dataset_sha256": self.sha, "policy_sha256": self.policy.sha256, "policy": self.policy.wire(),
                         "model_config": asdict(self.config), "model_state_sha256": self.state_sha,
                         "model_state_format": HYBRID_FORMAT, "model_state_verifier_sha256": "e" * 64,
                         "scoring_implementation": self.implementation, **recipe_binding(self.config)}
        scope = {**Confusion(1000, 0, 0, 1000000).metrics(),
                 "families": {family: Confusion(200, 0, 0, 0).metrics() for family in FAMILIES},
                 "cohorts": {cohort: Confusion(positive, 0, 0, normal).metrics() for cohort, positive, normal in
                             (("READY", 700, 700000), ("UNSEEN_READY", 200, 200000), ("COLD", 100, 100000))}}
        cases = [{"policy": ScorePolicy.strict(ready, cold, rule, schema=4).wire(),
                  "scopes": {"MODEL_ONLY": scope, "SIEM_FINAL": scope}}
                 for ready, cold, rule in product(DETECTION_GRID, DETECTION_GRID, (45, 60, 70))]
        self.records = {"hybrid-selection.json": self.selected,
                        "hybrid-campaign.progress.json": {"status": "FIT_AND_CALIBRATION_COMPLETE", "model_kind": HYBRID_MODEL_KIND,
                            "code_fingerprint": self.code, "dataset_manifest_sha256": self.sha,
                            "actual_fits_completed": 360, "actual_composite_trials": 360, "actual_component_fit_calls": 720,
                            "required_component_fit_calls": 720, "additional_fits_in_recalibration": 0,
                            "labeled_training_manifest_sha256_by_fold": {fold: label["manifest_sha256"] for fold, label in self.labels.items()}},
                        f"hybrid-models/{self.metadata['model_version']}.json": self.metadata,
                        f"hybrid-models/{self.metadata['model_version']}.joblib": None}
        archives = {}
        for index, run in enumerate(self.runs):
            run_id = run["run_id"]; fold = run["fold"]; config = asdict(run["config"])
            fit = {"run_id": run_id, "fold": fold, "config": config, "dataset_manifest_sha256": self.sha,
                   "code_fingerprint": self.code, "fit_split_sha256": self.split(f"fold{fold}-fit")["sha256"],
                   "status": "FITTED_CALIBRATED", "source_model_version": "fixture_source_" + str(index),
                   "source_model_sha256": "f" * 64, "model_sha256": "f" * 64, "calibration_sha256": self.cal_sha,
                   "actual_composite_trials": 1, "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0,
                   **self.label_binding(fold), **recipe_binding(run["config"])}
            self.records[f"hybrid-runs/{run_id}.json"] = fit
            archives[run_id] = {key: fit[key] for key in ("source_model_sha256", "model_sha256")}
            self.records[f"hybrid-validations/{run_id}.json"] = {
                "run_id": run_id, "fold": fold, "config": config, "status": "VALIDATED", "evaluation_scope": "VALIDATION",
                "selection_identity": self.identity, "model_sha256": fit["model_sha256"], "calibration_sha256": self.cal_sha,
                "dataset_manifest_sha256": self.sha, "validation_split_sha256": self.split(f"fold{fold}-validation")["sha256"],
                "policies": cases, **recipe_binding(run["config"])}
            if index < 45:
                representative = run_id == self.run["run_id"]
                self.records[f"hybrid-top-recalibrations/{run_id}.json"] = {
                    "run_id": run_id, "fold": fold, "config": config, "selection_identity": self.identity,
                    "source_model_version": fit["source_model_version"], "source_model_sha256": fit["source_model_sha256"],
                    "additional_fit_calls": 0, "model_version": self.metadata["model_version"] if representative else "fixture_recal_" + str(index),
                    "model_sha256": self.model_sha if representative else "f" * 64,
                    "calibration_sha256": self.cal_sha, "policy_sha256": self.policy.sha256,
                    "model_state_sha256": self.state_sha, "model_state_format": HYBRID_FORMAT,
                    "model_state_verifier_sha256": "e" * 64, **recipe_binding(run["config"])}
        self.files = {path: self.model_sha if path.endswith(".joblib") else "9" * 64 for path in self.records}
        self.proof = {"format": HYBRID_PROOF_FORMAT, "dataset_sha256": self.sha, "selection_sha256": "9" * 64,
                      "model_sha256": self.model_sha, "calibration_sha256": self.cal_sha, "model_state_sha256": self.state_sha,
                      "files": self.files, "source_label_manifests": self.labels, "archive_model_sha256": archives}
        for relative in (*self.records, HYBRID_PROOF_FILE):
            path = self.root / relative; path.parent.mkdir(mode=0o700, exist_ok=True)
            path.write_text("{}"); path.chmod(0o600)

    def no_rows(self, name): raise AssertionError("this test must not open any numeric/holdout row")
    def split(self, name):
        if name == "holdout":
            return {"normal": 10000000, "positive": 10000, "sha256": "8" * 64}
        if name.endswith("-fit"): return {"records": 50000, "sha256": "7" * 64}
        if name.endswith("-validation"): return {"normal": 1000000, "positive": 1000, "sha256": "6" * 64}
        raise AssertionError("unexpected split " + name)
    def label_binding(self, fold):
        return {"labeled_training_artifact_id": f"labels-fold{fold}", "labeled_training_manifest_sha256": str(fold) * 64,
                "labeled_training_split_sha256": hashlib.sha256(canonical(self.fold_manifests[fold]["sections"]).encode()).hexdigest(),
                "normal_fit_split_sha256": "7" * 64, "labeled_training_windows": 81500,
                "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000}}
    def read(self, path, maximum, *, document=True):
        relative = str(path.relative_to(self.root))
        if relative == HYBRID_PROOF_FILE: return "5" * 64, self.proof
        return self.files[relative], self.records[relative]
    def store(self):
        fixture = self
        class Store:
            def __init__(self, directory): self.directory = directory
            def load_candidate(self, version): return fixture.metadata, fixture.payload
            @staticmethod
            def scoring_identity(model): return fixture.implementation
        return Store


class HybridStrictProofTest(unittest.TestCase):
    def exercise(self, fixture, *, source=False, proof=None):
        with patch("app.frozen_evaluation._hybrid_read", side_effect=fixture.read), \
                patch("app.frozen_evaluation.fingerprint", return_value=fixture.code), \
                patch("app.frozen_evaluation.hybrid_fold_training", side_effect=lambda dataset, fold:
                      ([], [], fixture.fold_manifests[fold], str(fold) * 64)) as labels, \
                patch("app.frozen_evaluation.ModelStore", fixture.store()), \
                patch("app.frozen_evaluation.state_sha256", return_value=fixture.state_sha), \
                patch("app.frozen_evaluation.verifier_sha256", return_value="e" * 64):
            result = verify_hybrid_strict_proof(fixture.dataset, fixture.selected, fixture.metadata, fixture.payload, source=source, proof=proof)
            self.assertEqual(labels.call_count, 3)
            return result

    def test_full_inventory_reads_all_receipts_and_all_three_protected_label_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary)); result = self.exercise(fixture)
            self.assertEqual(result["actual_composite_trials"], 360)
            self.assertEqual(result["actual_component_fit_calls"], 720)
            self.assertEqual(result["validation_runs"], 360)
            self.assertEqual(result["zero_fit_recalibrations"], 45)
            self.assertEqual(result["format"], HYBRID_PROOF_FORMAT)

    def test_summary_missing_receipts_wrong_labels_and_fake_fit_counts_do_not_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            original = deepcopy(fixture.proof)
            fixture.proof["files"].pop(next(path for path in fixture.files if path.startswith("hybrid-validations/")))
            with self.assertRaises(ValueError): self.exercise(fixture)
            fixture.proof = original; fixture.files = fixture.proof["files"]
            progress = fixture.records["hybrid-campaign.progress.json"]
            progress["actual_component_fit_calls"] = 719
            with self.assertRaisesRegex(ValueError, "360/720"): self.exercise(fixture)
            progress["actual_component_fit_calls"] = 720
            first = fixture.records["hybrid-runs/" + fixture.runs[0]["run_id"] + ".json"]
            first["actual_component_fit_calls"] = 1
            with self.assertRaisesRegex(ValueError, "both component"): self.exercise(fixture)
            first["actual_component_fit_calls"] = 2
            fixture.proof["source_label_manifests"]["3"]["manifest_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "labeled source hash"): self.exercise(fixture)

    def test_foreign_policy_recalibration_fit_or_selected_source_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary)); fixture.metadata["fold"] = 2
            with self.assertRaisesRegex(ValueError, "fold3 seed42"): self.exercise(fixture)
            fixture.metadata["fold"] = 3
            fixture.metadata["catalogue_mode"] = "PILOT"
            with self.assertRaisesRegex(ValueError, "state/source"): self.exercise(fixture)
            fixture.metadata.pop("catalogue_mode")
            fixture.metadata["scope"] = "SCOPED_TEST"
            with self.assertRaisesRegex(ValueError, "state/source"): self.exercise(fixture)
            fixture.metadata.pop("scope")
            fixture.metadata["actual_component_fit_counts"]["normal_component_fit_calls"] = True
            with self.assertRaisesRegex(ValueError, "state/source"): self.exercise(fixture)
            fixture.metadata["actual_component_fit_counts"]["normal_component_fit_calls"] = 1
            path = "hybrid-top-recalibrations/" + fixture.runs[0]["run_id"] + ".json"
            fixture.records[path]["additional_fit_calls"] = 1
            with self.assertRaisesRegex(ValueError, "zero additional"): self.exercise(fixture)

    def test_source_fallback_derives_inventory_read_only_but_package_requires_installed_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary)); path = fixture.root / HYBRID_PROOF_FILE
            path.unlink()  # Only this temporary test fixture is removed.
            with self.assertRaisesRegex(ValueError, "proof unavailable"):
                verify_hybrid_strict_proof(fixture.dataset, fixture.selected, fixture.metadata, fixture.payload)
            with patch("app.package_catalog.hybrid_strict_proof", return_value=fixture.proof) as construct:
                self.exercise(fixture, source=True)
                construct.assert_called_once_with(fixture.dataset, fixture.selected, fixture.metadata, fixture.payload)
            self.assertFalse(path.exists())

    def test_prebuilt_proof_is_deeply_checked_without_native_constructor_recursion(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary)); path = fixture.root / HYBRID_PROOF_FILE
            path.unlink()  # Only this temporary fixture is removed.
            with patch("app.package_catalog.hybrid_strict_proof", side_effect=AssertionError("prebuilt proof must not recurse")):
                result = self.exercise(fixture, proof=fixture.proof)
                self.assertEqual(result["proof_sha256"], hashlib.sha256(canonical(fixture.proof).encode()).hexdigest())
            self.assertFalse(path.exists())

    def test_private_readback_rejects_public_symlink_changed_hash_and_oversize_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / "owned-proof.json"; path.write_text('{"fixture":true}'); path.chmod(0o600)
            checksum, record = _hybrid_read(path, 100)
            self.assertEqual(checksum, hashlib.sha256(path.read_bytes()).hexdigest()); self.assertEqual(record, {"fixture": True})
            with self.assertRaisesRegex(ValueError, "bounded protected"): _hybrid_read(path, 2)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "protected"): _hybrid_read(path, 100)
            path.chmod(0o600); link = root / "link-proof.json"; link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "canonical"): _hybrid_read(link, 100)


class HybridFinalAdapterTest(unittest.TestCase):
    def test_source_adapter_checks_state_and_proof_before_any_holdout_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            (fixture.root / "hybrid-selection.json").write_text(canonical(fixture.selected))
            guard = {"format": HYBRID_PROOF_FORMAT, "actual_composite_trials": 360, "actual_component_fit_calls": 720,
                     "validation_runs": 360, "zero_fit_recalibrations": 45}
            with patch("app.frozen_evaluation.ShardedDataset", return_value=fixture.dataset), \
                    patch("app.frozen_evaluation.selection_identity", return_value=fixture.identity), \
                    patch("app.frozen_evaluation.ModelStore", fixture.store()), \
                    patch("app.frozen_evaluation.state_sha256", return_value=fixture.state_sha), \
                    patch("app.frozen_evaluation.state_format", return_value=HYBRID_FORMAT), \
                    patch("app.frozen_evaluation.verifier_sha256", return_value="e" * 64), \
                    patch("app.frozen_evaluation.verify_hybrid_strict_proof", return_value=guard) as proof, \
                    patch("app.frozen_evaluation.evaluate_bound", return_value={"quality_gate": "NOT_RUN"}) as bound:
                result = evaluate(fixture.root, fixture.root, HYBRID_MODEL_KIND)
                self.assertEqual(result["quality_gate"], "NOT_RUN")
                proof.assert_called_once_with(fixture.dataset, fixture.selected, fixture.metadata, fixture.payload, source=True)
                self.assertEqual(bound.call_args.args[5]["hybrid_strict_proof"], guard)
                fixture.selected["model_state_sha256"] = "0" * 64
                (fixture.root / "hybrid-selection.json").write_text(canonical(fixture.selected))
                proof.reset_mock(); bound.reset_mock()
                with self.assertRaisesRegex(ValueError, "state/scoring"): evaluate(fixture.root, fixture.root, HYBRID_MODEL_KIND)
                proof.assert_not_called(); bound.assert_not_called()

    def test_worker_adapter_uses_typed_config_and_proof_but_cannot_accept_preview_labels(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary)); recipe_id = "hybrid_recipe_fixture"
            (fixture.root / "hybrid-selection.json").write_text(canonical(fixture.selected))
            fixture.metadata.update(recipe_id=recipe_id, catalogue_mode="STRICT", selected_reference_model_sha256=fixture.model_sha,
                                    strict_proof_sha256="5" * 64)
            recipe = SimpleNamespace(mode="STRICT", dataset=fixture.dataset, model_kind=HYBRID_MODEL_KIND,
                recipe_version=1, recipe_sha256=recipe_binding(fixture.config)["recipe_sha256"], config=fixture.config,
                policy=fixture.policy, fold=3, recipe_id=recipe_id, expected_model_sha256=fixture.model_sha,
                expected_calibration_sha256=fixture.cal_sha, expected_model_state_sha256=fixture.state_sha,
                model_state_format=HYBRID_FORMAT, model_state_verifier_sha256="e" * 64,
                labeled_training_artifact_id="labels-fold3", labeled_training_manifest_sha256="3" * 64, strict_proof_sha256="5" * 64,
                holdout_access_audit_sha256=None)
            guard = {"format": HYBRID_PROOF_FORMAT, "proof_sha256": "5" * 64}
            with patch("app.catalog_evaluation.selection_identity", return_value=fixture.identity), \
                    patch("app.catalog_evaluation.state_sha256", return_value=fixture.state_sha), \
                    patch("app.catalog_evaluation.state_format", return_value=HYBRID_FORMAT), \
                    patch("app.catalog_evaluation.verifier_sha256", return_value="e" * 64), \
                    patch("app.model.ModelStore.scoring_identity", return_value=fixture.implementation), \
                    patch("app.catalog_evaluation.verify_hybrid_strict_proof", return_value=guard) as proof, \
                    patch("app.catalog_evaluation.evaluate_bound", return_value={"quality_gate": "NOT_RUN"}) as bound:
                evaluate_recipe(fixture.store()(fixture.root), recipe, fixture.metadata["model_version"], fixture.root)
                proof.assert_called_once(); self.assertEqual(bound.call_args.args[5]["hybrid_strict_proof"], guard)
                for pin in (None, "bad", "6" * 64):
                    recipe.strict_proof_sha256 = pin; proof.reset_mock(); bound.reset_mock()
                    with self.assertRaisesRegex(ValueError, "proof pin"):
                        evaluate_recipe(fixture.store()(fixture.root), recipe, fixture.metadata["model_version"], fixture.root)
                    proof.assert_not_called(); bound.assert_not_called()
                recipe.strict_proof_sha256 = "5" * 64
                guard["proof_sha256"] = "6" * 64; proof.reset_mock(); bound.reset_mock()
                with self.assertRaisesRegex(ValueError, "proof checksum"):
                    evaluate_recipe(fixture.store()(fixture.root), recipe, fixture.metadata["model_version"], fixture.root)
                proof.assert_called_once(); bound.assert_not_called(); guard["proof_sha256"] = "5" * 64
                recipe.labeled_training_artifact_id = "pilot-labels-fixture"; proof.reset_mock(); bound.reset_mock()
                with self.assertRaisesRegex(ValueError, "labeled source"): evaluate_recipe(fixture.store()(fixture.root), recipe, fixture.metadata["model_version"], fixture.root)
                proof.assert_not_called(); bound.assert_not_called()

    def test_internal_transport_cannot_start_a_hybrid_without_verified_complete_proofs(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            with patch.object(fixture.dataset, "split", side_effect=AssertionError("holdout must remain unopened")), \
                    self.assertRaisesRegex(ValueError, "verified hybrid proof"):
                evaluate_bound(fixture.dataset, fixture.store()(fixture.root), fixture.metadata, fixture.payload,
                               fixture.policy, {}, fixture.root)


if __name__ == "__main__": unittest.main()
