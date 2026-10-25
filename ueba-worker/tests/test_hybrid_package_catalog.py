"""Mocked future receipt boundaries, never strict data/fit/quality evidence."""
from contextlib import ExitStack
import copy
from dataclasses import asdict
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.contract import HYBRID_MODEL_KIND, campaign_runs, model_recipe_binding, recipe_binding
from app.archived_catalog import FORMAT as ARCHIVE_FORMAT, SIDECAR
from app.model_state_dispatch import HYBRID_FORMAT
from app.package_catalog import package_recipe, recipe_entry
from app.policy import ScorePolicy, canonical
from app.quality_proof import sha_file


def write(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else canonical(value).encode())
    path.chmod(0o600)


class HybridPackageTest(unittest.TestCase):
    def future_receipts(self, root):
        source = root / "standard"; source.mkdir(mode=0o700)
        splits = {}
        labels = {}
        for fold in (1, 2, 3):
            split = {"sha256": str(fold) * 64, "shards": []}; splits[f"fold{fold}-fit"] = split
            splits[f"fold{fold}-validation"] = {"sha256": "6" * 64, "shards": []}
            directory = root / f"labels-fold{fold}"; directory.mkdir(mode=0o700)
            write(directory / "predeclared.private.json", {"fold": fold})
            write(directory / "normal/normal-fixture-000000.json", b"[]")
            write(directory / "supplement/supplement-fixture-000000.json", b"[]")
            sections = {role: {"shards": [{"path": f"{role}/{role}-fixture-000000.json",
                                          "sha256": sha_file(directory / f"{role}/{role}-fixture-000000.json")}]}
                        for role in ("normal", "supplement")}
            manifest = {"fold": fold, "scope": "FULL_STRICT_SOURCE", "standard_fit": split, "sections": sections,
                        "predeclared_sha256": sha_file(directory / "predeclared.private.json")}
            write(directory / "manifest.private.json", manifest)
            labels[fold] = ([], [], manifest, sha_file(directory / "manifest.private.json"))
        manifest = {"stage": "STRICT", "feature_schema_version": 4, "dataset_id": "future-strict-fixture", "splits": splits}
        write(source / "manifest.json", manifest)
        dataset = SimpleNamespace(root=source, manifest=manifest, sha256=sha_file(source / "manifest.json"), split=splits.__getitem__)
        code = {"test_fixture_only": True}; identity = {"fit_code_fingerprint": code, "dataset_manifest_sha256": dataset.sha256,
                                                       "model_kind": HYBRID_MODEL_KIND}
        write(source / "hybrid-campaign.progress.json", {"status": "FIT_AND_CALIBRATION_COMPLETE",
              "dataset_manifest_sha256": dataset.sha256, "code_fingerprint": code, "model_kind": HYBRID_MODEL_KIND,
              "actual_fits_completed": 360, "actual_composite_trials": 360, "actual_component_fit_calls": 720,
              "required_component_fit_calls": 720, "additional_fits_in_recalibration": 0,
              "labeled_training_manifest_sha256_by_fold": {str(fold): labels[fold][3] for fold in (1, 2, 3)}})
        runs = campaign_runs(HYBRID_MODEL_KIND); metadata = None; selected_version = None
        for index, run in enumerate(runs):
            fold = run["fold"]; normal_sha = splits[f"fold{fold}-fit"]["sha256"]
            binding = {"labeled_training_artifact_id": f"labels-fold{fold}", "labeled_training_manifest_sha256": labels[fold][3],
                       "labeled_training_split_sha256": hashlib.sha256(canonical(labels[fold][2]["sections"]).encode()).hexdigest(),
                       "normal_fit_split_sha256": normal_sha, "labeled_training_windows": 81500,
                       "labeled_class_windows": {"0": 71500, "1": 8000, "2": 2000}}
            source_version = f"hybrid_source_fixture_{index:03d}"; version = f"hybrid_cal_fixture_{index:03d}"
            write(source / f"hybrid-models/{source_version}.joblib", b"SOURCE_TEST_BYTES_NOT_A_MODEL")
            write(source / f"hybrid-models/{version}.joblib", b"CALIBRATED_TEST_BYTES_NOT_A_MODEL")
            fit = {"status": "FITTED_CALIBRATED", "dataset_manifest_sha256": dataset.sha256, "code_fingerprint": code,
                   "run_id": run["run_id"], "fold": fold, "config": asdict(run["config"]), "fit_split_sha256": normal_sha,
                   "actual_composite_trials": 1, "actual_component_fit_calls": 2, "additional_fit_calls_in_recalibration": 0,
                   "source_model_version": source_version, "source_model_sha256": sha_file(source / f"hybrid-models/{source_version}.joblib"),
                   "model_version": version, "model_sha256": sha_file(source / f"hybrid-models/{version}.joblib"),
                   "calibration_sha256": "c" * 64, **binding, **recipe_binding(run["config"])}
            write(source / f"hybrid-runs/{run['run_id']}.json", fit)
            write(source / f"hybrid-validations/{run['run_id']}.json", {"status": "VALIDATED", "evaluation_scope": "VALIDATION",
                  "run_id": run["run_id"], "selection_identity": identity, "model_sha256": fit["model_sha256"],
                  "calibration_sha256": fit["calibration_sha256"], "fold": fold, "config": asdict(run["config"]),
                  "dataset_manifest_sha256": dataset.sha256, "validation_split_sha256": "6" * 64,
                  "policies": [], **recipe_binding(run["config"])})
            if index < 45:
                top_version = f"hybrid_top_fixture_{index:03d}"
                receipt = {"selection_identity": identity, "run_id": run["run_id"], "fold": fold, "config": asdict(run["config"]),
                           "source_model_version": source_version, "source_model_sha256": fit["source_model_sha256"],
                           "model_version": top_version, "model_sha256": "b" * 64, "calibration_sha256": "c" * 64,
                           "model_state_sha256": "d" * 64, "model_state_format": HYBRID_FORMAT,
                           "model_state_verifier_sha256": "e" * 64, "additional_fit_calls": 0, **recipe_binding(run["config"])}
                write(source / f"hybrid-top-recalibrations/{run['run_id']}.json", receipt)
                if selected_version is None and fold == 3 and run["config"].random_state == 42:
                    selected_version = top_version
                    metadata = {"calibration_scope": "STRICT", "dataset_manifest_sha256": dataset.sha256, "fold": 3,
                                "training_windows": 50000,
                                "actual_component_fit_counts": {"normal_component_fit_calls": 1, "labeled_component_fit_calls": 1},
                                "scoring_implementation": {"mocked_boundary": True},
                                "labeled_training_scope": "CALLER_VERIFIED_SEPARATE_CHRONOLOGICAL_TRAINING_ONLY",
                                "normal_training_scope": "NORMAL_READY_FIT_ONLY_CALLER_ENFORCED",
                                "data_provenance": "DEMO_ONLY", "confirmed_attack_target_available": False,
                                "model_config": asdict(run["config"]), "score_policy": ScorePolicy.strict(schema=4).wire(),
                                "sha256": "b" * 64, "calibration_sha256": "c" * 64,
                                "model_state_sha256": "d" * 64, "model_state_format": HYBRID_FORMAT,
                                "model_state_verifier_sha256": "e" * 64, **binding, **recipe_binding(run["config"])}
        write(source / f"hybrid-models/{selected_version}.json", metadata)
        write(source / f"hybrid-models/{selected_version}.joblib", b"SELECTED_TEST_BYTES_NOT_A_MODEL")
        metadata["sha256"] = sha_file(source / f"hybrid-models/{selected_version}.joblib")
        write(source / f"hybrid-models/{selected_version}.json", metadata)
        for run in runs[:45]:
            path = source / f"hybrid-top-recalibrations/{run['run_id']}.json"
            import json
            value = json.loads(path.read_bytes())
            if value["model_version"] == selected_version:
                value["model_sha256"] = metadata["sha256"]; write(path, value)
        selected = {"status": "SELECTED", "actual_fits_completed": 360, "validation_runs_completed": 360,
                    "completed_recalibrations": 45, "additional_fit_calls_in_recalibration": 0,
                    "dataset_sha256": dataset.sha256, "model_version": selected_version,
                    "model_sha256": metadata["sha256"], "calibration_sha256": "c" * 64,
                    "model_config": metadata["model_config"], "policy": metadata["score_policy"], "selection_identity": identity,
                    "model_state_sha256": "d" * 64, "model_state_format": HYBRID_FORMAT,
                    "model_state_verifier_sha256": "e" * 64, "scoring_implementation": {"mocked_boundary": True},
                    **model_recipe_binding(metadata)}
        write(source / "hybrid-selection.json", selected)
        return dataset, labels, metadata, selected

    def mocks(self, dataset, labels, metadata):
        stack = ExitStack()
        stack.enter_context(patch("app.package_catalog.fingerprint", return_value={"test_fixture_only": True}))
        stack.enter_context(patch("app.package_catalog.hybrid_fold_training", side_effect=lambda _, fold: labels[fold]))
        stack.enter_context(patch("app.package_catalog.ModelStore.load_candidate", return_value=(metadata, {"model": object()})))
        stack.enter_context(patch("app.package_catalog.ModelStore.scoring_identity", return_value={"mocked_boundary": True}))
        stack.enter_context(patch("app.package_catalog.state_sha256", return_value="d" * 64))
        stack.enter_context(patch("app.package_catalog.state_format", return_value=HYBRID_FORMAT))
        stack.enter_context(patch("app.package_catalog.verifier_sha256", return_value="e" * 64))
        return stack

    def test_verified_future_receipts_produce_typed_id_only_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            dataset, labels, metadata, _ = self.future_receipts(Path(temporary))
            with self.mocks(dataset, labels, metadata):
                entry = recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
            self.assertEqual(entry["mode"], "STRICT"); self.assertEqual(entry["fold"], 3)
            self.assertEqual(entry["config"], metadata["model_config"])
            self.assertEqual(entry["model_state_format"], HYBRID_FORMAT)
            self.assertEqual(entry["labeled_training_artifact_id"], "labels-fold3")
            self.assertEqual(entry["normal_fit_split_sha256"], "3" * 64)
            self.assertFalse(any("path" in key for key in entry))

    def test_missing_and_nonzero_component_evidence_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            dataset, labels, metadata, _ = self.future_receipts(Path(temporary))
            with self.mocks(dataset, labels, metadata):
                path = dataset.root / "hybrid-campaign.progress.json"
                import json
                progress = json.loads(path.read_bytes()); progress["actual_component_fit_calls"] = 360; write(path, progress)
                with self.assertRaisesRegex(ValueError, "360/720"):
                    recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
                progress["actual_component_fit_calls"] = 720; write(path, progress)
                (dataset.root / "hybrid-runs" / (campaign_runs(HYBRID_MODEL_KIND)[0]["run_id"] + ".json")).unlink()
                with self.assertRaises(ValueError): recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)

    def test_boolean_counters_wrong_seed_and_scoped_labels_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            dataset, labels, metadata, selected = self.future_receipts(Path(temporary))
            with self.mocks(dataset, labels, metadata):
                selected["additional_fit_calls_in_recalibration"] = False; write(dataset.root / "hybrid-selection.json", selected)
                with self.assertRaisesRegex(ValueError, "typed hybrid"): recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
                selected["additional_fit_calls_in_recalibration"] = 0; write(dataset.root / "hybrid-selection.json", selected)
                metadata["model_config"]["random_state"] = 43
                with self.assertRaises(ValueError): recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
                metadata["model_config"]["random_state"] = 42
                with patch("app.package_catalog.hybrid_fold_training", side_effect=ValueError("SCOPED_TEST refused")):
                    with self.assertRaisesRegex(ValueError, "SCOPED_TEST"):
                        recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)

    def test_unknown_kind_preview_and_unexpected_receipts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            dataset, labels, metadata, _ = self.future_receipts(Path(temporary))
            with self.assertRaises(ValueError): recipe_entry(dataset, "future-hybrid-recipe", model_kind="unknown")
            with self.assertRaises(ValueError): recipe_entry(dataset, "future-hybrid-recipe", preview=True, model_kind=HYBRID_MODEL_KIND)
            write(dataset.root / "hybrid-validations/unapproved-receipt.json", {})
            with self.mocks(dataset, labels, metadata):
                with self.assertRaisesRegex(ValueError, "approved proof"):
                    recipe_entry(dataset, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)

    def test_private_bundle_copies_all_proofs_and_labels_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); dataset, labels, metadata, _ = self.future_receipts(root)
            destination = root / "catalogue"
            def loaded(directory, expected_sha256):
                import json
                manifest = json.loads((directory / "manifest.private.json").read_bytes())
                self.assertEqual(sha_file(directory / "manifest.private.json"), expected_sha256)
                return [], [], manifest  # Explicitly mocked loader boundary, never full data evidence.
            with self.mocks(dataset, labels, metadata), patch("app.package_catalog.ShardedDataset", return_value=dataset), \
                    patch("app.hybrid_strict_dataset.load_hybrid_strict_fit", side_effect=loaded), \
                    patch("app.frozen_evaluation.verify_hybrid_strict_proof", return_value={"mocked_boundary": True}) as deep_guard:
                entry = package_recipe(dataset.root, destination, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
                deep_guard.assert_called_once(); self.assertIn("proof", deep_guard.call_args.kwargs)
                installed = destination / dataset.manifest["dataset_id"]
                self.assertEqual(len(list((installed / "hybrid-runs").glob("*.json"))), 360)
                self.assertEqual(len(list((installed / "hybrid-validations").glob("*.json"))), 360)
                self.assertEqual(len(list((installed / "hybrid-top-recalibrations").glob("*.json"))), 45)
                self.assertEqual(sha_file(installed / "hybrid-strict-proof.json"), entry["strict_proof_sha256"])
                for fold in (1, 2, 3): self.assertTrue((destination / f"labels-fold{fold}/manifest.private.json").is_file())
                for path in destination.rglob("*"):
                    self.assertFalse(path.is_symlink()); self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
                self.assertEqual(package_recipe(dataset.root, destination, entry["recipe_id"], model_kind=HYBRID_MODEL_KIND), entry)
                write(next((installed / "hybrid-validations").glob("*.json")), {})
                with self.assertRaisesRegex(ValueError, "installed campaign proof"):
                    package_recipe(dataset.root, destination, entry["recipe_id"], model_kind=HYBRID_MODEL_KIND)

    def test_actual_deep_guard_rejects_missing_policy_grid_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); dataset, labels, metadata, _ = self.future_receipts(root)
            destination = root / "must-not-publish"
            with self.mocks(dataset, labels, metadata), patch("app.package_catalog.ShardedDataset", return_value=dataset), \
                    patch("app.frozen_evaluation.fingerprint", return_value={"test_fixture_only": True}), \
                    patch("app.frozen_evaluation.hybrid_fold_training", side_effect=lambda _, fold: labels[fold]), \
                    patch("app.frozen_evaluation.state_sha256", return_value="d" * 64), \
                    patch("app.frozen_evaluation.verifier_sha256", return_value="e" * 64):
                with self.assertRaisesRegex(ValueError, "original192 policies"):
                    package_recipe(dataset.root, destination, "future-hybrid-recipe", model_kind=HYBRID_MODEL_KIND)
            self.assertFalse(destination.exists())

    def test_archived_route_keeps_same_full_proof_and_all_three_private_label_bundles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); dataset, labels, metadata, _ = self.future_receipts(root)
            # Mocked recipe/proof fixture contains no numeric shards. The real
            # small archive reader/copy boundary is exercised in test_package_catalog.
            write(dataset.root / SIDECAR, {'archive_schema_version': 1, 'archive_format': ARCHIVE_FORMAT,
                  'dataset_manifest_sha256': dataset.sha256, 'shards': {}})
            dataset.archive_sha256 = sha_file(dataset.root / SIDECAR); dataset._archive_entries = {}
            destination = root / 'archive-catalogue'
            def view(directory, *, expected_sha256, expected_archive_sha256):
                self.assertEqual(expected_sha256, dataset.sha256)
                self.assertEqual(expected_archive_sha256, dataset.archive_sha256)
                result = copy.copy(dataset); result.root = Path(directory); return result
            def loaded(directory, expected_sha256):
                import json
                self.assertEqual(sha_file(directory / 'manifest.private.json'), expected_sha256)
                return [], [], json.loads((directory / 'manifest.private.json').read_bytes())
            with self.mocks(dataset, labels, metadata), patch('app.package_catalog.open_owned_dataset', side_effect=view), \
                    patch('app.hybrid_strict_dataset.load_hybrid_strict_fit', side_effect=loaded), \
                    patch('app.frozen_evaluation.verify_hybrid_strict_proof', return_value={'mocked_boundary': True}) as guard:
                entry = package_recipe(dataset.root, destination, 'archive-future-hybrid-recipe', model_kind=HYBRID_MODEL_KIND,
                                       expected_sha256=dataset.sha256, expected_archive_sha256=dataset.archive_sha256)
                guard.assert_called_once(); self.assertIn('proof', guard.call_args.kwargs)
                self.assertEqual(entry['archive_sha256'], dataset.archive_sha256)
                installed = destination / dataset.manifest['dataset_id']
                self.assertEqual((installed / 'manifest.json').read_bytes(), (dataset.root / 'manifest.json').read_bytes())
                self.assertEqual((installed / SIDECAR).read_bytes(), (dataset.root / SIDECAR).read_bytes())
                self.assertEqual(sha_file(installed / 'hybrid-strict-proof.json'), entry['strict_proof_sha256'])
                for fold in (1, 2, 3):
                    for name in ('manifest.private.json', 'predeclared.private.json', 'normal/normal-fixture-000000.json',
                                 'supplement/supplement-fixture-000000.json'):
                        self.assertEqual((destination / f'labels-fold{fold}' / name).read_bytes(),
                                         (root / f'labels-fold{fold}' / name).read_bytes())
                self.assertEqual(package_recipe(dataset.root, destination, entry['recipe_id'], model_kind=HYBRID_MODEL_KIND,
                                 expected_sha256=dataset.sha256, expected_archive_sha256=dataset.archive_sha256), entry)


if __name__ == "__main__": unittest.main()
