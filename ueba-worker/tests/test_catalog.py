"""Small catalogue fixtures verify trust boundaries, not benchmark quality."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from app.catalog import ShardedDataset, validate_rows
from app.contract import FEATURE_NAMES_V2
from app.policy import canonical


def row(index=1, cold=False):
    return {"frame_id": f"catalogue-test-frame-{index:06d}", "account_id": f"catalogue-test-account-{index:06d}",
            "window_start": "2026-10-01T00:00:00Z", "label": 0, "family": "normal",
            "cohort": "COLD" if cold else "READY", "baseline_established": not cold,
            "trusted_window_count": 3 if cold else 48,
            "features": [2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]}


def catalogue(root, rows=None):
    rows = rows or [row()]
    (root / "shards").mkdir(exist_ok=True)
    encoded = canonical(rows).encode()
    (root / "shards/holdout-000000.json").write_bytes(encoded)
    shard = {"id": "holdout-000000", "path": "shards/holdout-000000.json",
             "sha256": hashlib.sha256(encoded).hexdigest(), **validate_rows(rows)}
    split = {key: value for key, value in shard.items() if key not in ("id", "path", "sha256")}
    split["shards"] = [shard]
    split["sha256"] = hashlib.sha256(canonical(split).encode()).hexdigest()
    manifest = {"catalog_schema_version": 2, "dataset_id": "catalogue-test-v2b", "stage": "PILOT",
                "feature_schema_version": 2, "telemetry_contract_version": 2,
                "feature_names": list(FEATURE_NAMES_V2), "data_provenance": "DEMO_ONLY", "splits": {"holdout": split}}
    (root / "manifest.json").write_text(canonical(manifest))
    return manifest


class CatalogTest(unittest.TestCase):
    def test_rows_are_verified_and_only_numeric_features_are_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalogue(root, [row(), row(2, True)])
            value = ShardedDataset(root)
            descriptor, rows = next(value.iter_shards("holdout"))
            self.assertEqual(descriptor["records"], 2)
            self.assertEqual(rows[1]["cohort"], "COLD")
            self.assertEqual(ShardedDataset(root, expected_sha256=value.sha256).sha256, value.sha256)
            with self.assertRaises(ValueError): ShardedDataset(root, expected_sha256="0" * 64)

    def test_changed_bytes_cannot_reuse_the_approved_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalogue(root)
            dataset = ShardedDataset(root)
            (root / "shards/holdout-000000.json").write_text(canonical([row(2)]))
            with self.assertRaisesRegex(ValueError, "checksum"): dataset.load_shard("holdout", 0)

    def test_recomputed_file_hash_does_not_make_false_populations_or_raw_fields_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); document = catalogue(root)
            poisoned = row(); poisoned["raw_body"] = "never-persist-this"
            data = canonical([poisoned]).encode()
            (root / "shards/holdout-000000.json").write_bytes(data)
            split = document["splits"]["holdout"]
            split["shards"][0]["sha256"] = hashlib.sha256(data).hexdigest()
            split["sha256"] = hashlib.sha256(canonical({key: value for key, value in split.items() if key != "sha256"}).encode()).hexdigest()
            (root / "manifest.json").write_text(canonical(document))
            with self.assertRaisesRegex(ValueError, "contract"): ShardedDataset(root).load_shard("holdout", 0)

    def test_symlinks_and_traversal_are_not_catalogue_resources(self):
        for attack in ("symlink", "traversal"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); document = catalogue(root)
                if attack == "symlink":
                    target = root / "external.json"; target.write_text(canonical([row()]))
                    path = root / "shards/holdout-000000.json"; path.unlink(); path.symlink_to(target)
                    with self.assertRaises(ValueError): ShardedDataset(root).load_shard("holdout", 0)
                else:
                    split = document["splits"]["holdout"]; split["shards"][0]["path"] = "../external.json"
                    split["sha256"] = hashlib.sha256(canonical({key: value for key, value in split.items() if key != "sha256"}).encode()).hexdigest()
                    (root / "manifest.json").write_text(canonical(document))
                    with self.assertRaises(ValueError): ShardedDataset(root)

    def test_actual_cohort_bounds_rates_and_primary_episode_are_not_optional(self):
        for field, value in (("baseline_established", False), ("trusted_window_count", 29), ("label", True),
                             ("window_start", "2026-10-01T00:00:00+07:00"), ("cohort", "MADE_UP")):
            with self.subTest(field=field):
                invalid = row(); invalid[field] = value
                with self.assertRaises(ValueError): validate_rows([invalid])
        duplicated = row(2); duplicated["account_id"] = row()["account_id"]
        duplicated["window_start"] = "2026-10-01T00:15:00Z"
        with self.assertRaisesRegex(ValueError, "episode"): validate_rows([row(), duplicated])
        invalid = row(2, True); invalid["features"][11] = 1
        with self.assertRaisesRegex(ValueError, "personalized"): validate_rows([invalid])

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); catalogue(root)
            path = root / "manifest.json"
            path.write_text('{"stage":"PILOT","stage":"STRICT"}')
            with self.assertRaisesRegex(ValueError, "duplicate"): ShardedDataset(root)
            path.write_text('{"stage":NaN}')
            with self.assertRaisesRegex(ValueError, "non-finite"): ShardedDataset(root)

    def test_malformed_types_fail_as_contract_errors_not_unhandled_exceptions(self):
        for field in ("frame_id", "account_id", "window_start", "label", "family", "cohort",
                      "baseline_established", "trusted_window_count", "features"):
            for value in (None, {}, ["wrong-type"]):
                with self.subTest(field=field, value=value):
                    invalid = row(); invalid[field] = value
                    with self.assertRaises(ValueError): validate_rows([invalid])


if __name__ == "__main__": unittest.main()
