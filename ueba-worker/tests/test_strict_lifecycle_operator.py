"""Tests for the private byte-preserving lifecycle resume coordinator."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "observability/scripts/strict-lifecycle-operator.py"
SPEC = importlib.util.spec_from_file_location("strict_lifecycle_operator_under_test", SCRIPT)
OP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OP)


def base_state(*, batches=None, cursor=0, required=600):
    result = {
        "schema_version": 1,
        "scope": "NEW_STRICT_SOURCE_BYTE_PRESERVING_BATCH_RETIREMENT",
        "source_standard": "/private/source/standard",
        "campaign_bindings_file": "/private/checkpoint.json",
        "observer_container_id": "a" * 64,
        "proxy_socket_directory": "/private/proxy",
        "observer_code_sha256": "b" * 64,
        "retirement_code_sha256": "c" * 64,
        "archive_result_sha256": "d" * 64,
        "image_id": OP.IMAGE,
        "scratch_directory": "/private/scratch",
        "required_non_fit_manifest_targets": required,
        "next_target_start": cursor,
        "fit_source_retained": True,
        "archives_models_labels_metadata_retained": True,
        "old_holdout_acceptance_allowed": False,
        "unit_025_approval_prepared_not_launched": True,
        "aws_changed": False,
        "resume_rule": "Inspect before advancing.",
    }
    for index, target_start, target_count in (batches or []):
        result[f"batch_{index:04d}"] = {
            "target_start": target_start,
            "target_count": target_count,
            "approval_sha256": "1" * 64,
            "checkpoint_sha256": "2" * 64,
            "container_id": "3" * 64,
            "status": "SUCCEEDED",
            "original_aliases_deleted": target_count * 3,
            "original_bytes_retired": target_count * 100,
            "numeric_rows_parsed": 0,
        }
    return result


class StrictLifecycleOperatorTest(unittest.TestCase):
    def test_next_batch_uses_contiguous_manifest_cursor(self):
        state = base_state(batches=[(0, 0, 256), (1, 256, 44)], cursor=300, required=600)
        self.assertEqual((2, 300, 256), OP.next_batch(state))

    def test_next_batch_uses_short_final_range(self):
        state = base_state(batches=[(0, 0, 256), (1, 256, 256)], cursor=512, required=600)
        self.assertEqual((2, 512, 88), OP.next_batch(state))

    def test_next_batch_rejects_gap_or_cursor_drift(self):
        with self.assertRaises(ValueError):
            OP.next_batch(base_state(batches=[(1, 256, 256)], cursor=512))
        with self.assertRaises(ValueError):
            OP.next_batch(base_state(batches=[(0, 0, 256)], cursor=300))

    def test_next_batch_rejects_unsafe_flags_and_unknown_members(self):
        state = base_state()
        state["aws_changed"] = True
        with self.assertRaises(ValueError):
            OP.next_batch(state)
        state = base_state()
        state["unrecognized"] = True
        with self.assertRaises(ValueError):
            OP.next_batch(state)

    def test_next_batch_accepts_explicit_exec_provenance_only(self):
        state = base_state(batches=[(0, 0, 256)], cursor=256)
        state["batch_0000"]["execution_kind"] = "DOCKER_EXEC_IN_METADATA_OBSERVER"
        self.assertEqual((1, 256, 256), OP.next_batch(state))
        state["batch_0000"]["execution_kind"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            OP.next_batch(state)

    def test_expected_targets_use_exact_two_link_manifest_pair(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "standard"
            (source / "verification").mkdir(parents=True)
            source.chmod(0o700)
            (source / "verification").chmod(0o700)
            manifest = {
                "splits": {
                    "fold1-fit": {"shards": [{"id": "fit-000"}]},
                    "fold1-validation": {"shards": [{"id": "validation-001"}]},
                    "holdout": {"shards": [{"id": "holdout-002"}]},
                }
            }
            primary = source / "manifest.json"
            mirror = source / "verification/manifest.json"
            primary.write_text(json.dumps(manifest))
            primary.chmod(0o600)
            os.link(primary, mirror)
            OP.SOURCE = source
            expected = OP.expected_targets({"targets": [
                {"projection": "shards/holdout-002.json"},
                {"projection": "shards/validation-001.json"},
            ]}, 0, 2)
            self.assertEqual(2, len(expected))


if __name__ == "__main__":
    unittest.main()
