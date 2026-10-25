"""Opaque JVM descriptor fixtures only; no class execution, model fit or scoring."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.contract import HYBRID_MODEL_KIND
from app.policy import canonical
from app.risk_replay import CLASS_FILES
from app.selection import producer_class_binding, selection_identity


class ProducerSnapshotSelectionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.classes = self.workspace / "backend/target/classes/com/flarefitness/backend"
        names = set(CLASS_FILES) | {"ops/UebaFeatureExport.class", "service/siem/AccountBaselinePolicy.class",
            "service/siem/AccountBehaviorFeatures.class", "service/siem/AccountRiskEngine.class", "service/siem/SecurityEventNormalizer.class",
            "service/siem/ContextualBehaviorFeatures.class", "service/siem/SessionEndpointBehaviorFeatures.class", "service/siem/EndpointCategory.class"}
        self.mapping = {}
        for name in names:
            path = self.classes / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = b"OPAQUE-NOT-JVM-BYTECODE:" + name.encode(); path.write_bytes(raw); path.chmod(0o600)
            self.mapping[name] = hashlib.sha256(raw).hexdigest()
        self.snapshot = {"classes": self.mapping, "jars": {"0001-fixture.jar": "c" * 64}}
        self.path = self.workspace / "snapshot.json"; self.write_snapshot()
        self.dataset = SimpleNamespace(sha256="a" * 64, manifest={"stage": "STRICT", "feature_schema_version": 4,
            "workspace_snapshot_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()})
        self.original = deepcopy(self.dataset.manifest)

    def write_snapshot(self):
        self.path.write_text(canonical(self.snapshot)); self.path.chmod(0o600)

    def identity(self):
        with patch("app.selection.fingerprint", return_value={"fixture": "no-fit"}), \
                patch("app.selection.validate_candidate", side_effect=AssertionError("no scoring")):
            return selection_identity(self.dataset, self.workspace, HYBRID_MODEL_KIND)

    def test_actual_producer_shape_derives_hash_pinned_classes_without_manifest_rewrite(self):
        result = self.identity()
        self.assertEqual(result["producer_workspace_snapshot_sha256"], self.dataset.manifest["workspace_snapshot_sha256"])
        self.assertEqual(result["production_classes"], {name: self.mapping[name] for name in CLASS_FILES})
        self.assertEqual(result["feature_producers"]["service/siem/SessionEndpointBehaviorFeatures.class"],
                         self.mapping["service/siem/SessionEndpointBehaviorFeatures.class"])
        self.assertIn("selection.py", result["selection_sources"])
        self.assertEqual(self.dataset.manifest, self.original)
        self.assertNotIn("compiled_feature_sha256", self.dataset.manifest)

    def test_existing_compiled_map_path_keeps_identity_without_snapshot_provenance(self):
        self.dataset.manifest["compiled_feature_sha256"] = self.mapping
        self.path.unlink()  # Private temporary descriptor fixture only.
        result = self.identity()
        self.assertNotIn("producer_workspace_snapshot_sha256", result)
        self.assertEqual(result["production_classes"], {name: self.mapping[name] for name in CLASS_FILES})

    def test_missing_wrong_or_changed_snapshot_pin_refuses_before_class_read_or_scoring(self):
        for value in (None, True, "0" * 64):
            self.dataset.manifest["workspace_snapshot_sha256"] = value
            with patch("app.selection.class_binding", side_effect=AssertionError("reject before class read")), self.assertRaises(ValueError):
                self.identity()
        self.dataset.manifest = deepcopy(self.original); self.path.write_bytes(self.path.read_bytes() + b"\n")
        with patch("app.selection.class_binding", side_effect=AssertionError("reject before class read")), self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.identity()

    def test_changed_production_or_feature_class_is_not_laundered_by_snapshot_descriptor(self):
        for name in ("service/siem/AccountRiskEngine.class", "service/siem/SessionEndpointBehaviorFeatures.class"):
            path = self.classes / name; saved = path.read_bytes(); path.write_bytes(b"CHANGED-OPAQUE-CLASS")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "differs"):
                self.identity()
            path.write_bytes(saved)

    def test_symlink_public_or_foreign_snapshot_descriptor_refuses(self):
        with patch("app.selection.os.geteuid", return_value=os.geteuid() + 1), self.assertRaisesRegex(ValueError, "owner-controlled"):
            self.identity()
        self.path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "owner-controlled"): self.identity()
        self.path.chmod(0o600); saved = self.workspace / "saved-snapshot.json"; self.path.rename(saved); self.path.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "canonical"): self.identity()
        self.path.unlink(); saved.rename(self.path)  # Private temporary descriptor fixture only.
        name = "service/siem/AccountRiskEngine.class"; path = self.classes / name; saved = path.with_suffix(".saved")
        path.rename(saved); path.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"): self.identity()

    def test_typed_relative_descriptor_and_class_count_bounds_remain_closed(self):
        for classes in ({"../outside.class": "f" * 64}, {"Valid.class": True},
                        {f"Fixture{index}.class": "f" * 64 for index in range(4097)}):
            self.snapshot["classes"] = classes; self.write_snapshot()
            self.dataset.manifest["workspace_snapshot_sha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()
            with self.subTest(count=len(classes)), self.assertRaises(ValueError):
                producer_class_binding(self.dataset, self.workspace)


if __name__ == "__main__": unittest.main()
