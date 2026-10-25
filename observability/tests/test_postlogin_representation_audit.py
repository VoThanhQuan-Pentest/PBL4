import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from ueba_research_artifacts import commit, digest, private_directory, publish

spec = importlib.util.spec_from_file_location("postlogin_audit", SCRIPTS / "audit-ueba-postlogin-representation.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PostloginRepresentationAuditTest(unittest.TestCase):
    def test_fixture_labels_intent_and_session_assignment_stay_outside_transport(self):
        pairs = audit.pairs()
        self.assertEqual(len(pairs), 12)
        for name, _, left, right in pairs:
            for side, value in (("left", left), ("right", right)):
                for frame in audit.frame(name, side, value):
                    self.assertNotIn("semantics", frame)
                    for event in frame["events"]:
                        self.assertFalse(set(event) & {"label", "intent", "fixture_id", "token", "jti", "session_verified"})
                        if event["event_type"] != "HTTP_REQUEST":
                            self.assertNotIn("session_pseudonym", event)
                        else:
                            self.assertEqual(event["route_group"], "profile")
        _, _, legitimate, hidden = pairs[-1]
        self.assertEqual(legitimate["events"], hidden["events"])
        self.assertNotEqual(legitimate["label"], hidden["label"])

    def test_frames_stay_inside_their_own_window_and_history_precedes_evaluation(self):
        from datetime import datetime, timedelta
        for name, _, left, right in audit.pairs():
            for side, value in (("left", left), ("right", right)):
                frames = audit.frame(name, side, value)
                previous = None
                for frame in frames:
                    start = datetime.fromisoformat(frame["window_start"].replace("Z", "+00:00"))
                    if previous is not None:
                        self.assertLess(previous, start)
                    previous = start
                    self.assertLessEqual(len(frame["account_id"]), 64)
                    for event in frame["events"]:
                        at = datetime.fromisoformat(event["event_timestamp"].replace("Z", "+00:00"))
                        self.assertLessEqual(start, at)
                        self.assertLess(at, start + timedelta(minutes=15))

    def test_commit_is_idempotent_and_detects_receipt_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            first = commit(path, {"counts": 12}, phase="p1")
            self.assertEqual(commit(path, {"counts": 12}, phase="p1"), first)
            self.assertEqual(digest(path / first["receipt"]), first["receipt_sha256"])
            with self.assertRaises(ValueError):
                commit(path, {"counts": 13}, phase="p1")
            (path / first["receipt"]).write_text('{}')
            with self.assertRaisesRegex(ValueError, "changed"):
                commit(path, {"counts": 12}, phase="p1")

    def test_private_publication_refuses_symlink_and_over_cap_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "alias").symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                private_directory(root / "alias")
            publish(root / "receipt.json", {"good": True})
            previous = (root / "receipt.json").read_bytes()
            with self.assertRaises(ValueError):
                publish(root / "receipt.json", {"oversized": "x" * 100}, maximum=10)
            self.assertEqual((root / "receipt.json").read_bytes(), previous)
            self.assertEqual((root / "receipt.json").stat().st_mode & 0o777, 0o600)

    def test_failed_prepublication_fsync_preserves_previous_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            publish(path, {"committed": 1})
            with patch("ueba_research_artifacts.os.fsync", side_effect=OSError("fixture interruption")):
                with self.assertRaises(OSError):
                    publish(path, {"committed": 2})
            self.assertEqual(json.loads(path.read_text()), {"committed": 1})
            self.assertEqual(list(Path(directory).glob(".pending-*")), [])


if __name__ == "__main__":
    unittest.main()
