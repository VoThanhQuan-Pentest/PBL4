import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from app.holdout_provenance import MARKER, holdout_audit_resources, require_unblocked_holdout


def audit():
    return {'audit_schema_version': 1, 'status': 'BLOCKED', 'dataset_id': 'owned-source-test',
            'affected_split': 'holdout', 'reason': 'INDETERMINATE_HOLDOUT_EXPOSURE',
            'acceptance_allowed': False, 'audit_id': 'owned-audit-test', 'recorded_at_utc': '2026-10-05T03:47:40Z'}


class HoldoutProvenanceTest(unittest.TestCase):
    def test_known_blocked_registry_pin_cannot_be_bypassed_by_marker_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, 'private audit pin'):
                require_unblocked_holdout(root, 'a' * 64)
            with self.assertRaisesRegex(ValueError, 'invalid private'):
                require_unblocked_holdout(root, 'bad')
            require_unblocked_holdout(root, None)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name); self.root = self.parent / 'standard'; self.root.mkdir(mode=0o700)
    def marker(self, directory=None, value=None):
        path = (directory or self.parent) / MARKER
        path.write_text(json.dumps(value if value is not None else audit())); path.chmod(0o600)
        return path
    def test_absence_preserves_legacy_and_exact_parent_or_root_marker_blocks(self):
        require_unblocked_holdout(self.root)
        path = self.marker(); raw = path.read_bytes()
        self.assertEqual(holdout_audit_resources(SimpleNamespace(root=self.root)), ((path, raw),))
        with self.assertRaisesRegex(ValueError, 'BLOCKED'): require_unblocked_holdout(self.root)
        path.unlink(); self.marker(self.root)
        with self.assertRaisesRegex(ValueError, 'BLOCKED'): require_unblocked_holdout(self.root)
    def test_malformed_unknown_or_attempted_clear_status_fails_closed(self):
        path = self.marker()
        for value in (audit() | {'status': 'UNBLOCKED'}, audit() | {'acceptance_allowed': True},
                      audit() | {'audit_schema_version': True}, audit() | {'extra': 1}):
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): require_unblocked_holdout(self.root)
        for raw in ('not json', '{"status":"BLOCKED","status":"UNBLOCKED"}', '{"x":NaN}'):
            path.write_text(raw)
            with self.assertRaises(ValueError): require_unblocked_holdout(self.root)
    def test_dangling_symlink_public_or_hardlinked_marker_never_disappears(self):
        path = self.parent / MARKER; path.symlink_to(self.parent / 'missing')
        with self.assertRaises(ValueError): require_unblocked_holdout(self.root)
        path.unlink(); path = self.marker(); path.chmod(0o644)
        with self.assertRaises(ValueError): require_unblocked_holdout(self.root)
        path.chmod(0o600)
        import os
        os.link(path, self.parent / 'alias')
        with self.assertRaises(ValueError): require_unblocked_holdout(self.root)


if __name__ == '__main__': unittest.main()
