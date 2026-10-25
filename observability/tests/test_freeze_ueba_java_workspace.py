import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/freeze-ueba-java-workspace.py'
SPEC = importlib.util.spec_from_file_location('private_java_workspace_test', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)


class FreezeJavaWorkspaceTest(unittest.TestCase):
    def fixture(self, root):
        source = root / 'source'; source.mkdir(mode=0o700)
        files = {'backend/target/classes/com/flarefitness/backend/ops/Test.class': b'declared-class-fixture',
                 'jars/0000-test.jar': b'declared-jar-fixture'}
        for relative, body in files.items():
            path = source / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body); path.chmod(0o664)
        snapshot = {'classes': {'ops/Test.class': hashlib.sha256(files[next(iter(files))]).hexdigest()},
                    'jars': {'0000-test.jar': hashlib.sha256(files['jars/0000-test.jar']).hexdigest()}}
        body = MODULE.canonical(snapshot).encode(); (source / 'snapshot.json').write_bytes(body); (source / 'snapshot.json').chmod(0o664)
        (source / 'unrelated.properties').write_text('must-not-be-copied')
        return source, hashlib.sha256(body).hexdigest()

    def test_declared_byte_only_copy_private_modes_and_absolute_derived_classpath(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, sha = self.fixture(root)
            receipt = MODULE.freeze_workspace(source, root, sha)
            destination = Path(receipt['workspace']); self.assertEqual(receipt['declared_file_count'], 3)
            self.assertFalse((destination / 'unrelated.properties').exists())
            for name in receipt['files']:
                self.assertEqual((source / name).read_bytes(), (destination / name).read_bytes())
                self.assertEqual((source / name).stat().st_mode & 0o777, 0o664)
            for path in (destination, *destination.rglob('*')):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            classpath = (destination / 'backend/target/ueba-experiment.classpath').read_bytes()
            self.assertEqual(classpath.decode(), str(destination / 'jars/0000-test.jar'))
            self.assertEqual(hashlib.sha256(classpath).hexdigest(), receipt['derived_classpath_sha256'])
            self.assertTrue(receipt['source_bytes_and_modes_unchanged']); self.assertEqual(receipt['numeric_resources_read'], 0)

    def test_bad_snapshot_hash_corrupt_declared_file_and_symlink_fail_before_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, sha = self.fixture(root)
            with self.assertRaises(ValueError): MODULE.freeze_workspace(source, root, '0' * 64)
            jar = source / 'jars/0000-test.jar'; jar.write_bytes(b'changed')
            with self.assertRaises(ValueError): MODULE.freeze_workspace(source, root, sha)
            jar.unlink(); jar.symlink_to(source / 'unrelated.properties')
            with self.assertRaises(ValueError): MODULE.freeze_workspace(source, root, sha)
            self.assertEqual(list(root.glob('hybrid-execution-java-*')), [])


if __name__ == '__main__': unittest.main()
