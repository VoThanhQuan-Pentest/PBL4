"""Resource and split isolation tests; no Docker execution or model fitting."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts/auth_context_research_runner.py'
spec = importlib.util.spec_from_file_location('research_runner', MODULE)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.job = self.root / 'job'
        self.job.mkdir(mode=0o700)
        self.corpus = self.job / 'corpus'
        self.corpus.mkdir(mode=0o700)
        (self.job / 'result').mkdir(mode=0o700)
        for filename in runner.METADATA + tuple(set(sum(runner.SPLITS.values(), ()))):
            (self.corpus / filename).write_bytes(b'fixture')
        self.root_patch = patch.object(runner, 'RESEARCH_ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_selection_cannot_mount_evaluation_or_controls(self):
        with patch.object(runner, 'verify_models'):
            command = runner.container_command('select', self.job, None, None, 'auth-research-fixture')
        mounts = ' '.join(command)
        self.assertIn('train.jsonl.gz', mounts)
        self.assertIn('development.jsonl.gz', mounts)
        self.assertNotIn('evaluation.jsonl.gz', mounts)
        self.assertNotIn('controls.jsonl.gz', mounts)
        self.assertIn('--network none', mounts)
        self.assertIn('--read-only', mounts)
        self.assertIn('dst=/run/model,readonly', mounts)
        self.assertIn('dst=/run/auth-shadow,readonly', mounts)

    def test_evaluation_cannot_mount_train_or_development(self):
        with patch.object(runner, 'verify_models'):
            command = runner.container_command('evaluate', self.job, None, None, 'auth-research-fixture')
        mounts = ' '.join(command)
        self.assertIn('evaluation.jsonl.gz', mounts)
        self.assertIn('controls.jsonl.gz', mounts)
        self.assertNotIn('train.jsonl.gz', mounts)
        self.assertNotIn('development.jsonl.gz', mounts)

    def test_benchmark_uses_smaller_cgroup_and_only_evaluation(self):
        with patch.object(runner, 'verify_models'):
            command = runner.container_command('benchmark', self.job, None, None, 'auth-research-fixture')
        mounts = ' '.join(command)
        self.assertIn('--memory 512m --cpus 1', mounts)
        self.assertIn('evaluation.jsonl.gz', mounts)
        self.assertNotIn('controls.jsonl.gz', mounts)
        self.assertNotIn('train.jsonl.gz', mounts)

    def test_low_memory_refuses_before_docker_or_log_creation(self):
        with patch.object(runner, 'available_memory', return_value=2 * 1024**3), \
             patch.object(runner.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'STOP_RESOURCE'):
                runner.run('select', self.job)
        popen.assert_not_called()
        self.assertFalse((self.job / 'select-supervisor.log').exists())

    def test_hung_fit_deadline_does_not_reset_between_polls(self):
        result = self.job / 'result'
        (result / 'A-42-fit-reserved.json').write_text('{}')
        seen = {}
        runner.check_fit_deadlines(result, seen, 10)
        with self.assertRaisesRegex(RuntimeError, 'fit deadline'):
            runner.check_fit_deadlines(result, seen, 10 + runner.FIT_SECONDS + 1)
        (result / 'A-42-state.json').write_text('{}')
        runner.check_fit_deadlines(result, seen, 10 + runner.FIT_SECONDS + 1)

    def test_classpath_receipt_binds_jar_and_harness_bytes(self):
        folder = self.job / 'classpath'; folder.mkdir()
        harness = folder / 'harness'; harness.mkdir()
        classes = folder / 'classes'; classes.mkdir()
        libraries = folder / 'lib'; libraries.mkdir()
        library = libraries / 'one.jar'; library.write_bytes(b'library')
        (classes / 'Producer.class').write_bytes(b'producer')
        compiled = harness / 'com/flarefitness/backend/ops/AuthShadowLabCaptureServer.class'
        compiled.parent.mkdir(parents=True); compiled.write_bytes(b'class')
        source = folder / 'AuthShadowLabCaptureServer.java'; source.write_bytes(b'source')
        jar = folder / 'app.jar'; jar.write_bytes(b'jar')
        path = os.pathsep.join(map(str, (harness, classes, library, jar)))
        sha = lambda value: hashlib.sha256(value).hexdigest()
        receipt = {'status': 'CLASSPATH_PREPARED', 'app_image': runner.PRODUCER_IMAGE,
                   'commit': '60b505998f5e64cc8cff75f38dafcd1563de8929', 'classpath': path,
                   'jdk_image': runner.JDK_IMAGE, 'jdk_major': 21,
                   'preparer_sha256': runner.file_sha(runner.ROOT / 'observability/scripts/auth_context_research_classpath.py', 1024 * 1024),
                   'application_jar_sha256': sha(b'jar'), 'harness_source_sha256': sha(b'source'),
                   'harness_class_sha256': sha(b'class'),
                   'libraries': [{'name': 'one.jar', 'sha256': sha(b'library')}], 'application_class_files': 1,
                   'application_classes_sha256': sha(json.dumps([('Producer.class', sha(b'producer'))],
                                                                   separators=(',', ':')).encode())}
        (self.job / 'classpath-receipt.json').write_text(json.dumps(receipt))
        runner.verify_classpath(self.job, path, sha(b'jar'))
        jar.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'jar checksum'):
            runner.verify_classpath(self.job, path, sha(b'jar'))

    def test_symlink_or_external_path_is_rejected(self):
        (self.root / 'link').symlink_to(self.job, target_is_directory=True)
        for path in (self.root / 'link', Path('/tmp/external'), self.job / '..' / '..' / 'escape'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.safe_path(path, self.root)


if __name__ == '__main__':
    unittest.main()
