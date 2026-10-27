from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import auth_context_research_classpath as helper


class ClasspathPreparationTest(unittest.TestCase):
    def test_rejects_archive_traversal_symlink_and_duplicate(self):
        for name in ('../escape', '/absolute', 'BOOT-INF/classes/../../outside',
                     'BOOT-INF/classes/a\\b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                helper.archive_target(zipfile.ZipInfo(name))
        info = zipfile.ZipInfo('BOOT-INF/classes/link')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            helper.archive_target(info)
        oversized = zipfile.ZipInfo('BOOT-INF/classes/huge.class')
        oversized.file_size = helper.MAX_ENTRY + 1
        with self.assertRaises(ValueError):
            helper.archive_target(oversized)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = root / 'bad.jar'
            with zipfile.ZipFile(jar, 'w') as z:
                z.writestr('BOOT-INF/classes/thing.class', b'one')
                z.writestr('BOOT-INF/classes/thing.class', b'two')
            with patch.object(helper, 'guard'), self.assertRaisesRegex(ValueError, 'duplicate'):
                helper.extract(jar, root / 'out', root, time.monotonic())

    def test_extract_only_expected_content(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jar = root / 'app.jar'
            with zipfile.ZipFile(jar, 'w') as z:
                z.writestr('BOOT-INF/classes/example/A.class', b'class')
                z.writestr('BOOT-INF/lib/one.jar', b'library')
                z.writestr('META-INF/ignored', b'ignored')
            with patch.object(helper, 'guard'):
                helper.extract(jar, root / 'out', root, time.monotonic())
            self.assertEqual((root / 'out/classes/example/A.class').read_bytes(), b'class')
            self.assertEqual((root / 'out/lib/one.jar').read_bytes(), b'library')
            self.assertFalse((root / 'out/META-INF').exists())

    def test_classpath_retains_application_jar_for_parity_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'lib').mkdir()
            (root / 'lib' / 'one.jar').write_bytes(b'library')
            self.assertEqual(helper.classpath_entries(root)[-1], root / 'app.jar')
            self.assertIn(root / 'lib' / 'one.jar', helper.classpath_entries(root))

    def test_private_job_creation_refuses_reuse_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'research'
            with patch.object(helper, 'RESEARCH_ROOT', root):
                job = root / 'one'
                helper.init_job(job)
                self.assertEqual(job.stat().st_mode & 0o777, 0o700)
                with self.assertRaises(FileExistsError):
                    helper.init_job(job)
                with self.assertRaises(ValueError):
                    helper.init_job(root / '..' / 'escape')
                (root / 'alias').symlink_to(job, target_is_directory=True)
                with self.assertRaises(ValueError):
                    helper.init_job(root / 'alias')

    def test_low_memory_refuses_before_any_docker_or_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'research'
            root.mkdir(mode=0o700)
            job = root / 'one'
            job.mkdir(mode=0o700)
            with patch.object(helper, 'RESEARCH_ROOT', root), \
                    patch.object(helper, 'resource_check', side_effect=RuntimeError('STOP_RESOURCE')), \
                    patch.object(helper.subprocess, 'Popen') as process:
                with self.assertRaisesRegex(RuntimeError, 'STOP_RESOURCE'):
                    helper.prepare(job)
                process.assert_not_called()
                self.assertEqual(list(job.iterdir()), [])

    def test_existing_marker_refuses_before_resource_or_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'research'
            root.mkdir(mode=0o700)
            job = root / 'one'
            job.mkdir(mode=0o700)
            (job / 'classpath-prepare.log').write_text('already used')
            with patch.object(helper, 'RESEARCH_ROOT', root), \
                    patch.object(helper, 'resource_check') as guard, \
                    patch.object(helper.subprocess, 'Popen') as process:
                with self.assertRaisesRegex(ValueError, 'marker'):
                    helper.prepare(job)
                guard.assert_not_called()
                process.assert_not_called()

    def test_resource_stop_targets_only_named_compiler(self):
        process = MagicMock()
        process.poll.return_value = None
        with patch.object(helper.subprocess, 'Popen', return_value=process), \
                patch.object(helper.subprocess, 'run') as run, \
                patch.object(helper, 'guard', side_effect=RuntimeError('STOP_RESOURCE')):
            with self.assertRaisesRegex(RuntimeError, 'STOP_RESOURCE'):
                helper.command(['docker', 'run'], Path('/tmp'), time.monotonic(),
                               MagicMock(), container='auth-compiler-private')
        self.assertEqual(run.call_args.args[0], ['docker', 'kill', 'auth-compiler-private'])
        process.kill.assert_called_once()


if __name__ == '__main__':
    unittest.main()
