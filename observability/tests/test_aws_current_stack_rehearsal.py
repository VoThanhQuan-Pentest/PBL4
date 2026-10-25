"""Non-Docker fail-closed controls; these fixtures are not AWS acceptance evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/rehearse-aws-current-stack.py'
SPEC = importlib.util.spec_from_file_location('aws_current_stack_rehearsal', SCRIPT)
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)


class CurrentStackControls(unittest.TestCase):
    def test_commands_never_publish_ports_or_run_privileged(self):
        command = rehearsal.fixture_command('owned-app', 'owned-network', 'nonce', 'sha256:' + 'a' * 64)
        self.assertIn('--pull=never', command)
        self.assertIn('--read-only', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--security-opt=no-new-privileges', command)
        self.assertNotIn('--privileged', command)
        self.assertFalse(any(value in command for value in ('-p', '--publish', '--publish-all', '-P')))

    def test_real_worker_alone_owns_ueba_alias(self):
        command = rehearsal.redis_command('redis', 'network', 'nonce', Path('/private/redis.env'))
        self.assertNotIn('ueba-worker', command)
        self.assertIn('redis', command)
        self.assertIn('flare.scope=' + rehearsal.SCOPE, command)
        self.assertIn('flare.rehearsal=nonce', command)

    def test_mutable_images_rejected_before_docker(self):
        with patch.object(rehearsal.legacy, 'inspect_image') as inspect:
            with self.assertRaises(ValueError):
                rehearsal.immutable_image('current-app:latest', 'app')
        inspect.assert_not_called()

    def test_image_flyway_override_rejected(self):
        identity = 'sha256:' + 'a' * 64
        state = {'Id': identity, 'Config': {'Env': ['SPRING_FLYWAY_VALIDATE_ON_MIGRATE=false']}}
        with patch.object(rehearsal.legacy, 'inspect_image', return_value=state):
            with self.assertRaises(ValueError):
                rehearsal.immutable_image(identity, 'app')

    def test_external_network_rejected(self):
        state = {'Internal': False, 'Driver': 'bridge', 'Labels': {'flare.scope': rehearsal.SCOPE, 'flare.rehearsal': 'nonce'}}
        result = subprocess.CompletedProcess([], 0, json.dumps([state]).encode(), b'')
        with patch.object(rehearsal, 'run', return_value=result):
            with self.assertRaises(ValueError):
                rehearsal.owned_network('network', 'nonce')

    def test_foreign_fixture_never_removed(self):
        state = {'Config': {'Labels': {'flare.scope': 'production', 'flare.rehearsal': 'nonce'}}}
        result = subprocess.CompletedProcess([], 0, json.dumps([state]).encode(), b'')
        with patch.object(rehearsal, 'run', return_value=result) as run:
            self.assertFalse(rehearsal.cleanup(['foreign'], None, 'nonce'))
        self.assertFalse(any(call.args[0][:2] == ['docker', 'rm'] for call in run.call_args_list))

    def test_java_namespace_cleanup_requires_exact_owned_database(self):
        state = {'Config': {'Labels': {'flare.scope': rehearsal.SCOPE, 'flare.rehearsal': 'nonce'}},
                 'HostConfig': {'NetworkMode': 'container:foreign-id', 'PortBindings': {}}}
        result = subprocess.CompletedProcess([], 0, json.dumps([state]).encode(), b'')
        with patch.object(rehearsal, 'run', return_value=result) as run, \
                patch.object(rehearsal, 'owned_container', side_effect=ValueError('foreign target')):
            self.assertFalse(rehearsal.cleanup(['flare-local-current-java-nonce'], None, 'nonce'))
        self.assertFalse(any(call.args[0][:2] == ['docker', 'rm'] for call in run.call_args_list))

    def test_packaged_jar_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / 'unsafe.jar'
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr('BOOT-INF/classes/../../../escape', b'unsafe')
            with self.assertRaises(ValueError):
                rehearsal.expand_jar(jar, root / 'expanded')
            self.assertFalse((root / 'escape').exists())

    def test_packaged_jar_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar = root / 'duplicate.jar'
            with zipfile.ZipFile(jar, 'w') as archive:
                archive.writestr('BOOT-INF/classes/same', b'one')
                with self.assertWarns(UserWarning):
                    archive.writestr('BOOT-INF/classes/same', b'two')
            with self.assertRaises(ValueError):
                rehearsal.expand_jar(jar, root / 'expanded')

    def test_existing_services_selected_fields_never_capture_env(self):
        state = {'id': 'id', 'image': 'image', 'running': True, 'started_at': 'time', 'restart_count': 0}
        result = subprocess.CompletedProcess([], 0, json.dumps(state).encode(), b'')
        with patch.object(rehearsal, 'run', return_value=result) as run:
            self.assertEqual(rehearsal.service_state('id'), state)
        template = run.call_args.args[0][-2]
        self.assertNotIn('.Config', template)
        self.assertNotIn('.Env', template)

    def test_existing_services_scope_excludes_concurrent_disposable_tests(self):
        result = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(rehearsal, 'run', return_value=result) as run:
            self.assertEqual(rehearsal.existing_services(), {})
        self.assertIn('label=com.docker.compose.project=flare-local-elk', run.call_args.args[0])
        self.assertIn('name=flare-local-elk-', run.call_args.args[0])

    def test_dependency_lock_rejects_unpinned_or_ambiguous_names(self):
        for body in ('numpy>=2', 'foo==1\nfoo==2', 'pydantic_core==1\npydantic-core==1', '', '-r /private/file'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                rehearsal.dependency_pins(body)
        self.assertEqual(rehearsal.dependency_pins('# locked\nnumpy==2.5.3\n'), {'numpy': '2.5.3'})

    def test_installed_versions_must_equal_exact_pins(self):
        result = subprocess.CompletedProcess([], 0, b'{"numpy":"wrong"}', b'')
        with patch.object(rehearsal, 'run', return_value=result):
            with self.assertRaises(ValueError):
                rehearsal.installed_worker_dependencies('owned-worker', {'numpy': '2.5.3'})


if __name__ == '__main__':
    unittest.main()
