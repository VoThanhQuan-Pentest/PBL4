"""Isolated contract tests: fixtures are never actual AWS checkpoint evidence."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/capture-aws-code-image-checkpoint.py'
SPEC = importlib.util.spec_from_file_location('aws_code_image_checkpoint', SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)

EXPECTED = capture.ExpectedIdentity('i-0123456789abcdef0', '123456789012', 'ap-southeast-1')


class AwsCodeImageCheckpointTest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        source = {
            'docker-compose.yml': b'services: {}\n',
            'backend/pom.xml': b'<project/>', 'backend/Dockerfile': b'FROM fixture',
            'backend/src/main/java/Fixture.java': b'class Fixture {}',
            'frontend/package.json': b'{"name":"fixture"}',
            'frontend/src/main.js': b'console.log("fixture")',
            'nginx/Dockerfile': b'FROM fixture', 'nginx/nginx.conf': b'events {}',
            'gateway/Dockerfile': b'FROM fixture', 'gateway/main.go': b'package main',
            'ueba-worker/Dockerfile': b'FROM fixture', 'ueba-worker/app/main.py': b'fixture = True',
            'observability/docker-compose.web-aws.yml': b'services: {}',
            'observability/scripts/fixture.py': b'fixture = True',
        }
        for relative, body in source.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        root.chmod(0o700)
        for path in root.rglob('*'):
            if path.is_dir():
                path.chmod(0o700)
        (root / '.env').write_bytes(b'FLARE_ENVIRONMENT=aws-lab\nDO_NOT_COPY=fixture-private-value\n')
        return root, source

    def containers(self):
        return {service: {'id': format(index + 1, '064x'),
                          'image_id': 'sha256:' + format(index + 17, '064x'),
                          'running': True, 'service': service, 'project': 'flare'}
                for index, service in enumerate(capture.SERVICES)}

    def identity(self):
        return {'instance_id': EXPECTED.instance_id, 'account_id': EXPECTED.account_id,
                'region': EXPECTED.region, 'method': 'FIXED_IMDSV2_IDENTITY_DOCUMENT_MATCH_ONLY',
                'cryptographic_origin_authenticated': False}

    def mocks(self, stack, *, save=None):
        observed = stack.enter_context(patch.object(capture, 'observe_identity', return_value=self.identity()))
        inspected = stack.enter_context(patch.object(capture, 'running_images', return_value=self.containers()))
        sizes = stack.enter_context(patch.object(capture, 'image_sizes',
                                                return_value={service: 100 for service in capture.SERVICES}))
        stack.enter_context(patch.object(capture, 'disk_headroom'))

        def fake_save(arguments, stream, maximum, deadline):
            self.assertEqual(tuple(arguments[:2]), ('image', 'save'))
            self.assertRegex(arguments[2], r'^sha256:[0-9a-f]{64}$')
            self.assertEqual(maximum, capture.MAX_IMAGE_BYTES)
            body = b'ISOLATED_IMAGE_STREAM_FIXTURE_NOT_AWS:' + arguments[2].encode()
            stream.write(body)
            if save:
                save(arguments)
            return {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}

        saved = stack.enter_context(patch.object(capture, 'stream_docker', side_effect=fake_save))
        return observed, inspected, sizes, saved

    def test_complete_isolated_capture_is_only_partial_never_aws_or_release_ready(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, source = self.fixture(directory)
            observed, inspected, _, saved = self.mocks(stack)
            manifest = capture.capture(EXPECTED, 'fixture_checkpoint', root=root, isolated_test_fixture=True)
            target = root / 'observability/runtime/private-backups/fixture_checkpoint'
            self.assertEqual(manifest, json.loads((target / 'manifest.json').read_text()))
            self.assertEqual(manifest['source_environment'], 'ISOLATED_TEST_FIXTURE_NOT_AWS')
            self.assertEqual(manifest['status'], 'PARTIAL_SOURCE_AND_IMAGES_ONLY')
            self.assertTrue(manifest['capture_completed'])
            self.assertTrue(manifest['source_and_running_image_ids_unchanged'])
            for field in ('release_ready', 'aws_origin_independently_authenticated',
                          'complete_rollback_checkpoint', 'restore_performed', 'deployment',
                          'image_archive_contents_inspected', 'legacy_application_on_upgraded_schema_verified',
                          'source_matches_saved_image_build', 'source_files_modified',
                          'running_services_modified', 'iam_credentials_requested'):
                self.assertFalse(manifest[field], field)
            self.assertEqual(set(manifest['artifacts']),
                             {'source', 'image_app', 'image_nginx', 'image_gateway', 'image_ueba_worker'})
            self.assertEqual(set(manifest['not_backed_up_or_restored']), set(capture.NOT_CAPTURED))
            self.assertEqual(saved.call_count, 4)
            self.assertEqual(observed.call_count, 2)
            self.assertEqual(inspected.call_count, 2)
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for path in target.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for artifact in manifest['artifacts'].values():
                body = (target / artifact['path']).read_bytes()
                self.assertEqual(artifact['sha256'], hashlib.sha256(body).hexdigest())
                self.assertEqual(artifact['size'], len(body))
            with tarfile.open(target / 'source.tar') as archive:
                self.assertEqual(set(archive.getnames()), set(source))
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertEqual(archive.extractfile(member).read(), source[member.name])
            self.assertNotIn('fixture-private-value', json.dumps(manifest))

    def test_no_nonproduction_root_can_be_relabelled_as_aws(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(capture, 'observe_identity') as observed:
            with self.assertRaisesRegex(capture.CaptureError, 'FIXED_AWS_ROOT_REQUIRED'):
                capture.capture(EXPECTED, 'fixture', root=Path(directory))
            observed.assert_not_called()

    def test_cli_has_no_root_project_socket_fixture_or_size_bypass(self):
        with patch('sys.argv', [str(SCRIPT), '--help']), patch('sys.stdout', new_callable=io.StringIO) as output:
            with self.assertRaises(SystemExit) as failure:
                capture.main()
            self.assertEqual(failure.exception.code, 0)
        help_text = output.getvalue()
        for option in ('--root', '--project', '--docker-host', '--fixture', '--max-image'):
            self.assertNotIn(option, help_text)
        self.assertEqual(capture.AWS_ROOT, Path('/opt/flare'))
        self.assertEqual(capture.DOCKER, ('docker', '--host', 'unix:///var/run/docker.sock'))

    def test_invalid_expected_identity_is_rejected_before_any_io(self):
        for identity in (capture.ExpectedIdentity('local', EXPECTED.account_id, EXPECTED.region),
                         capture.ExpectedIdentity(EXPECTED.instance_id, '1', EXPECTED.region),
                         capture.ExpectedIdentity(EXPECTED.instance_id, EXPECTED.account_id, 'region;command')):
            with self.subTest(identity=identity), patch.object(capture, 'open_directory') as opened:
                with self.assertRaises(capture.CaptureError):
                    capture.capture(identity, 'fixture')
                opened.assert_not_called()

    def test_deadline_is_a_bounded_integer_not_bool_float_or_string(self):
        for seconds in (True, 1.5, '900', 0, 3601):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(capture.CaptureError, 'INVALID_DEADLINE'):
                capture.Deadline(seconds)

    def test_cli_reports_constant_error_without_private_paths_or_body(self):
        arguments = [str(SCRIPT), '--expected-instance-id', EXPECTED.instance_id,
                     '--expected-account-id', EXPECTED.account_id, '--expected-region', EXPECTED.region,
                     '--checkpoint-name', 'checkpoint']
        with patch('sys.argv', arguments), patch('builtins.print') as printed, \
                patch.object(capture, 'capture', side_effect=capture.CaptureError('AWS_LAB_MARKER_REQUIRED')):
            self.assertEqual(capture.main(), 1)
            result = json.loads(printed.call_args.args[0])
            self.assertEqual(result['code'], 'AWS_LAB_MARKER_REQUIRED')
            self.assertFalse(result['release_ready'])
            self.assertNotIn('/opt/flare', printed.call_args.args[0])

    def test_cli_success_is_explicitly_partial(self):
        arguments = [str(SCRIPT), '--expected-instance-id', EXPECTED.instance_id,
                     '--expected-account-id', EXPECTED.account_id, '--expected-region', EXPECTED.region,
                     '--checkpoint-name', 'checkpoint']
        with patch('sys.argv', arguments), patch('builtins.print') as printed, \
                patch.object(capture, 'capture', return_value={'status': capture.STATUS}) as mocked:
            self.assertEqual(capture.main(), 0)
            self.assertEqual(mocked.call_args.args, (EXPECTED, 'checkpoint', 900))
            self.assertEqual(mocked.call_args.kwargs, {})
            summary = json.loads(printed.call_args.args[0])
            self.assertFalse(summary['complete_rollback_checkpoint'])
            self.assertFalse(summary['release_ready'])

    def test_marker_is_exact_unique_bounded_regular_and_never_copied(self):
        cases = (b'FLARE_ENVIRONMENT=local\n', b'FLARE_ENVIRONMENT="aws-lab"\n',
                 b'FLARE_ENVIRONMENT=aws-lab\nFLARE_ENVIRONMENT=local\n',
                 b'export FLARE_ENVIRONMENT=aws-lab\n', b'x' * 8193)
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.fixture(directory)
            root_fd = capture.open_directory(root)
            try:
                for body in cases:
                    (root / '.env').write_bytes(body)
                    with self.subTest(body=body[:40]), self.assertRaises(capture.CaptureError):
                        capture.marker_matches(root_fd, capture.Deadline())
                (root / '.env').unlink()
                os.mkfifo(root / '.env')
                with self.assertRaises(capture.CaptureError):
                    capture.marker_matches(root_fd, capture.Deadline())
            finally:
                os.close(root_fd)

    def test_marker_failure_prevents_metadata_docker_or_artifact_creation(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(directory)
            (root / '.env').write_text('FLARE_ENVIRONMENT=local\n')
            observed, inspected, _, saved = self.mocks(stack)
            with self.assertRaisesRegex(capture.CaptureError, 'AWS_LAB_MARKER_REQUIRED'):
                capture.capture(EXPECTED, 'fixture', root=root, isolated_test_fixture=True)
            observed.assert_not_called()
            inspected.assert_not_called()
            saved.assert_not_called()
            self.assertFalse((root / 'observability/runtime').exists())

    def test_source_allowlist_excludes_secrets_runtime_models_builds_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root, source = self.fixture(directory)
            excluded = ('backend/src/.env', 'backend/src/.env.example', 'backend/src/.secrets/private.json',
                        'backend/src/runtime/private.py', 'frontend/src/node_modules/private.js',
                        'frontend/src/build/private.js', 'frontend/src/.git/private.js',
                        'nginx/certs/private.conf', 'gateway/keys/private.go',
                        'ueba-worker/app/models/model.json', 'ueba-worker/app/model.joblib',
                        'ueba-worker/app/private.key', 'observability/runtime/private.py',
                        'unselected/source.py', 'frontend/.npmrc')
            for relative in excluded:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('DO_NOT_COPY_FIXTURE')
            (root / 'frontend/src/link.js').symlink_to(root / '.env')
            (root / 'frontend/src/linked').symlink_to(root / 'backend/src', target_is_directory=True)
            root_fd = capture.open_directory(root)
            try:
                self.assertEqual(set(capture.snapshot_source(root_fd, capture.Deadline())), set(source))
            finally:
                os.close(root_fd)

    def test_source_files_fifo_limits_missing_build_files_and_total_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.fixture(directory)
            root_fd = capture.open_directory(root)
            try:
                fifo = root / 'frontend/src/pipe.js'
                os.mkfifo(fifo)
                with self.assertRaisesRegex(capture.CaptureError, 'NON_REGULAR_SOURCE_REJECTED'):
                    capture.snapshot_source(root_fd, capture.Deadline())
                fifo.unlink()
                for setting, limit, code in (('MAX_SOURCE_FILE_BYTES', 1, 'BOUNDED_REGULAR_SOURCE_FILE_REQUIRED'),
                                             ('MAX_SOURCE_BYTES', 1, 'SOURCE_TOTAL_SIZE_LIMIT_EXCEEDED'),
                                             ('MAX_SOURCE_FILES', 1, 'SOURCE_FILE_COUNT_LIMIT_EXCEEDED'),
                                             ('MAX_SOURCE_ENTRIES', 1, 'SOURCE_ENTRY_LIMIT_EXCEEDED')):
                    with patch.object(capture, setting, limit), self.subTest(setting=setting):
                        with self.assertRaisesRegex(capture.CaptureError, code):
                            capture.snapshot_source(root_fd, capture.Deadline())
                (root / 'backend/pom.xml').unlink()
                with self.assertRaisesRegex(capture.CaptureError, 'REQUIRED_SOURCE_BUILD_FILE_MISSING'):
                    capture.snapshot_source(root_fd, capture.Deadline())
            finally:
                os.close(root_fd)

    def test_source_symlinked_ancestor_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.fixture(directory)
            linked = root / 'linked'
            linked.symlink_to(root / 'backend', target_is_directory=True)
            with self.assertRaises(capture.CaptureError):
                capture.open_directory(linked / 'src')
            root_fd = capture.open_directory(root)
            try:
                with self.assertRaises(OSError):
                    capture.open_relative(root_fd, 'linked/pom.xml')
            finally:
                os.close(root_fd)

    def test_fresh_private_directory_and_exclusive_files_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.fixture(directory)
            root_fd = capture.open_directory(root)
            output_fd = capture.private_checkpoint(root_fd, 'fresh')
            try:
                capture.write_json(output_fd, 'manifest.json', {'original': True})
                with self.assertRaises(FileExistsError):
                    capture.write_json(output_fd, 'manifest.json', {'replacement': True})
                with self.assertRaisesRegex(capture.CaptureError, 'NEW_CHECKPOINT_DIRECTORY_REQUIRED'):
                    capture.private_checkpoint(root_fd, 'fresh')
                for name in ('../outside', '/absolute', 'space name', 'x' * 65):
                    with self.subTest(name=name), self.assertRaises(capture.CaptureError):
                        capture.private_checkpoint(root_fd, name)
                target = root / 'observability/runtime/private-backups/fresh/manifest.json'
                self.assertEqual(json.loads(target.read_text()), {'original': True})
            finally:
                os.close(output_fd)
                os.close(root_fd)

    def test_unprotected_or_symlinked_private_root_is_refused(self):
        for mode in ('permissions', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, _ = self.fixture(directory)
                parent = root / 'observability/runtime'
                parent.mkdir()
                private = parent / 'private-backups'
                if mode == 'permissions':
                    private.mkdir(mode=0o755)
                else:
                    private.symlink_to(root, target_is_directory=True)
                root_fd = capture.open_directory(root)
                try:
                    with self.assertRaises((capture.CaptureError, OSError)):
                        capture.private_checkpoint(root_fd, 'fresh')
                finally:
                    os.close(root_fd)

    def test_source_changes_or_new_source_files_retain_failed_partials(self):
        for change in ('edit', 'addition', 'removal'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root, _ = self.fixture(directory)
                changed = False

                def mutate(arguments):
                    nonlocal changed
                    if changed:
                        return
                    changed = True
                    path = root / 'frontend/src/main.js'
                    if change == 'edit':
                        path.write_text('changed source fixture')
                    elif change == 'addition':
                        (root / 'frontend/src/added.js').write_text('added fixture')
                    else:
                        path.unlink()

                self.mocks(stack, save=mutate)
                with self.assertRaisesRegex(capture.CaptureError, 'SOURCE_CHANGED_DURING_CAPTURE'):
                    capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
                target = root / 'observability/runtime/private-backups/partial'
                self.assertTrue((target / 'source.tar').is_file())
                self.assertTrue((target / 'image_app.tar').is_file())
                self.assertFalse((target / 'manifest.json').exists())
                self.assertEqual(json.loads((target / 'failure.json').read_text())['code'],
                                 'SOURCE_CHANGED_DURING_CAPTURE')
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in target.iterdir()))

    def test_container_or_image_changes_retain_failed_partials(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(directory)
            _, inspected, _, _ = self.mocks(stack)
            changed = self.containers()
            changed['app'] = {**changed['app'], 'image_id': 'sha256:' + 'f' * 64}
            inspected.side_effect = [self.containers(), changed]
            with self.assertRaisesRegex(capture.CaptureError, 'RUNNING_CONTAINERS_CHANGED_DURING_CAPTURE'):
                capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
            self.assertFalse((root / 'observability/runtime/private-backups/partial/manifest.json').exists())

    def test_failed_image_save_retains_no_success_manifest(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(directory)
            self.mocks(stack)

            def fail(arguments, stream, maximum, deadline):
                stream.write(b'FAILED_PARTIAL_FIXTURE')
                raise capture.CaptureError('DOCKER_COMMAND_FAILED')

            stack.enter_context(patch.object(capture, 'stream_docker', side_effect=fail))
            with self.assertRaisesRegex(capture.CaptureError, 'DOCKER_COMMAND_FAILED'):
                capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
            target = root / 'observability/runtime/private-backups/partial'
            self.assertEqual((target / 'image_app.tar').read_bytes(), b'FAILED_PARTIAL_FIXTURE')
            self.assertFalse((target / 'manifest.json').exists())
            self.assertFalse(json.loads((target / 'failure.json').read_text())['release_ready'])

    def test_keyboard_interrupt_retains_partial_and_records_cancellation(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(directory)
            self.mocks(stack)
            stack.enter_context(patch.object(capture, 'stream_docker', side_effect=KeyboardInterrupt))
            with self.assertRaisesRegex(capture.CaptureError, 'CAPTURE_CANCELLED'):
                capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
            target = root / 'observability/runtime/private-backups/partial'
            self.assertTrue((target / 'source.tar').is_file())
            self.assertEqual(json.loads((target / 'failure.json').read_text())['code'], 'CAPTURE_CANCELLED')
            self.assertFalse((target / 'manifest.json').exists())

    def test_source_root_replacement_after_capture_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(Path(directory) / 'source')
            self.mocks(stack)
            calls = 0

            def replace_root(expected, deadline):
                nonlocal calls
                calls += 1
                if calls == 2:
                    root.rename(Path(directory) / 'old_source')
                    root.mkdir()
                return self.identity()

            stack.enter_context(patch.object(capture, 'observe_identity', side_effect=replace_root))
            with self.assertRaisesRegex(capture.CaptureError, 'SOURCE_ROOT_CHANGED_DURING_CAPTURE'):
                capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
            target = Path(directory) / 'old_source/observability/runtime/private-backups/partial'
            self.assertFalse((target / 'manifest.json').exists())
            self.assertTrue((target / 'failure.json').exists())

    def docker_response(self, arguments, deadline):
        containers = self.containers()
        if arguments[0] == 'ps':
            service = arguments[arguments.index('--format') - 1].split('=', 2)[2]
            return containers[service]['id'] + '\n'
        if arguments[:2] == ('image', 'inspect'):
            return '100'
        identifier = arguments[-1]
        return json.dumps(next(value for value in containers.values() if value['id'] == identifier))

    def test_running_selection_is_exact_project_service_and_only_selected_inspect_fields(self):
        with patch.object(capture, 'docker_text', side_effect=self.docker_response) as docker:
            self.assertEqual(capture.running_images(capture.Deadline()), self.containers())
            self.assertEqual(docker.call_count, 8)
            for call in docker.call_args_list:
                args = call.args[0]
                if args[0] == 'ps':
                    self.assertIn('label=com.docker.compose.project=flare', args)
                    self.assertIn('--no-trunc', args)
                    self.assertEqual(args[-1], '{{.ID}}')
                else:
                    self.assertEqual(args[:4], ('inspect', '--type', 'container', '--format'))
                    self.assertEqual(args[4], capture.INSPECT_FORMAT)
                    self.assertNotIn('.Config.Env', args[4])
                    self.assertNotIn('{{json .}}', args[4])

    def test_zero_duplicate_short_or_malformed_running_containers_are_refused(self):
        for output in ('', 'a' * 12, 'a' * 64 + '\n' + 'b' * 64, 'not-a-container'):
            with self.subTest(output=output), patch.object(capture, 'docker_text', return_value=output):
                with self.assertRaisesRegex(capture.CaptureError, 'SINGLE_EXACT_RUNNING_SERVICE_REQUIRED'):
                    capture.running_images(capture.Deadline())

    def test_mutable_tag_wrong_project_service_or_not_running_are_refused(self):
        for field, bad in (('image_id', 'app:latest'), ('project', 'other'), ('service', 'other'),
                           ('running', False), ('running', 1), ('id', 'a' * 64)):
            value = {**self.containers()['app'], field: bad}
            with self.subTest(field=field, bad=bad), \
                    patch.object(capture, 'docker_text', side_effect=[self.containers()['app']['id'], json.dumps(value)]):
                with self.assertRaisesRegex(capture.CaptureError, 'RUNNING_IMMUTABLE_IMAGE_CONTRACT_MISMATCH'):
                    capture.running_images(capture.Deadline())

    def test_docker_image_size_is_only_selected_field_and_bounded_integer(self):
        for bad in ('-1', '0', 'true', '1.5', str(capture.MAX_IMAGE_BYTES + 1), 'NaN', '{"Size":100}'):
            with self.subTest(bad=bad), patch.object(capture, 'docker_text', return_value=bad):
                with self.assertRaises(capture.CaptureError):
                    capture.image_sizes(self.containers(), capture.Deadline())
        with patch.object(capture, 'docker_text', return_value='100') as docker:
            sizes = capture.image_sizes(self.containers(), capture.Deadline())
            self.assertEqual(set(sizes), set(capture.SERVICES))
            for call in docker.call_args_list:
                self.assertEqual(call.args[0][:4], ('image', 'inspect', '--format', '{{json .Size}}'))
                self.assertRegex(call.args[0][-1], r'^sha256:[0-9a-f]{64}$')

    def test_disk_headroom_reserves_at_least_one_gib(self):
        capacity = Mock(f_bavail=10, f_frsize=1024 * 1024)
        with patch.object(capture.os, 'fstatvfs', return_value=capacity):
            with self.assertRaisesRegex(capture.CaptureError, 'INSUFFICIENT_PRIVATE_BACKUP_DISK_HEADROOM'):
                capture.disk_headroom(123, 100)
        self.assertGreaterEqual(capture.DISK_RESERVE_BYTES, 1024 ** 3)
        self.assertEqual(capture.MAX_IMAGE_BYTES, 2 * 1024 ** 3)
        self.assertEqual(capture.MAX_TOTAL_IMAGE_BYTES, 8 * 1024 ** 3)

    def test_insufficient_space_leaves_private_failure_and_never_saves_images(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root, _ = self.fixture(directory)
            _, _, _, saved = self.mocks(stack)
            stack.enter_context(patch.object(capture, 'disk_headroom',
                                            side_effect=capture.CaptureError('INSUFFICIENT_PRIVATE_BACKUP_DISK_HEADROOM')))
            with self.assertRaises(capture.CaptureError):
                capture.capture(EXPECTED, 'partial', root=root, isolated_test_fixture=True)
            saved.assert_not_called()
            target = root / 'observability/runtime/private-backups/partial'
            self.assertFalse((target / 'manifest.json').exists())
            self.assertTrue((target / 'failure.json').exists())

    def imds_opener(self, document=None, token=b'fixture-token'):
        opener = Mock()
        response_token = io.BytesIO(token)
        response_document = io.BytesIO(document if document is not None else json.dumps({
            'instanceId': EXPECTED.instance_id, 'accountId': EXPECTED.account_id, 'region': EXPECTED.region,
            'privateIp': 'DO_NOT_RETAIN_FIXTURE'}).encode())
        opener.open.side_effect = [response_token, response_document]
        return opener

    def test_fixed_imdsv2_document_only_no_iam_proxies_redirects_or_crypto_claim(self):
        opener = self.imds_opener()
        with patch.object(capture.urllib.request, 'build_opener', return_value=opener) as build:
            identity = capture.observe_identity(EXPECTED, capture.Deadline())
        self.assertFalse(identity['cryptographic_origin_authenticated'])
        self.assertNotIn('DO_NOT_RETAIN_FIXTURE', json.dumps(identity))
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.full_url for request in requests],
                         [capture.IMDS_TOKEN_URL, capture.IMDS_IDENTITY_URL])
        self.assertEqual(requests[0].get_method(), 'PUT')
        self.assertEqual(requests[1].get_method(), 'GET')
        self.assertEqual(requests[1].get_header('X-aws-ec2-metadata-token'), 'fixture-token')
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], capture.NoRedirect)
        self.assertTrue(all('/iam/' not in request.full_url for request in requests))
        with self.assertRaisesRegex(capture.CaptureError, 'IMDS_REDIRECT_REJECTED'):
            capture.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://other')

    def test_imds_wrong_identity_duplicate_fields_or_oversized_documents_are_refused(self):
        bodies = (b'{"instanceId":"wrong"}',
                  b'{"accountId":"123456789012","accountId":"123456789012"}',
                  b'{"accountId":NaN}', b'[' * 2000 + b']' * 2000, b'x' * 32769)
        for body in bodies:
            with self.subTest(body=body[:50]), \
                    patch.object(capture.urllib.request, 'build_opener', return_value=self.imds_opener(body)):
                with self.assertRaises(capture.CaptureError):
                    capture.observe_identity(EXPECTED, capture.Deadline())
        for token in (b'', b'newline\nheader', b'x' * 4097):
            with self.subTest(token=token[:40]), \
                    patch.object(capture.urllib.request, 'build_opener', return_value=self.imds_opener(token=token)):
                with self.assertRaises(capture.CaptureError):
                    capture.observe_identity(EXPECTED, capture.Deadline())

    def test_trickling_imds_response_is_checked_against_deadline_between_chunks(self):
        response = Mock()
        response.read1.side_effect = [b'f', b'i', b'x']
        deadline = Mock()
        deadline.remaining.side_effect = [10, 10, capture.CaptureError('CAPTURE_DEADLINE_EXCEEDED')]
        with self.assertRaisesRegex(capture.CaptureError, 'CAPTURE_DEADLINE_EXCEEDED'):
            capture.bounded_imds_body(response, 4096, deadline)
        self.assertEqual(response.read1.call_count, 2)

    def test_selected_json_rejects_duplicates_nonfinite_and_deep_input(self):
        for body in ('{"image_id":1,"image_id":2}', 'NaN', 'Infinity', '1e400', '-1e400',
                     '9' * 10000, '-' + '9' * 10000, '[' * 2000 + ']' * 2000):
            with self.subTest(body=body[:40]), self.assertRaisesRegex(capture.CaptureError, 'FIXTURE_INVALID'):
                capture.selected_json(body, 'FIXTURE_INVALID')

    def test_selected_json_integer_limit_is_64_digits_and_finite_floats_are_allowed(self):
        for sign in ('', '-'):
            body = sign + '9' * 64
            self.assertEqual(capture.selected_json(body, 'FIXTURE_INVALID'), int(body))
            with self.assertRaisesRegex(capture.CaptureError, '^FIXTURE_INVALID$'):
                capture.selected_json(sign + '9' * 65, 'FIXTURE_INVALID')
        self.assertEqual(capture.selected_json('1.25e2', 'FIXTURE_INVALID'), 125.0)

    def test_matching_imds_identity_cannot_hide_overflowing_extra_numeric_fields(self):
        identity = json.dumps({'instanceId': EXPECTED.instance_id, 'accountId': EXPECTED.account_id,
                               'region': EXPECTED.region})[:-1]
        for number in ('1e400', '-1e400', '9' * 10000):
            body = (identity + ',"extra":' + number + '}').encode()
            with self.subTest(number=number[:40]), \
                    patch.object(capture.urllib.request, 'build_opener', return_value=self.imds_opener(body)):
                with self.assertRaisesRegex(capture.CaptureError, '^INVALID_IMDS_IDENTITY_DOCUMENT$'):
                    capture.observe_identity(EXPECTED, capture.Deadline())

    def test_stream_bounds_output_and_uses_no_shell_remote_context_or_credential_environment(self):
        original = subprocess.Popen
        processes = []

        def fixture_process(command, **kwargs):
            self.assertEqual(command[:3], capture.DOCKER)
            self.assertNotIn('shell', kwargs)
            self.assertNotIn('DOCKER_HOST', kwargs['env'])
            self.assertNotIn('AWS_ACCESS_KEY_ID', kwargs['env'])
            process = original([sys.executable, '-c', 'import sys; sys.stdout.write("fixture-output")'], **kwargs)
            processes.append(process)
            return process

        with patch.object(capture.subprocess, 'Popen', side_effect=fixture_process):
            with self.assertRaisesRegex(capture.CaptureError, 'DOCKER_OUTPUT_SIZE_LIMIT_EXCEEDED'):
                capture.stream_docker(('ps',), io.BytesIO(), 4, capture.Deadline())
        self.assertIsNotNone(processes[0].poll())

    def test_stream_deadline_kills_only_the_spawned_child_not_services(self):
        original = subprocess.Popen
        processes = []

        def fixture_process(command, **kwargs):
            process = original([sys.executable, '-c', 'import time; time.sleep(10)'], **kwargs)
            processes.append(process)
            return process

        began = time.monotonic()
        with patch.object(capture.subprocess, 'Popen', side_effect=fixture_process), \
                patch.object(capture.os, 'killpg', wraps=os.killpg) as killed:
            with self.assertRaisesRegex(capture.CaptureError, 'CAPTURE_DEADLINE_EXCEEDED'):
                capture.stream_docker(('image', 'save', 'sha256:' + 'a' * 64),
                                      io.BytesIO(), capture.MAX_IMAGE_BYTES, capture.Deadline(1))
        self.assertLess(time.monotonic() - began, 3)
        self.assertEqual(killed.call_args.args, (processes[0].pid, signal.SIGKILL))
        self.assertIsNotNone(processes[0].poll())

    def test_image_stream_checks_headroom_before_each_private_write(self):
        original = subprocess.Popen

        def fixture_process(command, **kwargs):
            return original([sys.executable, '-c', 'import sys; sys.stdout.write("fixture")'], **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'image.fixture'
            with destination.open('xb') as sink, \
                    patch.object(capture.subprocess, 'Popen', side_effect=fixture_process), \
                    patch.object(capture, 'disk_headroom',
                                 side_effect=capture.CaptureError('INSUFFICIENT_PRIVATE_BACKUP_DISK_HEADROOM')) as space:
                with self.assertRaisesRegex(capture.CaptureError, 'INSUFFICIENT_PRIVATE_BACKUP_DISK_HEADROOM'):
                    capture.stream_docker(('image', 'save', 'sha256:' + 'a' * 64), sink,
                                          capture.MAX_IMAGE_BYTES, capture.Deadline())
                self.assertEqual(space.call_args.args, (sink.fileno(), 7))
            self.assertEqual(destination.read_bytes(), b'')

    def test_script_contains_no_load_pull_build_stop_restart_deploy_or_secret_copy_commands(self):
        source = SCRIPT.read_text()
        self.assertNotIn('os.system', source)
        self.assertNotIn('extractall', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('/latest/meta-data/iam/', source)
        for operation in ('load', 'pull', 'build', 'stop', 'restart', 'compose'):
            self.assertNotIn("('" + operation + "',", source)


if __name__ == '__main__':
    unittest.main()
