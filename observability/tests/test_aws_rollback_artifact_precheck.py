"""Fail-closed, non-executing contracts for the AWS rollback artifact precheck."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/precheck-aws-rollback-artifacts.py'
SPEC = importlib.util.spec_from_file_location('aws_rollback_artifact_precheck', SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


class AwsRollbackArtifactPrecheckTest(unittest.TestCase):
    def manifest(self, artifacts=None):
        return {'format': preflight.FORMAT, 'source_environment': 'AWS',
                'source_schema_version': '27', 'target_schema_version': '36',
                'artifacts': artifacts or {}}

    def artifact(self, path, role):
        raw = {'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
               'source_environment': 'AWS'}
        if role in preflight.IMAGE_ROLES:
            raw['image_id'] = 'sha256:' + 'a' * 64
        return raw

    def fixture(self, directory):
        root = Path(directory)
        root.chmod(0o700)
        artifacts = {}
        for role in preflight.ROLES:
            path = root / (role + '.fixture')
            path.write_bytes(('immutable fixture ' + role).encode())
            path.chmod(0o600)
            artifacts[role] = self.artifact(path, role)
        return root, self.manifest(artifacts)

    def test_missing_aws_code_images_config_and_calibration_checkpoint_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            value['artifacts'] = {role: value['artifacts'][role] for role in ('database', 'models_and_calibrations')}
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertFalse(result['artifacts_verified'])
            self.assertTrue(result['checks']['database']['verified'])
            self.assertTrue(result['checks']['models_and_calibrations']['verified'])
            for role in set(preflight.ROLES) - set(value['artifacts']):
                self.assertEqual(result['checks'][role]['code'], 'MISSING_AWS_ORIGIN_BOUND_ARTIFACT')
            self.assertFalse(result['release_ready'])

    def test_all_hashes_verified_are_never_legacy_startup_or_database_rollback_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertTrue(result['artifacts_verified'])
            for field in ('release_ready', 'aws_origin_independently_authenticated',
                          'image_archive_contents_inspected', 'model_calibration_completeness_inspected',
                          'legacy_app_v34_on_schema36_verified', 'database_rollback_verified',
                          'database_rollback_performed', 'aws_calls', 'docker_calls',
                          'deployment', 'source_artifacts_modified'):
                self.assertFalse(result[field], field)

    def test_different_hash_fails_without_executing_or_printing_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            value['artifacts']['source']['sha256'] = 'b' * 64
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertEqual(result['checks']['source']['code'], 'CHECKPOINT_SHA256_MISMATCH')
            self.assertNotIn('immutable fixture', json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))

    def test_local_release_checkpoint_cannot_be_relabelled_through_local_origin(self):
        value = self.manifest()
        value['source_environment'] = 'LOCAL'
        with self.assertRaises(preflight.PrecheckError):
            preflight.parse_manifest(value)
        with tempfile.TemporaryDirectory() as directory:
            _, value = self.fixture(directory)
            value['artifacts']['source']['source_environment'] = 'LOCAL'
            with self.assertRaises(preflight.PrecheckError):
                preflight.parse_manifest(value)

    def test_exact_schema_and_supported_roles_required(self):
        for change in ({'source_schema_version': 27}, {'target_schema_version': '32'},
                       {'format': 'other'}, {'artifacts': []}, {'artifacts': {'extra': {}}}):
            with self.subTest(change=change), self.assertRaises(preflight.PrecheckError):
                preflight.parse_manifest({**self.manifest(), **change})

    def test_duplicate_top_level_and_nested_fields_are_refused_without_values_in_error(self):
        for text in ('{"source_environment":"LOCAL","source_environment":"AWS"}',
                     '{"artifacts":{"source":{"sha256":"PRIVATE_SENTINEL","sha256":"other"}}}',
                     '{"artifacts":{"source":{},"source":{}}}'):
            with self.subTest(text=text), self.assertRaisesRegex(preflight.PrecheckError, '^DUPLICATE_MANIFEST_FIELD$'):
                preflight.parse_manifest_json(text.encode())

    def test_nonfinite_malformed_and_excessively_deep_json_are_refused_safely(self):
        for text in ('{"field":NaN}', '{"field":Infinity}', '{"field":-Infinity}', '{"field":1e400}', '{"field":-1e400}'):
            with self.subTest(text=text), self.assertRaisesRegex(preflight.PrecheckError, '^NONFINITE_MANIFEST_VALUE$'):
                preflight.parse_manifest_json(text.encode())
        for raw in (b'{"private":"PRIVATE_SENTINEL"', b'\xff', ('[' * 1200 + '0' + ']' * 1200).encode()):
            with self.subTest(raw_length=len(raw)), self.assertRaisesRegex(preflight.PrecheckError, '^INVALID_MANIFEST_JSON$'):
                preflight.parse_manifest_json(raw)
        for text in ('9' * 65, '-' + '9' * 10000):
            with self.subTest(integer_digits=len(text)), self.assertRaisesRegex(preflight.PrecheckError, '^MANIFEST_INTEGER_LIMIT_EXCEEDED$'):
                preflight.parse_manifest_json(text.encode())

    def test_one_file_cannot_satisfy_multiple_required_artifact_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            _, value = self.fixture(directory)
            value['artifacts']['configuration'] = dict(value['artifacts']['source'])
            for path in ('source.fixture', './source.fixture'):
                value['artifacts']['configuration']['path'] = path
                with self.subTest(path=path), self.assertRaisesRegex(preflight.PrecheckError, '^DUPLICATE_ARTIFACT_PATH$'):
                    preflight.parse_manifest(value)

    def test_cli_duplicate_manifest_is_refused_before_artifact_read_or_evidence_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            manifest, output = root / 'manifest.json', root / 'evidence.json'
            manifest.write_bytes(b'{"source_environment":"PRIVATE_SENTINEL","source_environment":"AWS"}')
            manifest.chmod(0o600)
            with patch.object(preflight, 'PRIVATE_ROOT', root), \
                    patch('sys.argv', [str(SCRIPT), '--manifest', str(manifest), '--output', str(output)]), \
                    patch.object(preflight, 'precheck') as checks, patch('builtins.print') as printed:
                self.assertEqual(preflight.main(), 2)
                self.assertEqual(json.loads(printed.call_args.args[0])['code'], 'DUPLICATE_MANIFEST_FIELD')
                self.assertNotIn('PRIVATE_SENTINEL', printed.call_args.args[0])
                self.assertNotIn(str(root), printed.call_args.args[0])
                checks.assert_not_called()
            self.assertFalse(output.exists())

    def test_mutable_or_non_image_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            _, value = self.fixture(directory)
            for image_id in ('latest', 'app:latest', 'sha256:' + 'a' * 12, 2, None):
                value['artifacts']['image_app']['image_id'] = image_id
                with self.subTest(image_id=image_id), self.assertRaises(preflight.PrecheckError):
                    preflight.parse_manifest(value)

    def test_traversal_absolute_and_non_string_file_identities_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            _, value = self.fixture(directory)
            for path in ('../private', '/tmp/private', 'dir\\private', 'private\x00file', 5):
                value['artifacts']['source']['path'] = path
                with self.subTest(path=path), self.assertRaises(preflight.PrecheckError):
                    preflight.parse_manifest(value)

    def test_symlink_file_and_ancestor_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            link = root / 'link.fixture'
            link.symlink_to(root / 'source.fixture')
            value['artifacts']['source']['path'] = link.name
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertEqual(result['checks']['source']['code'], 'SYMLINK_PATH_REJECTED')
            link_directory = root / 'linked'
            link_directory.symlink_to(root, target_is_directory=True)
            value['artifacts']['source']['path'] = 'linked/source.fixture'
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertEqual(result['checks']['source']['code'], 'SYMLINK_PATH_REJECTED')

    def test_group_readable_artifact_and_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            (root / 'source.fixture').chmod(0o640)
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertEqual(result['checks']['source']['code'], 'BOUNDED_PRIVATE_REGULAR_FILE_REQUIRED')
            root.chmod(0o750)
            result = preflight.precheck(preflight.parse_manifest(value), root, root)
            self.assertEqual(result['checks']['database']['code'], 'PRIVATE_DIRECTORY_PROTECTION_REQUIRED')

    def test_fifo_is_rejected_without_blocking_and_artifact_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'private.fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(preflight.PrecheckError):
                preflight.read_private_file(fifo, 100)
            file = root / 'private.file'
            file.write_bytes(b'12345')
            file.chmod(0o600)
            with self.assertRaises(preflight.PrecheckError):
                preflight.read_private_file(file, 4)

    def test_no_aws_docker_shell_or_artifact_execution_dependency(self):
        source = SCRIPT.read_text()
        self.assertNotIn('import subprocess', source)
        self.assertNotIn('import pickle', source)
        self.assertNotIn('import joblib', source)
        self.assertNotIn('extractall', source)
        self.assertNotIn('os.system', source)

    def test_cli_never_overwrites_existing_evidence_or_prints_private_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(value))
            manifest.chmod(0o600)
            output = root / 'evidence.json'
            output.write_text('original private evidence')
            output.chmod(0o600)
            with patch.object(preflight, 'PRIVATE_ROOT', root), \
                    patch('sys.argv', [str(SCRIPT), '--manifest', str(manifest), '--output', str(output)]), \
                    patch('builtins.print') as printed:
                self.assertEqual(preflight.main(), 2)
                self.assertEqual(json.loads(printed.call_args.args[0])['code'], 'NEW_OUTPUT_REQUIRED')
                self.assertNotIn(str(root), printed.call_args.args[0])
            self.assertEqual(output.read_text(), 'original private evidence')

    def test_cli_writes_new_private_evidence_and_reports_only_integrity_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root, value = self.fixture(directory)
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(value))
            manifest.chmod(0o600)
            output = root / 'evidence.json'
            with patch.object(preflight, 'PRIVATE_ROOT', root), \
                    patch('sys.argv', [str(SCRIPT), '--manifest', str(manifest), '--output', str(output)]), \
                    patch('builtins.print') as printed:
                self.assertEqual(preflight.main(), 0)
                summary = json.loads(printed.call_args.args[0])
                self.assertTrue(summary['artifacts_verified'])
                self.assertFalse(summary['release_ready'])
                self.assertNotIn(str(root), printed.call_args.args[0])
            evidence = json.loads(output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertFalse(evidence['legacy_app_v34_on_schema36_verified'])
            self.assertFalse(evidence['database_rollback_verified'])


if __name__ == '__main__':
    unittest.main()
