"""Safety contracts for the opt-in local-only actual Flyway backup rehearsal."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('backup_upgrade_rehearsal', SCRIPTS / 'rehearse-aws-backup-upgrade.py')
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)


class BackupUpgradeRehearsalTest(unittest.TestCase):
    def test_java_failure_summary_never_returns_raw_private_diagnostics(self):
        private = b'java.lang.NoClassDefFoundError: private_user_password_value'
        result = rehearsal.classify_java_failure(private)
        self.assertEqual(result, 'JAVA_CLASS_LINKAGE_FAILURE')
        self.assertNotIn('private_user_password_value', result)
        self.assertEqual(rehearsal.classify_java_failure(b'other private diagnostics'),
                         'JAVA_PROCESS_FAILED_UNCLASSIFIED')

    def test_history_rows_are_checked_against_actual_migrations_executed(self):
        helper = (SCRIPTS.parents[1] / 'backend/src/test/java/com/flarefitness/backend/integration/AwsBackupUpgradeRehearsal.java').read_text()
        self.assertIn('historyRows + migrated', helper)
        self.assertNotIn('historyRows + 7', helper)
        self.assertIn('REHEARSAL_SOURCE_SCHEMA', helper)
        self.assertIn('ADDED_COLUMNS_FROM_31', helper)
        self.assertIn('historyRows == sourceVersionNumber', helper)
        self.assertIn('expectedRepeatableRows', helper)
        self.assertIn('source_repeatable_migration_count', helper)

    def test_schema31_requires_an_explicit_source_environment_before_docker(self):
        argv = ['rehearse-aws-backup-upgrade.py', '--allow-disposable-local-upgrade',
                '--backup', '/private/mysql.sql.gz', '--expected-backup-sha256', 'a' * 64,
                '--frozen-dependencies', '/private/frozen', '--output', '/private/out.json',
                '--source-schema', '31']
        with patch('sys.argv', argv), patch('sys.stderr', io.StringIO()), patch.object(rehearsal, 'run') as command:
            with self.assertRaises(SystemExit):
                rehearsal.main()
            command.assert_not_called()

    def test_source_checksum_mismatch_is_rejected_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'mysql.sql.gz'
            backup.write_bytes(gzip.compress(b'CREATE TABLE flyway_schema_history (id int);'))
            with patch.object(rehearsal, 'run') as command:
                with self.assertRaises(ValueError):
                    rehearsal.read_backup(backup, 'a' * 64)
                command.assert_not_called()
            digest = hashlib.sha256(backup.read_bytes()).hexdigest()
            self.assertEqual(rehearsal.read_backup(backup, digest)[1], digest)

    def test_symlink_backup_and_incomplete_dump_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'mysql.sql.gz'
            backup.write_bytes(gzip.compress(b'SELECT 1;'))
            link = Path(directory) / 'link.gz'
            link.symlink_to(backup)
            digest = hashlib.sha256(backup.read_bytes()).hexdigest()
            for source in (backup, link):
                with self.assertRaises(ValueError):
                    rehearsal.read_backup(source, digest)

    def test_database_has_no_network_ports_host_files_or_cli_password(self):
        command = rehearsal.mysql_container_command('owned-db', Path('/private/mysql.env'))
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('--pull=never', command)
        self.assertNotIn('-p', command)
        self.assertNotIn('--publish', command)
        self.assertNotIn('--mount', command)
        self.assertNotIn('--password', ' '.join(command))
        self.assertIn('1024m', command)
        self.assertIn('0.75', command)
        self.assertIn('/var/lib/mysql:rw,noexec,nosuid,size=1g', command)
        self.assertIn('@sha256:', rehearsal.MYSQL_IMAGE)

    def test_java_shares_only_disposable_namespace_and_cannot_take_url(self):
        command = rehearsal.java_container_command('owned-java', 'owned-db', Path('/private/mysql.env'),
                                                  Path('/work'), Path('/frozen'))
        self.assertEqual(command[command.index('--network') + 1], 'container:owned-db')
        self.assertIn('--read-only', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('768m', command)
        self.assertIn('128', command)
        self.assertNotIn('--publish', command)
        self.assertNotIn('jdbc:', ' '.join(command))
        self.assertEqual(rehearsal.JAVA_IMAGE,
                         'sha256:973e4842cf2aac59888e254b49dd2b724718f2e5e1f60ba74315e04c65a88151')
        self.assertIn('--entrypoint', command)
        self.assertIn('java', command)
        self.assertIn('MYSQL_PWD="$MYSQL_ROOT_PASSWORD"', rehearsal.database_command('owned-db')[-1])

    def test_e2e_repeatable_location_is_an_explicit_read_only_local_input(self):
        script = (SCRIPTS / 'rehearse-aws-backup-upgrade.py').read_text()
        self.assertIn("include_e2e_seed = source_environment == 'LOCAL'", script)
        production_command = rehearsal.java_container_command('owned-java', 'owned-db', Path('/private/mysql.env'),
                                                               Path('/work'), Path('/frozen'))
        self.assertNotIn('e2e-seed', ' '.join(production_command))
        local_command = rehearsal.java_container_command('owned-java', 'owned-db', Path('/private/mysql.env'),
                                                          Path('/work'), Path('/frozen'), include_e2e_seed=True)
        self.assertIn(str(rehearsal.E2E_SEEDS), ' '.join(local_command))
        self.assertIn('dst=/rehearsal/e2e-seed,readonly', ' '.join(local_command))

    def test_missing_explicit_opt_in_never_calls_docker(self):
        with patch('sys.argv', ['rehearse-aws-backup-upgrade.py']), patch('sys.stderr', io.StringIO()), \
                patch.object(rehearsal, 'run') as command:
            with self.assertRaises(SystemExit):
                rehearsal.main()
            command.assert_not_called()

    def test_changed_frozen_jar_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            frozen = Path(directory)
            (frozen / 'jars').mkdir()
            jar = frozen / 'jars/0093-flyway-core-11.20.3.jar'
            jar.write_bytes(b'changed retained jar')
            (frozen / 'snapshot.json').write_text(json.dumps({'jars': {jar.name: 'a' * 64}}))
            with self.assertRaises(ValueError):
                rehearsal.frozen_jars(frozen)

    def test_inspected_database_must_be_owned_and_have_no_public_ports(self):
        state = {'HostConfig': {'NetworkMode': 'none', 'PortBindings': {}},
                 'NetworkSettings': {'Networks': {'none': {}}},
                 'Config': {'Labels': {'flare.scope': 'disposable-local-backup-upgrade'}}}
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            rehearsal.validate_disposable_network('owned-db')
        state['HostConfig']['PortBindings'] = {'3306/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '3306'}]}
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            with self.assertRaises(ValueError):
                rehearsal.validate_disposable_network('owned-db')
        state['HostConfig']['PortBindings'] = {}
        state['Config']['Labels'] = {}
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            with self.assertRaises(ValueError):
                rehearsal.validate_disposable_network('unowned-db')


if __name__ == '__main__':
    unittest.main()
