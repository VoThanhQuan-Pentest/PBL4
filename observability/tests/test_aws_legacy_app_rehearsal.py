"""Isolation and immutable-runtime contracts for the opt-in legacy AWS app rehearsal."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
SPEC = importlib.util.spec_from_file_location('aws_legacy_app_rehearsal', SCRIPTS / 'rehearse-aws-legacy-app.py')
rehearsal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rehearsal)


class AwsLegacyAppRehearsalTest(unittest.TestCase):
    def source(self):
        values = {key: 'original-' + key.lower() for key in rehearsal.APP_KEYS}
        values.update(SPRING_DATASOURCE_USERNAME='flare_app', SPRING_DATASOURCE_PASSWORD='test-db-value',
                      REDIS_PASSWORD='test-redis-value')
        return values

    def state(self):
        return {'Id': 'owned-id', 'Config': {'Labels': {'flare.scope': rehearsal.SCOPE,
                'flare.rehearsal': 'nonce'}}, 'HostConfig': {'PortBindings': {}},
                'NetworkSettings': {'Networks': {'owned-internal': {}}}}

    def test_missing_opt_in_cannot_call_docker(self):
        with patch('sys.argv', ['rehearse-aws-legacy-app.py']), patch('sys.stderr', io.StringIO()), \
                patch.object(rehearsal, 'run') as command:
            with self.assertRaises(SystemExit):
                rehearsal.main()
            command.assert_not_called()

    def test_dotenv_never_executes_or_interpolates_values(self):
        self.assertEqual(rehearsal.dotenv(b'A="a b"\nEMPTY=\n# comment\n'), {'A': 'a b', 'EMPTY': ''})
        for body in (b'A=$(command)', b'A=${B}', b'A=a\nA=b', b'export A=b', b'A=a b', b'A=bad\x00'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                rehearsal.dotenv(body)

    def test_original_security_profile_and_mail_configuration_remain(self):
        source = self.source()
        mysql, app = rehearsal.fixture_environment(source, 'private-fixture-root')
        for key in rehearsal.APP_KEYS:
            self.assertEqual(app[key], source[key])
        self.assertEqual(mysql['MYSQL_USER'], source['SPRING_DATASOURCE_USERNAME'])
        self.assertEqual(mysql['MYSQL_PASSWORD'], source['SPRING_DATASOURCE_PASSWORD'])
        self.assertEqual(app['SPRING_DATASOURCE_USERNAME'], source['SPRING_DATASOURCE_USERNAME'])
        self.assertEqual(app['SPRING_DATASOURCE_PASSWORD'], source['SPRING_DATASOURCE_PASSWORD'])
        self.assertTrue(app['SPRING_DATASOURCE_URL'].startswith('jdbc:mysql://db:3306/flare_rehearsal?'))
        self.assertEqual(app['SPRING_DATA_REDIS_HOST'], 'redis')
        self.assertEqual(app['SIEM_UEBA_URL'], 'http://ueba-worker:8091')
        self.assertFalse(any('FLYWAY' in key or 'JAVA' in key for key in app))
        self.assertFalse(any('FLYWAY' in key for key in mysql))
        for key in ('SIEM_ENABLED', 'SIEM_SECURITY_EVENTS_ENABLED', 'SIEM_UEBA_ENABLED', 'SIEM_PREVENTION_ENABLED'):
            self.assertEqual(app[key], 'false')

    def test_app_uses_exact_id_default_entrypoint_and_no_host_port(self):
        command = rehearsal.app_command('owned-app', 'owned-internal', 'nonce', Path('/private/app.env'), 'sha256:' + 'a' * 64)
        self.assertEqual(command[-1], 'sha256:' + 'a' * 64)
        self.assertIn('--pull=never', command)
        self.assertIn('--read-only', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--security-opt=no-new-privileges', command)
        self.assertEqual(command[command.index('--network') + 1], 'owned-internal')
        for prohibited in ('--publish', '-p', '--entrypoint', 'repair', '--env', '--mount'):
            self.assertNotIn(prohibited, command)
        self.assertFalse(any('FLYWAY' in value.upper() for value in command))

    def test_db_tmpfs_and_redis_private_config_keep_credentials_off_command_line(self):
        mysql = rehearsal.mysql_command('owned-db', 'owned-internal', 'nonce', Path('/private/mysql.env'))
        redis = rehearsal.redis_command('owned-redis', 'owned-internal', 'nonce', Path('/private/redis.env'))
        self.assertIn('/var/lib/mysql:rw,noexec,nosuid,size=1g', mysql)
        self.assertIn('/data:rw,noexec,nosuid,size=64m', redis)
        self.assertIn('/run/rehearsal/redis.conf', redis)
        self.assertIn('ueba-worker', redis)
        self.assertEqual(redis[redis.index('--user') + 1], f'{rehearsal.os.getuid()}:{rehearsal.os.getgid()}')
        self.assertNotIn('--requirepass', redis)
        self.assertNotIn('--password', ' '.join(mysql + redis))
        for command in (mysql, redis):
            self.assertIn('--pull=never', command)
            self.assertIn('flare.rehearsal=nonce', command)
            self.assertNotIn('--publish', command)
            self.assertNotIn('-p', command)

    def test_private_env_is_0600_and_refuses_injected_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'private.env'
            rehearsal.write_env(path, {'KEY': 'private-test-value'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                rehearsal.write_env(Path(temporary) / 'bad.env', {'KEY': 'value\nOTHER=bad'})

    def test_container_requires_exact_nonce_network_and_no_ports(self):
        state = self.state()
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            rehearsal.owned_container('owned-app', 'owned-internal', 'nonce')
            for mutation in ('wrong_nonce', 'other_network', 'public_port'):
                bad = json.loads(json.dumps(state))
                if mutation == 'wrong_nonce':
                    bad['Config']['Labels']['flare.rehearsal'] = 'other'
                elif mutation == 'other_network':
                    bad['NetworkSettings']['Networks']['bridge'] = {}
                else:
                    bad['HostConfig']['PortBindings'] = {'8080/tcp': [{'HostPort': '8080'}]}
                with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([bad]).encode())):
                    with self.assertRaises(ValueError):
                        rehearsal.owned_container('owned-app', 'owned-internal', 'nonce')

    def test_network_must_be_internal_and_exactly_owned(self):
        state = {'Internal': True, 'Driver': 'bridge', 'Labels': {'flare.scope': rehearsal.SCOPE, 'flare.rehearsal': 'nonce'}}
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            rehearsal.owned_network('owned-internal', 'nonce')
        state['Internal'] = False
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=json.dumps([state]).encode())):
            with self.assertRaises(ValueError):
                rehearsal.owned_network('owned-internal', 'nonce')

    def test_cleanup_refuses_collision_or_other_owner(self):
        state = self.state()
        state['Config']['Labels']['flare.rehearsal'] = 'other'
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps([state]).encode())) as command:
            self.assertFalse(rehearsal.cleanup(['collision'], None, 'nonce'))
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][1], 'inspect')

    def test_cleanup_removes_only_owned_inspected_id(self):
        state = self.state()
        responses = [SimpleNamespace(returncode=0, stdout=json.dumps([state]).encode()), SimpleNamespace(returncode=0)]
        with patch.object(rehearsal, 'run', side_effect=responses) as command:
            self.assertTrue(rehearsal.cleanup(['owned'], None, 'nonce'))
            self.assertEqual(command.call_args.args[0], ['docker', 'rm', '-fv', 'owned-id'])

    def test_cleanup_does_not_mistake_daemon_failure_for_absent_resource(self):
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(returncode=1, stderr=b'Daemon unavailable')):
            self.assertFalse(rehearsal.cleanup(['owned'], None, 'nonce'))
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(returncode=1, stderr=b'Error: No such container: owned')):
            self.assertTrue(rehearsal.cleanup(['owned'], None, 'nonce'))

    def test_failed_image_verification_cannot_load_any_image(self):
        with patch.object(rehearsal.image_verifier, 'verify_image', return_value={'image_archive_verified': False}), \
                patch.object(rehearsal, 'run') as command:
            with self.assertRaises(ValueError):
                rehearsal.read_image_metadata(Path('/private/image.tar'), 'sha256:' + 'a' * 64, 'b' * 64)
            command.assert_not_called()

    def test_only_absent_null_docker_optional_defaults_are_equivalent(self):
        saved = {'Entrypoint': ['java', '-jar', '/app/app.jar'], 'Env': ['JAVA_HOME=/java']}
        loaded = {**saved, 'Cmd': None, 'OnBuild': None, 'Volumes': None}
        self.assertTrue(rehearsal.matching_runtime_configuration(loaded, saved))
        for key, changed in (('Cmd', ['changed']), ('OnBuild', ['RUN changed']), ('Volumes', {'/data': {}}),
                             ('Env', ['FLYWAY_ENABLED=false']), ('User', 'root')):
            self.assertFalse(rehearsal.matching_runtime_configuration({**loaded, key: changed}, saved))

    def test_tagged_image_inventory_retains_exact_repository_tag_and_id(self):
        records = [{'Repository': 'user/image', 'Tag': 'latest', 'ID': 'sha256:a'},
                   {'Repository': '<none>', 'Tag': '<none>', 'ID': 'sha256:b'}]
        with patch.object(rehearsal, 'run', return_value=SimpleNamespace(stdout=('\n'.join(json.dumps(row) for row in records) + '\n').encode())):
            self.assertEqual(rehearsal.tagged_images(), [('user/image', 'latest', 'sha256:a')])


if __name__ == '__main__':
    unittest.main()
