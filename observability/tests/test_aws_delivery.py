import importlib.util
import fcntl
from datetime import datetime, timedelta, timezone
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace
import urllib.error
import unittest
from unittest.mock import patch
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / f'observability/scripts/{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class AwsDeliveryTest(unittest.TestCase):
    def bootstrap_fixture(self, root):
        scripts = root / 'observability/scripts'
        scripts.mkdir(parents=True)
        source = (ROOT / 'observability/scripts/bootstrap-aws-admin.sh').read_text()
        # Exercise a private test copy, preserving the production script's /opt/flare guard.
        source = source.replace('[ "$ROOT_DIR" = /opt/flare ]', f'[ "$ROOT_DIR" = "{root}" ]')
        script = scripts / 'bootstrap-aws-admin.sh'
        script.write_text(source)
        wrapper = scripts / 'aws-compose.sh'
        wrapper.write_text('#!/usr/bin/env bash\nprintf "%s" "$BOOTSTRAP_TEST_OUTPUT"\nexit "${BOOTSTRAP_TEST_STATUS:-0}"\n')
        wrapper.chmod(0o700)
        return script, root / 'observability/runtime/private-credentials'

    def test_bootstrap_publishes_private_credential_and_never_overwrites(self):
        value = {'id': 'aws-bootstrap-fixture', 'username': 'aws_bootstrap_fixture',
                 'password': 'Fixture-not-a-real-secret'}
        with tempfile.TemporaryDirectory() as directory:
            script, private = self.bootstrap_fixture(Path(directory))
            env = dict(os.environ, BOOTSTRAP_TEST_OUTPUT=json.dumps(value))
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            dest = private / 'aws-bootstrap.json'
            self.assertEqual(json.loads(dest.read_text()), value)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(private.glob('*.capture-*')))
            self.assertNotIn(value['password'], result.stdout + result.stderr)
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(dest.read_text()), value)

    def test_failed_bootstrap_retains_private_capture_without_poisoning_destination(self):
        for status, output in ((2, ''), (2, '{"partial":true}'), (0, 'invalid output')):
            with self.subTest(status=status, output=output), tempfile.TemporaryDirectory() as directory:
                script, private = self.bootstrap_fixture(Path(directory))
                env = dict(os.environ, BOOTSTRAP_TEST_OUTPUT=output, BOOTSTRAP_TEST_STATUS=str(status))
                result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((private / 'aws-bootstrap.json').exists())
                captures = list(private.glob('aws-bootstrap.capture-*'))
                self.assertEqual(len(captures), 1)
                self.assertEqual(captures[0].read_text(), output)
                self.assertEqual(captures[0].stat().st_mode & 0o777, 0o600)

    def test_bootstrap_refuses_a_concurrent_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            script, private = self.bootstrap_fixture(Path(directory))
            private.mkdir(parents=True)
            with (private / '.aws-bootstrap.lock').open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(['bash', str(script)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Another bootstrap', result.stderr)
                self.assertFalse(list(private.glob('*.json')))

    def config(self, *files, envfile=None):
        args = ['docker', 'compose']
        if envfile:
            args += ['--env-file', envfile]
        for name in files:
            args += ['-f', name]
        return json.loads(subprocess.check_output(args + ['config', '--format', 'json'], cwd=ROOT,
                         env=dict(os.environ, OBSERVABILITY_ROOT_DIR=str(ROOT))))

    def test_cloud_stack_enables_siem_without_publishing_internal_services(self):
        services = self.config('docker-compose.yml', 'observability/docker-compose.web-aws.yml', envfile='.env.aws.example')['services']
        for flag in ('SIEM_ENABLED', 'SIEM_SECURITY_EVENTS_ENABLED', 'SIEM_UEBA_ENABLED', 'SIEM_PREVENTION_ENABLED'):
            self.assertEqual(services['app']['environment'][flag], 'true')
        self.assertEqual(services['app']['environment']['SIEM_PREVENTION_DEMO_ENABLED'], 'false')
        self.assertEqual(services['app']['environment']['SPRING_PROFILES_ACTIVE'], '')
        for name in ('app', 'nginx', 'db', 'redis', 'ueba-worker'):
            self.assertFalse(services[name].get('ports'))
        self.assertEqual(services['gateway']['restart'], 'unless-stopped')
        self.assertIn('uid=10001', services['gateway']['tmpfs'][0])
        self.assertIn('mode=0700', services['gateway']['tmpfs'][0])
        recovery = next(port for port in services['gateway']['ports'] if port['target'] == 8089)
        self.assertEqual(recovery['host_ip'], '127.0.0.1')

    def test_web_deploy_requires_private_provider_keys_from_aws_only_bundle(self):
        deploy = (ROOT / 'observability/scripts/deploy-web.sh').read_text()
        fetch = (ROOT / 'observability/scripts/fetch-aws-web-bundle.sh').read_text()
        self.assertIn('AWS_PROVIDER_KEYS_DIR:?Set AWS_PROVIDER_KEYS_DIR', deploy)
        self.assertIn('"$AWS_WEB_BUNDLE_DIR/prevention"', deploy)
        self.assertNotIn('$ROOT_DIR/.secrets/prevention', deploy)
        self.assertIn('[ "$mode" = "600" ]', deploy)
        self.assertIn('install -d -m 0700 "$dest/prevention"', fetch)

    def test_monitor_private_binding_is_only_added_by_aws_overlay(self):
        local = self.config('observability/docker-compose.monitor.yml')['services']['elasticsearch']
        self.assertFalse(local.get('ports'))
        cloud = self.config('observability/docker-compose.monitor.yml', 'observability/docker-compose.monitor-aws.yml')['services']['elasticsearch']
        self.assertEqual([(port['host_ip'], port['target']) for port in cloud['ports']], [('10.20.10.20', 9200)])

    def test_operator_wrapper_refuses_local_mutation(self):
        result = subprocess.run(['bash', str(ROOT / 'observability/scripts/aws-compose.sh'), 'web', 'up'], capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_cost_gate_includes_idle_storage_ipv4_and_tax(self):
        module = load('aws-preflight')
        rates = dict(instance_hour='0.10', gp3_gb_month='0.10', snapshot_gb_month='0.05',
                     ipv4_hour='0.005', egress_gb='0.10', tax_multiplier='1.10')
        self.assertEqual(str(module.estimate(rates)), '17.49')
        checked_rates = json.loads((ROOT / 'observability/aws-cost-rates.checked.json').read_text())
        self.assertEqual(module.SNAPSHOT_STORAGE_GB_UPPER_BOUND, 140)
        self.assertEqual(str(module.estimate(checked_rates)), '20.39')
        rates['instance_hour'] = -1
        with self.assertRaises(ValueError):
            module.estimate(rates)

    def test_latency_summary_uses_nearest_rank_and_has_no_empty_success_value(self):
        module = load('measure-aws-access-latency')
        self.assertIn('https://10.20.10.20:9200/', module.REMOTE)
        self.assertNotIn('https://127.0.0.1:9200/', module.REMOTE)
        self.assertEqual(module.percentile(list(range(1, 31)), .95), 29)
        self.assertEqual(module.percentile(list(range(1, 31)), .5), 15)
        self.assertIsNone(module.percentile([], .95))

    def test_operator_rejects_remote_cleartext_and_credential_urls(self):
        client = load('aws-soc').Client
        for value in ('http://8.8.8.8', 'http://user:pass@127.0.0.1', 'http://127.0.0.1/api', 'http://127.0.0.1?x=y'):
            with self.assertRaises(ValueError):
                client(value)

    def test_login_retries_only_rate_limits_and_stops_after_three_attempts(self):
        module = load('aws-soc')
        credential = {'username': 'fixture', 'password': 'fixture'}
        client = module.Client('http://127.0.0.1:18088')
        rate_limit = urllib.error.HTTPError(client.origin, 429, 'fixture', {}, None)
        with patch.object(client, 'request', side_effect=[rate_limit, {'user': {}}]) as request, \
                patch.object(module.time, 'sleep') as sleep:
            client.login(credential)
            self.assertEqual(request.call_count, 2)
            sleep.assert_called_once_with(65)
        with patch.object(client, 'request', side_effect=rate_limit) as request, \
                patch.object(module.time, 'sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                client.login(credential)
            self.assertEqual(request.call_count, 3)
            self.assertEqual(sleep.call_count, 2)
        unauthorized = urllib.error.HTTPError(client.origin, 401, 'fixture', {}, None)
        with patch.object(client, 'request', side_effect=unauthorized) as request, \
                patch.object(module.time, 'sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                client.login(credential)
            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()

    def test_training_uses_closed_past_windows_without_weakening_server_guard(self):
        module = load('aws-soc')
        payloads = []
        class FakeClient:
            def __init__(self, origin):
                pass
            def login(self, credential):
                pass
            def request(self, method, path, body=None):
                if method == 'POST' and path == '/api/siem/ueba/training-jobs':
                    payloads.append(body)
                return {'id': 'fixture', 'status': 'SUCCEEDED', 'data_provenance': 'DEMO_ONLY',
                        'model_version': 'model-fixture'}
        with patch.object(module, 'Client', FakeClient), patch('builtins.print'):
            module.train(SimpleNamespace(url='http://127.0.0.1:18089'), {'accounts': {'admin': {}}})
        end = datetime.fromisoformat(payloads[0]['to'])
        start = datetime.fromisoformat(payloads[0]['from'])
        self.assertLessEqual(end, datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15))
        self.assertEqual(end - start, timedelta(days=14))

    def test_soc_workflow_fixture_scope_can_differ_from_operator_dataset_only_when_explicit(self):
        module = load('verify-aws-soc-workflow')
        operator_dataset = 'aws-demo01'
        fixture_dataset, default_ids = module.fixture_scope(operator_dataset)
        self.assertEqual(fixture_dataset, operator_dataset)
        self.assertEqual(default_ids, {f'ueba-demo-{operator_dataset}-{index}' for index in range(1, 6)})

        fixture_dataset, explicit_ids = module.fixture_scope(operator_dataset, 'aws515-20261012')
        self.assertEqual(fixture_dataset, 'aws515-20261012')
        self.assertEqual(explicit_ids, {f'ueba-demo-aws515-20261012-{index}' for index in range(1, 6)})
        self.assertNotIn('ueba-demo-aws-demo01-1', explicit_ids)
        for invalid in ('../aws-demo01', 'aws515-20261012;DROP', ''):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                module.fixture_scope(operator_dataset, invalid)
        with self.assertRaises(ValueError):
            module.fixture_scope('../aws-demo01')

    def test_soc_verifier_requires_customer_and_l1_denial(self):
        module = load('aws-soc')
        observed = []
        class FakeClient:
            customer_allowed = False
            l1_allowed = False
            def __init__(self, origin):
                self.role = None
            def login(self, credential):
                self.role = credential['role']
            def request(self, method, path, body=None):
                observed.append((self.role, method, path))
                if path.endswith('/activate?version=0') and not self.l1_allowed:
                    raise urllib.error.HTTPError(path, 403, 'denied', {}, None)
                if path == '/api/siem/status' and self.role == 'Customer' and not self.customer_allowed:
                    raise urllib.error.HTTPError(path, 403, 'denied', {}, None)
                if path == '/api/siem/ueba/status':
                    return {'worker_available': True, 'model_available': True,
                            'active_model_provenance': 'DEMO_ONLY'}
                if path == '/api/siem/prevention/status':
                    return {'gateway_state': 'APPLIED', 'active_signatures': 1,
                            'ipinfo_state': 'CONFIGURED', 'abuse_ip_db_state': 'CONFIGURED'}
                if path.startswith('/api/siem/ip-intelligence'):
                    return [{'provider': provider, 'status': 'FRESH', 'data_provenance': 'REAL',
                             'observed_at': 'fixture'} for provider in ('IPINFO', 'ABUSEIPDB')]
                return {}
        state = {'dataset': 'fixture', 'accounts': {role: {'role': role} for role in ('admin', 'l1', 'l2')}}
        with tempfile.TemporaryDirectory() as directory:
            customer_file = Path(directory) / 'customer.json'
            customer_file.write_text(json.dumps([{'role': 'Customer'}]))
            args = SimpleNamespace(url='http://127.0.0.1:18088', customer_credentials=customer_file)
            with patch.object(module, 'Client', FakeClient), patch('builtins.print') as output:
                module.verify(args, state)
                self.assertTrue(json.loads(output.call_args.args[0])['passed'])
                self.assertIn(('Customer', 'POST', '/api/auth/logout'), observed)
                FakeClient.customer_allowed = True
                with self.assertRaisesRegex(RuntimeError, 'Customer SIEM access'):
                    module.verify(args, state)
                FakeClient.customer_allowed = False
                FakeClient.l1_allowed = True
                with self.assertRaisesRegex(RuntimeError, 'L1 activation'):
                    module.verify(args, state)

    def test_waf_cleanup_revokes_only_new_signature_block_and_disables_canary(self):
        module = load('verify-aws-waf-lifecycle')
        source_ip = '203.0.113.8'
        blocks = [
            {'id': 'baseline', 'ip_address': source_ip, 'source_type': 'SIGNATURE',
             'reason': module.AUTO_SIGNATURE_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'revoked_at': None, 'version': 1},
            {'id': 'new-manual', 'ip_address': source_ip, 'source_type': 'MANUAL',
             'reason': module.AUTO_SIGNATURE_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'revoked_at': None, 'version': 2},
            {'id': 'new-signature', 'ip_address': source_ip, 'source_type': 'SIGNATURE',
             'reason': module.AUTO_SIGNATURE_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'revoked_at': None, 'version': 3},
        ]

        class FakeClient:
            def __init__(self):
                self.signature = {'id': 'canary', 'version': 7, 'status': 'ACTIVE'}
                self.revoked = []
                self.logged_out = False

            def request(self, method, path, body=None):
                if method == 'GET' and path.startswith('/api/siem/ip-blocks'):
                    return {'content': blocks, 'has_next': False}
                if method == 'POST' and '/revoke?' in path:
                    block_id = path.split('/ip-blocks/', 1)[1].split('/revoke?', 1)[0]
                    self.revoked.append(block_id)
                    return {}
                if method == 'GET' and path.startswith('/api/siem/signatures'):
                    return {'content': [self.signature], 'has_next': False}
                if method == 'POST' and '/disable?' in path:
                    self.signature['status'] = 'DISABLED'
                    self.signature['version'] += 1
                    return self.signature
                if method == 'POST' and path == '/api/auth/logout':
                    self.logged_out = True
                    return {}
                raise AssertionError((method, path))

        client = FakeClient()
        errors = module.cleanup_artifacts(client, [client], source_ip, {'baseline'}, 'canary')
        self.assertEqual(errors, [])
        self.assertEqual(client.revoked, ['new-signature'])
        self.assertEqual(client.signature['status'], 'DISABLED')
        self.assertTrue(client.logged_out)

    def test_auth_scan_cleanup_only_revokes_new_known_automatic_blocks(self):
        module = load('verify-aws-auth-scan-lifecycle')
        source_ip = '203.0.113.8'
        rows = [
            {'id': 'baseline', 'ip_address': source_ip, 'source_type': 'SCAN',
             'reason': module.SCAN_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'started_at': '2026-10-13T00:00:00', 'revoked_at': None, 'version': 1},
            {'id': 'new-repeated-scan', 'ip_address': source_ip, 'source_type': 'SCAN',
             'reason': module.SCAN_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'started_at': '2026-10-13T00:00:00', 'revoked_at': None, 'version': 2},
            {'id': 'new-reputation-scan', 'ip_address': source_ip, 'source_type': 'SCAN',
             'reason': module.REPUTATION_SCAN_REASON, 'expires_at': '2099-01-01T00:00:00',
             'started_at': '2026-10-13T00:00:00', 'revoked_at': None, 'version': 3},
            {'id': 'new-manual', 'ip_address': source_ip, 'source_type': 'MANUAL',
             'reason': 'Operator block for unrelated incident', 'expires_at': '2099-01-01T00:00:00',
             'started_at': '2026-10-13T00:00:00', 'revoked_at': None, 'version': 4},
            {'id': 'other-ip', 'ip_address': '203.0.113.9', 'source_type': 'SCAN',
             'reason': module.SCAN_BLOCK_REASON, 'expires_at': '2099-01-01T00:00:00',
             'started_at': '2026-10-13T00:00:00', 'revoked_at': None, 'version': 5},
        ]

        class FakeClient:
            def __init__(self):
                self.revoked = []
            def request(self, method, path, body=None):
                if method == 'GET' and path.startswith('/api/siem/ip-blocks'):
                    return {'content': rows, 'has_next': False}
                if method == 'POST' and '/revoke?' in path:
                    block_id = path.split('/ip-blocks/', 1)[1].split('/revoke?', 1)[0]
                    self.revoked.append(block_id)
                    next(row for row in rows if row['id'] == block_id)['revoked_at'] = '2026-10-13T00:01:00'
                    return {}
                raise AssertionError((method, path))

        client = FakeClient()
        revoked, errors = module.cleanup_test_blocks(client, [client], source_ip, {'baseline'})
        self.assertEqual(errors, [])
        self.assertEqual(set(revoked), {'new-repeated-scan', 'new-reputation-scan'})
        self.assertEqual(set(client.revoked), set(revoked))
        self.assertIsNone(next(row for row in rows if row['id'] == 'new-manual')['revoked_at'])
        self.assertIsNone(next(row for row in rows if row['id'] == 'other-ip')['revoked_at'])

    def test_auth_scan_window_and_reputation_gates_are_exact(self):
        module = load('verify-aws-auth-scan-lifecycle')
        now = datetime(2026, 10, 13, 11, 12, 34, tzinfo=timezone.utc)
        first = module.next_minute_probe_start(now)
        second = module.next_adjacent_minute_probe_start(first)
        self.assertEqual(first, datetime(2026, 10, 13, 11, 13, 5, tzinfo=timezone.utc))
        self.assertEqual(second, datetime(2026, 10, 13, 11, 14, 30, tzinfo=timezone.utc))
        high = [{'provider': 'ABUSEIPDB', 'status': 'FRESH', 'data_provenance': 'REAL',
                 'abuse_score': 80, 'total_reports': 3, 'distinct_reporters': 2}]
        self.assertTrue(module.reputation_can_block_one_scan(high))
        self.assertFalse(module.reputation_can_block_one_scan([{**high[0], 'data_provenance': 'DEMO_ONLY'}]))
        self.assertFalse(module.reputation_can_block_one_scan([{**high[0], 'abuse_score': 79}]))
        providers = [
            {'provider': 'IPINFO', 'status': 'FRESH', 'data_provenance': 'REAL', 'observed_at': 't1'},
            {'provider': 'ABUSEIPDB', 'status': 'FRESH', 'data_provenance': 'REAL', 'observed_at': 't2'},
        ]
        self.assertTrue(module.provider_rows_ready(providers))
        self.assertEqual(module.provider_observation_map(providers), {'IPINFO': 't1', 'ABUSEIPDB': 't2'})
        self.assertFalse(module.provider_rows_ready([providers[0]]))

    def test_auth_scan_public_probe_uses_csrf_cookie_and_keeps_redirects_disabled(self):
        module = load('verify-aws-auth-scan-lifecycle')
        observed = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path == '/api/auth/csrf':
                    body = b'{"token":"csrf-fixture"}'
                    observed.append(('csrf', self.path))
                    self.send_response(200)
                    self.send_header('Set-Cookie', 'session=fixture; Path=/; HttpOnly')
                else:
                    body = b'{}'
                    self.send_response(404 if self.path.startswith('/assets/') else 200)
                    observed.append(('get', self.path))
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                data = json.loads(self.rfile.read(size))
                observed.append(('login', self.headers.get('X-XSRF-TOKEN'),
                                 self.headers.get('Cookie'), data.get('username')))
                self.send_response(401)
                self.end_headers()

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            probe = module.PublicWebProbe(f'http://127.0.0.1:{server.server_port}')
            self.assertEqual(probe.failed_login('synthetic-missing', 'not-a-real-password'), 401)
            self.assertEqual(probe.request('GET', '/assets/owned-missing.css'), 404)
            login = next(row for row in observed if row[0] == 'login')
            self.assertEqual(login[1], 'csrf-fixture')
            self.assertIn('session=fixture', login[2])
            self.assertEqual(login[3], 'synthetic-missing')
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_client_fetches_csrf_and_keeps_only_in_memory_cookies(self):
        observed = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                body = b'{"token":"csrf-test"}' if self.path.endswith('/csrf') else b'{"enabled":true}'
                observed.append((self.path, self.headers.get('Cookie')))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                observed.append((self.path, self.headers.get('X-XSRF-TOKEN')))
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(200)
                self.send_header('Set-Cookie', 'access_token=test-only; Path=/; HttpOnly')
                self.end_headers()
                self.wfile.write(b'{"user":{"role":"Admin"}}')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = load('aws-soc').Client(f'http://127.0.0.1:{server.server_port}')
            client.login({'username': 'fixture', 'password': 'fixture'})
            client.request('GET', '/api/siem/status')
            self.assertIn(('/api/auth/login', 'csrf-test'), observed)
            self.assertIn(('/api/siem/status', 'access_token=test-only'), observed)
        finally:
            server.shutdown(); server.server_close(); thread.join()

if __name__ == '__main__':
    unittest.main()
