import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('docker'), 'Docker Compose is required for static rendering only')
class TopologyTest(unittest.TestCase):
    def test_only_the_scanner_network_is_externally_isolated_and_browser_ports_remain_loopback(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {**os.environ, 'OBSERVABILITY_ROOT_DIR': str(ROOT), 'ASVS_TLS_DIR': temporary,
                   'UEBA_OPERATOR_GID': str(os.getgid())}
            args = ['docker', 'compose', '--env-file', '.env.e2e.example', '--project-name',
                    'pbl4-observability-runtime-123-1', '--profile', 'observability']
            for file in ['docker-compose.yml', 'docker-compose.e2e.yml',
                         'observability/docker-compose.monitor.yml', 'observability/docker-compose.local.yml',
                         'security/asvs/docker-compose.tls.yml']:
                args += ['-f', file]
            output = subprocess.run(args+['config', '--format', 'json'], cwd=ROOT, env=env,
                                    capture_output=True, text=True, check=True)
            config = json.loads(output.stdout)
        self.assertFalse(config['networks']['flare-internal'].get('internal', False))
        self.assertTrue(config['networks']['asvs-scanner']['internal'])
        scanner_peers = [name for name, service in config['services'].items()
                         if 'asvs-scanner' in service.get('networks', {})]
        self.assertEqual(['tls-edge'], scanner_peers)
        for service, port in [('tls-edge', 8443), ('mailpit', 8025), ('gateway', 8088)]:
            ports = config['services'][service]['ports']
            self.assertTrue(any(p['host_ip'] == '127.0.0.1' and str(p['published']) == str(port) for p in ports))
        self.assertTrue(config['services']['tls-edge']['read_only'])
        self.assertEqual('true', config['services']['app']['environment']['APP_LOGIN_OTP_ENABLED'])
