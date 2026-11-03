import ipaddress
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
    def render(self, overrides=None):
        with tempfile.TemporaryDirectory() as temporary:
            env = {**os.environ, 'OBSERVABILITY_ROOT_DIR': str(ROOT), 'ASVS_TLS_DIR': temporary,
                   'UEBA_OPERATOR_GID': str(os.getgid()), **(overrides or {})}
            args = ['docker', 'compose', '--env-file', '.env.e2e.example', '--project-name',
                    'pbl4-observability-runtime-123-1', '--profile', 'observability']
            for file in ['docker-compose.yml', 'docker-compose.e2e.yml',
                         'observability/docker-compose.monitor.yml', 'observability/docker-compose.local.yml',
                         'security/asvs/docker-compose.tls.yml']:
                args += ['-f', file]
            output = subprocess.run(args+['config', '--format', 'json'], cwd=ROOT, env=env,
                                    capture_output=True, text=True, check=True)
            return json.loads(output.stdout)

    def test_only_the_scanner_network_is_externally_isolated_and_browser_ports_remain_loopback(self):
        config = self.render()
        self.assertFalse(config['networks']['flare-internal'].get('internal', False))
        self.assertTrue(config['networks']['asvs-scanner']['internal'])
        scanner_peers = [name for name, service in config['services'].items()
                         if 'asvs-scanner' in service.get('networks', {})]
        self.assertEqual(['tls-edge'], scanner_peers)
        for service, port in [('tls-edge', 8443), ('mailpit', 8025), ('gateway', 8088)]:
            ports = config['services'][service]['ports']
            self.assertTrue(any(p['host_ip'] == '127.0.0.1' and str(p['published']) == str(port) for p in ports))
        self.assertTrue(config['services']['tls-edge']['read_only'])
        edge = config['services']['tls-edge']
        self.assertEqual('diagnostics-runtime', edge['build']['target'])
        self.assertEqual(['/usr/local/bin/nginx-diagnostics'], edge['entrypoint'])
        self.assertEqual('nginx', edge['command'][0])
        self.assertEqual('101:101', edge['user'])
        self.assertEqual('1048576', edge['environment']['NGINX_DIAGNOSTICS_MAX_BYTES'])
        self.assertTrue(any(item.startswith('/var/log/nginx:') and 'size=4m' in item
                            and 'uid=101' in item and 'gid=101' in item for item in edge['tmpfs']))
        self.assertEqual('true', config['services']['app']['environment']['APP_LOGIN_OTP_ENABLED'])
        self.assertEqual('900', config['services']['app']['environment']['APP_SESSION_IDLE_SECONDS'])
        self.assertEqual('28800', config['services']['app']['environment']['APP_JWT_EXPIRATION_SECONDS'])

    def test_tls_edge_has_one_explicit_trusted_identity_for_default_and_custom_subnets(self):
        for subnet, gateway_ip, edge_ip in [('172.31.0.0/24', '172.31.0.50', '172.31.0.51'),
                                           ('172.25.42.0/24', '172.25.42.50', '172.25.42.51')]:
            with self.subTest(subnet=subnet):
                config = self.render({'FLARE_INTERNAL_SUBNET': subnet, 'FLARE_GATEWAY_PRIVATE_IP': gateway_ip,
                                      'ASVS_TLS_EDGE_PRIVATE_IP': edge_ip})
                actual = config['services']['tls-edge']['networks']['flare-internal']['ipv4_address']
                self.assertEqual(edge_ip, actual)
                self.assertIn(ipaddress.ip_address(actual), ipaddress.ip_network(subnet))
                self.assertNotEqual(gateway_ip, actual)
                self.assertEqual(edge_ip+'/32', config['services']['gateway']['environment']['PREVENTION_TRUSTED_PROXY_CIDRS'])
                self.assertEqual(gateway_ip+'/32', config['services']['nginx']['environment']['NGINX_TRUSTED_PROXY_CIDR'])
                addresses = [(service.get('networks', {}).get('flare-internal') or {}).get('ipv4_address')
                             for service in config['services'].values()]
                self.assertEqual(1, addresses.count(edge_ip))
