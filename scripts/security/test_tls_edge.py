import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import uuid
import prepare_ci_tls

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('docker') and shutil.which('openssl'), 'Docker and OpenSSL are required')
class TlsEdgeTest(unittest.TestCase):
    @classmethod
    def command(cls, *args, check=True):
        return subprocess.run(args, check=check, capture_output=True, timeout=60)

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.names = ['asvs-tls-test-' + uuid.uuid4().hex for _ in range(3)]
        cls.addClassCleanup(cls.cleanup_containers)
        cls.image = os.environ.get('NGINX_TLS_EDGE_TEST_IMAGE', 'flare-asvs-tls-edge:ci')
        cls.base_image = re.search(r'FROM (nginx:\S+) AS diagnostics-runtime',
                                   (ROOT/'nginx/Dockerfile').read_text())[1]
        cls.csp = re.search(r'Content-Security-Policy "([^"]+)"', (ROOT/'nginx/security-headers.conf').read_text())[1]
        prepare_ci_tls._generate_certificates(cls.directory)
        fixture_headers = (
            f'add_header Content-Security-Policy "{cls.csp}" always;'
            'add_header X-Content-Type-Options nosniff always;'
            'add_header X-Frame-Options DENY always;'
            'add_header Referrer-Policy strict-origin-when-cross-origin always;'
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;'
            'add_header Strict-Transport-Security "max-age=1" always;')
        fixture = (
            'pid /tmp/mock.pid; error_log /dev/stderr warn; events {} http { access_log off;'
            'client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy;'
            'fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;'
            'server { listen 8082; default_type text/plain;'
            f'location / {{ {fixture_headers} return 200 "$host|$http_x_forwarded_proto"; }}'
            f'location = /auth-denied {{ {fixture_headers} default_type application/json;'
            'add_header Cache-Control no-store always; return 401 \'{"code":"UNAUTHORIZED"}\'; }}}')
        (cls.directory/'mock.conf').write_text(fixture)
        # A dedicated fixture bridge is required for Docker's loopback-only port
        # publication; neither container joins an application network or volume.
        cls.command('docker', 'network', 'create', cls.names[0])
        uid, gid = os.getuid(), os.getgid()
        # Match the invoking UID so synthetic 600-mode keys remain readable
        # without changing host ownership or installing any CA in the host trust store.
        common = ['--network', cls.names[0], '--user', f'{uid}:{gid}', '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges:true', '--cpus', '0.5',
                  '--tmpfs', f'/tmp:rw,noexec,nosuid,size=16m,mode=0700,uid={uid},gid={gid}']
        cls.command('docker', 'run', '-d', '--name', cls.names[1], '--network-alias', 'gateway',
                    *common, '--memory', '32m', '-v', f'{cls.directory}/mock.conf:/run/mock.conf:ro',
                    '--entrypoint', 'sh', cls.base_image,
                    '-c', 'nginx -c /run/mock.conf && exec sleep 3600')
        cls.tls_options = [*common, '--memory', '64m',
                           '-e', 'NGINX_DIAGNOSTICS_MAX_BYTES=1048576',
                           '--tmpfs', f'/var/log/nginx:rw,noexec,nosuid,size=4m,mode=0700,uid={uid},gid={gid}',
                           '-v', f'{ROOT}/security/asvs/tls/nginx.conf:/run/tls.conf:ro',
                           '-v', f'{cls.directory}/server.crt:/run/asvs/server.crt:ro',
                           '-v', f'{cls.directory}/server.key:/run/asvs/server.key:ro',
                           '--entrypoint', '/usr/local/bin/nginx-diagnostics']
        cls.command('docker', 'run', '-d', '--name', cls.names[2], *cls.tls_options,
                    '-p', '127.0.0.1::8443', cls.image, 'nginx', '-c', '/run/tls.conf', '-g', 'daemon off;')
        try:
            port = cls.command('docker', 'port', cls.names[2], '8443/tcp').stdout.decode().strip()
        except subprocess.CalledProcessError as failure:
            details = [cls.command('docker', 'logs', name, check=False).stderr.decode() for name in cls.names[1:]]
            raise RuntimeError('Disposable Nginx setup failed: ' + failure.stderr.decode() + '\n'.join(details)) from failure
        cls.port = int(port.rsplit(':', 1)[1])
        cls.context = ssl.create_default_context(cafile=str(cls.directory/'ca.crt'))
        last = 'not ready'
        for attempt in range(30):
            try:
                status = cls.request('/')[0]
                if status == 200:
                    return
                last = f'HTTP status {status}'
            except (OSError, http.client.HTTPException) as failure:
                last = str(failure)
            time.sleep(0.1)
        details = [cls.command('docker', 'logs', name, check=False).stderr.decode() for name in cls.names[1:]]
        raise RuntimeError('Disposable TLS fixture failed to become ready: ' + last + '\n' + '\n'.join(details))

    @classmethod
    def cleanup_containers(cls):
        for name in cls.names[1:]:
            cls.command('docker', 'rm', '-f', name, check=False)
        cls.command('docker', 'network', 'rm', cls.names[0], check=False)

    @classmethod
    def request(cls, path, extra_headers=(), port=None):
        with socket.create_connection(('127.0.0.1', cls.port if port is None else port), timeout=4) as raw:
            with cls.context.wrap_socket(raw, server_hostname='app.soc.test') as connection:
                headers = ''.join(f'{key}: {value}\r\n' for key, value in extra_headers)
                connection.sendall(f'GET {path} HTTP/1.1\r\nHost: app.soc.test\r\n{headers}Connection: close\r\n\r\n'.encode())
                response = http.client.HTTPResponse(connection)
                response.begin()
                return response.status, response.getheaders(), response.read(65536), connection.version()

    def security_headers(self, fields):
        for name in ('Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options',
                     'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy'):
            self.assertEqual(1, sum(key.lower() == name.lower() for key, _ in fields), name)
        headers = {key.lower(): value for key, value in fields}
        self.assertIn("base-uri 'none'", headers['content-security-policy'])
        self.assertIn("object-src 'none'", headers['content-security-policy'])
        self.assertIn("frame-ancestors 'none'", headers['content-security-policy'])
        self.assertIn('max-age=31536000', headers['strict-transport-security'])
        self.assertEqual('nosniff', headers['x-content-type-options'])
        self.assertEqual('DENY', headers['x-frame-options'])
        return headers

    def client(self, *options):
        return subprocess.run(['openssl', 's_client', '-connect', f'127.0.0.1:{self.port}',
                               '-servername', 'app.soc.test', '-CAfile', str(self.directory/'ca.crt'),
                               '-verify_return_error', '-verify_hostname', 'app.soc.test', '-brief', *options],
                              input=b'', capture_output=True, timeout=10)

    def test_readonly_configuration_preflight_uses_the_supervised_command(self):
        result = self.command('docker', 'run', '--rm', *self.tls_options, self.image,
                              'nginx', '-t', '-c', '/run/tls.conf', check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        self.assertNotIn(b'-----BEGIN', result.stdout + result.stderr)

    def test_small_ephemeral_sink_rotates_without_stopping(self):
        config = self.directory / 'rotation.conf'
        original = (ROOT/'security/asvs/tls/nginx.conf').read_text()
        self.assertEqual(1, original.count('proxy_pass http://gateway:8082;'))
        config.write_text(original.replace('proxy_pass http://gateway:8082;',
                                           'proxy_pass http://127.0.0.1:1;'))
        options = [item.replace(f'{ROOT}/security/asvs/tls/nginx.conf:', f'{config}:')
                   .replace('NGINX_DIAGNOSTICS_MAX_BYTES=1048576', 'NGINX_DIAGNOSTICS_MAX_BYTES=4096')
                   for item in self.tls_options]
        name = 'asvs-tls-rotation-' + uuid.uuid4().hex
        self.addCleanup(self.command, 'docker', 'rm', '-f', name, check=False)
        self.command('docker', 'run', '-d', '--name', name, *options,
                     '-p', '127.0.0.1::8443', self.image, 'nginx', '-c', '/run/tls.conf', '-g', 'daemon off;')
        port = int(self.command('docker', 'port', name, '8443/tcp').stdout.decode().strip().rsplit(':', 1)[1])
        for _ in range(30):
            try:
                if self.request('/', port=port)[0] == 502:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        else:
            self.fail('Owned rotation fixture did not become ready')
        for _ in range(150):
            self.assertEqual(502, self.request('/', port=port)[0])
        self.assertEqual(b'true', self.command('docker', 'inspect', '--format',
                                              '{{.State.Running}}', name).stdout.strip())
        for file in ('native-errors.json.log', 'native-errors.json.log.1'):
            data = self.command('docker', 'exec', name, 'cat', '/var/log/nginx/' + file).stdout
            self.assertTrue(0 < len(data) <= 4096)
            self.assertTrue(data.endswith(b'\n'))
            for line in data.splitlines():
                self.assertEqual('nginx', json.loads(line)['observer.type'])

    def test_real_transport_normal_responses_and_edge_generated_errors(self):
        status, fields, body, protocol = self.request('/')
        self.assertEqual(200, status)
        self.assertEqual(b'app.soc.test|https', body)
        self.assertEqual('TLSv1.3', protocol)
        self.assertEqual(self.csp, self.security_headers(fields)['content-security-policy'])
        status, fields, body, _ = self.request('/auth-denied')
        self.assertEqual(401, status)
        self.assertEqual(b'{"code":"UNAUTHORIZED"}', body)
        headers = self.security_headers(fields)
        self.assertEqual('application/json', headers['content-type'])
        self.assertEqual('no-store', headers['cache-control'])
        for options, expected in [
                (['-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'],
                 'ECDHE-RSA-AES256-GCM-SHA384'),
                (['-tls1_3', '-ciphersuites', 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384'],
                 'TLS_AES_256_GCM_SHA384')]:
            result = self.client(*options)
            self.assertEqual(0, result.returncode, result.stderr.decode())
            self.assertIn(expected, (result.stdout + result.stderr).decode())
        for cipher in ('AES128-SHA', 'ECDHE-RSA-AES128-SHA'):
            result = self.client('-tls1_2', '-cipher', cipher)
            self.assertNotEqual(0, result.returncode)
            self.assertRegex((result.stdout + result.stderr).decode(), r'handshake failure|alert number 40')
        for protocol in ('-tls1', '-tls1_1'):
            result = self.client(protocol, '-cipher', 'AES128-SHA:@SECLEVEL=0')
            self.assertNotEqual(0, result.returncode)
            self.assertRegex((result.stdout + result.stderr).decode(), r'protocol version|alert number 70')
        status, fields, _, _ = self.request('/%GG')
        self.assertEqual(400, status)
        headers = self.security_headers(fields)
        self.assertIn("default-src 'none'", headers['content-security-policy'])
        self.assertEqual('text/html; charset=utf-8', headers['content-type'])
        # Keep the fixture endpoint alive while closing only its HTTP listener.
        self.command('docker', 'exec', self.names[1], 'nginx', '-c', '/run/mock.conf', '-s', 'quit')
        for _ in range(20):
            status, fields, _, _ = self.request('/')
            if status == 502:
                break
            time.sleep(0.05)
        self.assertEqual(502, status)
        headers = self.security_headers(fields)
        self.assertIn("default-src 'none'", headers['content-security-policy'])
        self.assertEqual('text/html; charset=utf-8', headers['content-type'])
        query = 'OWNED_TLS_QUERY_CANARY_20261029'
        referrer = 'OWNED_TLS_REFERER_CANARY_20261029'
        encoded = ''.join(f'%{byte:02x}' for byte in query.encode())
        for value in (query, encoded):
            status, fields, _, _ = self.request('/api/health?access_token=' + value,
                [('Referer', 'https://app.soc.test/?token=' + referrer)])
            self.assertEqual(502, status)
            self.security_headers(fields)
        # Drain all three native 502 diagnostics before asserting absence. A
        # baseline record alone must not let delayed canary output pass.
        for _ in range(40):
            captured = self.command('docker', 'logs', self.names[2], check=False)
            native = self.command('docker', 'exec', self.names[2], 'cat',
                                  '/var/log/nginx/native-errors.json.log').stdout
            records = [json.loads(line) for line in native.splitlines()]
            stderr_records = [json.loads(line) for line in captured.stderr.splitlines()]
            if all(sum(item['event.code'] == 'upstream_connect_failed' for item in rows) >= 3
                   for rows in (records, stderr_records)):
                break
            time.sleep(0.05)
        else:
            self.fail('Native canary diagnostics did not drain before privacy assertions')
        for output in (captured.stdout, captured.stderr, native):
            for canary in (query, referrer, encoded):
                self.assertNotIn(canary.encode(), output)
        self.assertIn('upstream_connect_failed', {item['event.code'] for item in records})
        for item in records:
            self.assertEqual({'@timestamp', 'observer.type', 'log.level', 'event.code'}, set(item))
        rss = self.command('docker', 'exec', self.names[2], 'cat', '/proc/1/status').stdout.decode()
        print(json.dumps({'tls_edge_diagnostics_pid1_rss_kib':
                          int(next(line.split()[1] for line in rss.splitlines() if line.startswith('VmRSS:')))}))


if __name__ == '__main__':
    unittest.main()
