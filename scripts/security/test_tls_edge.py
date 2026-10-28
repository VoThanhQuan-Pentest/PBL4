import http.client
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
        cls.image = re.search(r'image: (nginx:\S+)', (ROOT/'security/asvs/docker-compose.tls.yml').read_text())[1]
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
                    '--entrypoint', 'sh', cls.image,
                    '-c', 'nginx -c /run/mock.conf && exec sleep 3600')
        cls.command('docker', 'run', '-d', '--name', cls.names[2], *common, '--memory', '64m',
                    '-p', '127.0.0.1::8443', '-v', f'{ROOT}/security/asvs/tls/nginx.conf:/run/tls.conf:ro',
                    '-v', f'{cls.directory}/server.crt:/run/asvs/server.crt:ro',
                    '-v', f'{cls.directory}/server.key:/run/asvs/server.key:ro',
                    '--entrypoint', 'nginx', cls.image, '-c', '/run/tls.conf', '-g', 'daemon off;')
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
    def request(cls, path):
        with socket.create_connection(('127.0.0.1', cls.port), timeout=4) as raw:
            with cls.context.wrap_socket(raw, server_hostname='app.soc.test') as connection:
                connection.sendall(f'GET {path} HTTP/1.1\r\nHost: app.soc.test\r\nConnection: close\r\n\r\n'.encode())
                response = http.client.HTTPResponse(connection)
                response.begin()
                return response.status, response.getheaders(), response.read(65536), connection.version()

    def security_headers(self, fields):
        for name in ('Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options',
                     'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy'):
            self.assertEqual(1, sum(key.lower() == name.lower() for key, _ in fields), name)
        headers = {key.lower(): value for key, value in fields}
        self.assertIn("base-uri 'none'", headers['content-security-policy'])
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
        # Leave the fixture network endpoint alive but close its HTTP listener:
        # TCP rejects immediately, generating a genuine TLS-edge 502 response.
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


if __name__ == '__main__':
    unittest.main()
