import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import prepare_ci_tls


class DisposableTlsTest(unittest.TestCase):
    def test_installer_rejects_local_execution_before_any_command_or_directory_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'tls'
            env = {'GITHUB_ACTIONS': 'false', 'ASVS_TLS_DIR': str(root), 'RUNNER_TEMP': temporary}
            with patch.dict(os.environ, env, clear=True), patch.object(prepare_ci_tls, 'run') as commands:
                with self.assertRaises(RuntimeError):
                    prepare_ci_tls.main()
                commands.assert_not_called()
            self.assertFalse(root.exists())

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for real disposable certificate checks')
    def test_actual_generated_keys_chain_and_hostnames_without_installing_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Invoke only generation: never the installer, sudo, NSS or system trust-store changes.
            prepare_ci_tls._generate_certificates(root)
            for name in ('ca', 'server'):
                details = self.openssl('x509', '-in', str(root/f'{name}.crt'), '-noout', '-text')
                self.assertIn(b'Public-Key: (3072 bit)', details)
                self.assertIn(b'sha256WithRSAEncryption', details)
                self.assertEqual(0o600, stat.S_IMODE((root/f'{name}.key').stat().st_mode))
            self.openssl('verify', '-CAfile', str(root/'ca.crt'), str(root/'server.crt'))
            for host in ('app.soc.test', 'attacker.test'):
                self.openssl('verify', '-CAfile', str(root/'ca.crt'),
                             '-verify_hostname', host, str(root/'server.crt'))
            # x509 -checkhost historically exits 0 on mismatch in OpenSSL 3.0;
            # verify checks both chain and hostname and reliably rejects it.
            wrong_host = subprocess.run(['openssl', 'verify', '-CAfile', str(root/'ca.crt'),
                                         '-verify_hostname', 'untrusted.example', str(root/'server.crt')],
                                        capture_output=True, timeout=15)
            self.assertNotEqual(0, wrong_host.returncode)
            self.assertEqual(self.openssl('pkey', '-in', str(root/'server.key'), '-pubout'),
                             self.openssl('x509', '-in', str(root/'server.crt'), '-pubkey', '-noout'))

    @staticmethod
    def openssl(*args):
        return subprocess.run(['openssl', *args], check=True, capture_output=True, timeout=15).stdout


if __name__ == '__main__':
    unittest.main()
