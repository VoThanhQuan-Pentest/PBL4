#!/usr/bin/env python3
"""Provision a private CA exclusively on a disposable hosted runner."""
from pathlib import Path
import os
import subprocess
from ci_scope import require_ci_scope


def run(*args, **kwargs):
    subprocess.run(args, check=True, capture_output=True, **kwargs)


def _generate_certificates(root):
    # ASVS 5.0.0-11.2.3: RSA-3072 provides the required 128-bit security strength.
    run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '1',
        '-subj', '/CN=ASVS isolated test CA', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.crt'))
    run('openssl', 'req', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=app.soc.test',
        '-addext', 'subjectAltName=DNS:app.soc.test,DNS:attacker.test',
        '-keyout', str(root/'server.key'), '-out', str(root/'server.csr'))
    run('openssl', 'x509', '-req', '-in', str(root/'server.csr'), '-CA', str(root/'ca.crt'),
        '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-days', '1', '-sha256',
        '-copy_extensions', 'copy', '-out', str(root/'server.crt'))


def main():
    require_ci_scope()
    root = Path(os.environ['ASVS_TLS_DIR']).resolve()
    runner = Path(os.environ['RUNNER_TEMP']).resolve()
    if not root.is_relative_to(runner) or root.exists():
        raise RuntimeError('A new TLS directory under RUNNER_TEMP is required')
    root.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        _generate_certificates(root)
        # Container101 gets only its server key, never the CA private key.
        run('sudo', 'chown', '101:101', str(root/'server.key'))
        run('sudo', 'chmod', '0600', str(root/'server.key'))
        (root/'server.crt').chmod(0o644)
        run('sudo', 'cp', str(root/'ca.crt'), '/usr/local/share/ca-certificates/asvs-ci.crt')
        run('sudo', 'update-ca-certificates')
        nss = Path.home()/'.pki/nssdb'; nss.mkdir(parents=True, exist_ok=True)
        if not (nss/'cert9.db').exists(): run('certutil', '-N', '-d', 'sql:'+str(nss), '--empty-password')
        run('certutil', '-A', '-d', 'sql:'+str(nss), '-n', 'ASVS isolated CA', '-t', 'C,,', '-i', str(root/'ca.crt'))
        run('sudo', 'tee', '-a', '/etc/hosts', input=b'\n127.0.0.1 app.soc.test attacker.test\n')
    finally:
        os.umask(previous)
    print('Disposable TLS CA installed; no certificate verification bypass is enabled.')


if __name__ == '__main__': main()
