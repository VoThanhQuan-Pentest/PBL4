#!/usr/bin/env python3
"""Create a fresh AWS lab environment privately; never overwrite an existing file."""
import argparse
import ipaddress
import os
from pathlib import Path
import secrets

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web-ip', required=True)
    args = parser.parse_args()
    ip = ipaddress.IPv4Address(args.web_ip)
    if not ip.is_global:
        parser.error('web-ip must be the Web Elastic IP')
    root = Path(__file__).resolve().parents[2]
    directory = root / '.secrets' / 'aws-lab'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = directory / 'web.env'
    text = (root / '.env.aws.example').read_text()
    replacements = {
        'replace-with-random-16-plus-character-password': secrets.token_hex(24),
        'replace-with-different-random-16-plus-character-password': secrets.token_hex(24),
        'replace-with-at-least-32-random-characters': secrets.token_hex(32),
        'REPLACE_WITH_WEB_ELASTIC_IP': str(ip),
    }
    for original, value in replacements.items():
        text = text.replace(original, value)
    # Redis does not share the MySQL password.
    lines = [f'REDIS_PASSWORD={secrets.token_hex(24)}' if line.startswith('REDIS_PASSWORD=') else line
             for line in text.splitlines()]
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('\n'.join(lines) + '\n')
    print(f'Private environment created at {destination}; transfer to /opt/flare/.env on Web.')

if __name__ == '__main__':
    main()
