#!/usr/bin/env python3
"""Build a deterministic offline lookup, from pinned public password corpora, without storing plaintext in the app."""
import argparse
import hashlib
import json
from pathlib import Path

REVISION = 'fd02038d8b47e2f9d28d75ab3719f5ecf7f2d571'
SOURCES = {
    'xato': ('Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt',
             '424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51'),
    'rockyou': ('Passwords/Leaked-Databases/rockyou-75.txt',
                'd36811f6d5c8dd78c52738efa730689422ac2a9a0ea28255928ae16fbbbcb83d'),
}


def build(inputs):
    hashes = set()
    evidence = []
    for name, (relative, expected) in SOURCES.items():
        raw = inputs[name].read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Pinned source checksum mismatch: ' + name)
        eligible = set()
        for line in raw.splitlines():
            try: password = line.decode('utf-8')
            except UnicodeDecodeError: continue
            if 12 <= len(password) <= 128 and not password.isspace():
                eligible.add(hashlib.sha256(password.encode('utf-8')).digest())
        if name == 'xato' and len(eligible) < 3000:
            raise ValueError('At least 3000 policy-matching common passwords are required')
        hashes.update(eligible)
        evidence.append({'name': name, 'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/' + REVISION + '/' + relative,
                         'sha256': expected, 'input_bytes': len(raw), 'eligible_entries': len(eligible)})
    binary = b''.join(sorted(hashes))
    return binary, {'revision': REVISION, 'sources': evidence, 'license': 'MIT (SecLists)',
                    'format': 'Sorted distinct SHA-256 digests, 32 bytes per record, unsigned lexicographic order; UTF-8 exact input',
                    'selection': '12..128 Unicode code points, valid UTF-8 nonblank lines; no case folding or input trimming',
                    'entries': len(hashes), 'bytes': len(binary), 'sha256': hashlib.sha256(binary).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xato', type=Path, required=True)
    parser.add_argument('--rockyou', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    args = parser.parse_args()
    binary, metadata = build({'xato': args.xato, 'rockyou': args.rockyou})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(binary)
    args.metadata.write_text(json.dumps(metadata, indent=2)+'\n')
    print(json.dumps({'entries': metadata['entries'], 'bytes': len(binary), 'sha256': metadata['sha256']}))


if __name__ == '__main__': main()
