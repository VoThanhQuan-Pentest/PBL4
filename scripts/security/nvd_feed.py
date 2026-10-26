#!/usr/bin/env python3
"""Refuse a stale official NIST bulk feed before bootstrapping Dependency-Check."""
from datetime import datetime, timedelta, timezone
import urllib.request

METADATA = 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta'


def validate_metadata(text, now):
    fields = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    modified = datetime.fromisoformat(fields['lastModifiedDate'].replace('Z', '+00:00'))
    if modified.tzinfo is None:
        raise ValueError('NVD feed must carry a timezone')
    age = now - modified
    if age < -timedelta(minutes=2) or age > timedelta(hours=48):
        raise ValueError('Official NVD bulk feed is stale or future-dated; audit remains blocked')
    digest = fields.get('sha256', '')
    if len(digest) != 64 or any(c not in '0123456789abcdefABCDEF' for c in digest):
        raise ValueError('Official NVD metadata has no SHA-256 checksum')
    return modified.isoformat()


def main():
    with urllib.request.urlopen(METADATA, timeout=20) as response:
        data = response.read(16385)
    if len(data) > 16384:
        raise ValueError('NVD metadata exceeds its bound')
    modified = validate_metadata(data.decode('utf-8'), datetime.now(timezone.utc))
    print('Official NIST feed freshness verified: ' + modified)


if __name__ == '__main__': main()
