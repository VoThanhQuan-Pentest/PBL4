#!/usr/bin/env python3
"""Encrypt diagnostics on failure; publish only nonsecret status/count receipts."""
import json
import os
from pathlib import Path
import subprocess
from ci_scope import require_ci_scope
from run_zap import encrypt


def main():
    project, root = require_ci_scope()
    output = Path(os.environ['RUNNER_TEMP'])/'asvs-results'; output.mkdir(mode=0o700, exist_ok=True)
    args = ['docker', 'compose', '--env-file', '.env.e2e.example', '--project-name', project, '--profile', 'observability']
    for file in os.environ['OBSERVABILITY_COMPOSE_FILES'].split(':'): args += ['-f', file]
    for label, command in [('compose-log', ['logs', '--no-color']), ('compose-state', ['ps', '--all'])]:
        raw = output/(label+'.private.txt')
        with raw.open('wb') as handle:
            raw.chmod(0o600)
            subprocess.run(args+command, stdout=handle, stderr=subprocess.STDOUT, timeout=30)
        encrypt(raw, output/(label+'.cms'), root/'security/asvs/evidence-recipient.crt')
        raw.unlink()
    # The existing pipeline verifier uses its own receipt name; retain it encrypted if present.
    for candidate in (root/'observability/runtime').glob('*verification*.json'):
        encrypt(candidate, output/(candidate.stem+'.cms'), root/'security/asvs/evidence-recipient.crt')
    print(json.dumps({'source_sha': os.environ['GITHUB_SHA'], 'diagnostics': 'ENCRYPTED', 'asvs_l2_established': False}))


if __name__ == '__main__': main()
