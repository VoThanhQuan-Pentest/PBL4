#!/usr/bin/env python3
"""Seed and validate an evidence matrix; scanner success never implies ASVS compliance."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'security/asvs/requirements-5.0.0.csv'
CATALOG_SHA256 = '98c8fe911b9edb403af8ee05d3ce8201ecac2659e313b053890a62847cdcf680'
VERSION = '5.0.0'
STATES = {'PASS', 'FAIL', 'NOT_VERIFIED', 'NOT_APPLICABLE'}


def requirements():
    if hashlib.sha256(CATALOG.read_bytes()).hexdigest() != CATALOG_SHA256:
        raise ValueError('Official ASVS catalog digest mismatch')
    with CATALOG.open(encoding='utf-8-sig', newline='') as handle:
        rows = [row for row in csv.DictReader(handle) if int(row['L']) <= 2]
    ids = [row['req_id'] for row in rows]
    if len(rows) != 253 or len(set(ids)) != len(ids):
        raise ValueError('Incomplete or duplicate ASVS L1/L2 catalog')
    return rows


def seed(sha):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('A full source commit SHA is required')
    return {'schema_version': 1, 'asvs_version': VERSION, 'level': 2,
            'source_sha': sha, 'environment': 'isolated-lab',
            'requirements': [{'id': 'v5.0.0-' + row['req_id'][1:],
                'level': int(row['L']), 'chapter': row['chapter_name'],
                'description': row['req_description'], 'status': 'NOT_VERIFIED',
                'rationale': '', 'evidence': [], 'finding_ids': []} for row in requirements()]}


def validate(matrix, *, strict=False):
    if matrix.get('schema_version') != 1 or matrix.get('asvs_version') != VERSION or matrix.get('level') != 2:
        raise ValueError('Wrong matrix schema, ASVS version or assurance level')
    if matrix.get('environment') != 'isolated-lab':
        raise ValueError('This gate supports only the explicitly assessed isolated-lab environment')
    sha = matrix.get('source_sha', '')
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('A full source commit SHA is required')
    expected = {'v5.0.0-' + row['req_id'][1:]: row for row in requirements()}
    rows = matrix.get('requirements')
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError('Every ASVS L1/L2 requirement must be represented')
    seen = set()
    for row in rows:
        key = row['id']
        if key not in expected or key in seen:
            raise ValueError('Unknown or duplicate requirement: ' + key)
        seen.add(key)
        if row.get('level') != int(expected[key]['L']) or row.get('description') != expected[key]['req_description']:
            raise ValueError('Altered standard requirement: ' + key)
        state = row.get('status')
        if state not in STATES:
            raise ValueError('Invalid result state: ' + key)
        evidence = row.get('evidence')
        if not isinstance(evidence, list):
            raise ValueError('Evidence must be an array: ' + key)
        if state in {'PASS', 'NOT_APPLICABLE', 'FAIL'}:
            if not isinstance(row.get('rationale'), str) or not row['rationale'].strip() or not evidence:
                raise ValueError('Result requires rationale and evidence: ' + key)
        for entry in evidence:
            if entry.get('source_sha') != sha or not entry.get('reference') or not entry.get('summary'):
                raise ValueError('Evidence must identify this exact source SHA and reference: ' + key)
            kind = entry.get('kind')
            if kind not in {'source_review', 'automated_test', 'manual_test', 'deployment_check'}:
                raise ValueError('Unsupported evidence kind: ' + key)
            if kind in {'automated_test', 'manual_test', 'deployment_check'}:
                if entry.get('result') not in {'passed', 'failed', 'not_run'}:
                    raise ValueError('Missing actual test/check result: ' + key)
                if state == 'PASS' and entry['result'] != 'passed':
                    raise ValueError('Failed/skipped/unrun test cannot prove PASS: ' + key)
        if state == 'NOT_APPLICABLE' and not any(e['kind'] == 'source_review' for e in evidence):
            raise ValueError('Non-applicability needs source-backed justification: ' + key)
    counts = dict(Counter(row['status'] for row in rows))
    qualified = not any(counts.get(s, 0) for s in ['FAIL', 'NOT_VERIFIED'])
    if strict and not qualified:
        raise ValueError('ASVS L2 is not established: FAIL or NOT_VERIFIED requirements remain')
    return {'asvs_version': VERSION, 'level': 2, 'source_sha': sha, 'environment': 'isolated-lab',
            'requirements_total': len(rows), 'counts': counts,
            'asvs_l2_established_in_declared_environment': qualified,
            'production_model_qualified': False}


def progress(matrix, checkpoint, current_sha, *, require_current=False):
    """Derive progress from evidence; never present an older assessment as current."""
    if not isinstance(current_sha, str) or not re.fullmatch('[0-9a-f]{40}', current_sha):
        raise ValueError('A full current source commit SHA is required')
    if not isinstance(matrix, dict) or not isinstance(checkpoint, dict):
        raise ValueError('Matrix and checkpoint must be JSON objects')
    assessment = validate(matrix)
    counts = {state: assessment['counts'].get(state, 0) for state in sorted(STATES)}
    verified = checkpoint.get('verified')
    cached = verified.get('assessment_progress') if isinstance(verified, dict) else None
    if not isinstance(cached, dict) or not isinstance(cached.get('counts'), dict):
        raise ValueError('Checkpoint assessment cache is missing or malformed')
    cached_counts = cached['counts']
    if (cached.get('source_sha') != assessment['source_sha']
            or set(cached_counts) - STATES
            or any(type(cached_counts.get(state, 0)) is not int
                   or cached_counts.get(state, 0) != counts[state] for state in STATES)):
        raise ValueError('Checkpoint assessment cache disagrees with the evidence matrix')
    if checkpoint.get('pushed_sha') != current_sha:
        raise ValueError('Checkpoint candidate SHA disagrees with current source; refresh the checkpoint')
    current = assessment['source_sha'] == current_sha
    if require_current and not current:
        raise ValueError('Assessment is historical; current-source progress is not established')
    applicable = assessment['requirements_total'] - counts['NOT_APPLICABLE']
    concluded = counts['PASS'] + counts['FAIL']
    completion = round(100 * concluded / applicable, 1) if applicable else None
    passed = round(100 * counts['PASS'] / applicable, 1) if applicable else None
    return {
        'schema_version': 1,
        'current_source_sha': current_sha,
        'snapshot_status': 'CURRENT' if current else 'HISTORICAL',
        'assessment_snapshot': {
            'source_sha': assessment['source_sha'], 'counts': counts,
            'requirements_total': assessment['requirements_total'],
            'applicable': applicable, 'concluded': concluded,
            'completion_percent': completion, 'pass_percent': passed,
        },
        'current_assessment': {
            'completion_percent': completion if current else None,
            'pass_percent': passed if current else None,
            'asvs_l2_established': current and assessment['asvs_l2_established_in_declared_environment'],
        },
        'overall_project_completion_percent': None,
        'candidate_fixes_and_ci_do_not_promote_requirements': True,
        'reassessment_required': not current,
    }


def read_document(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Evidence document exceeds 8 MiB')
    return json.loads(path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('seed')
    create.add_argument('--sha', required=True)
    check = commands.add_parser('validate')
    check.add_argument('matrix', type=Path)
    check.add_argument('--strict', action='store_true')
    report = commands.add_parser('progress')
    report.add_argument('matrix', type=Path)
    report.add_argument('--checkpoint', required=True, type=Path)
    report.add_argument('--require-current', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'seed':
            result = seed(args.sha)
        elif args.command == 'validate':
            result = validate(read_document(args.matrix), strict=args.strict)
        else:
            # Resolve the actual checkout, rather than trusting a caller-supplied "current" SHA.
            current_sha = subprocess.check_output(
                ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
            result = progress(read_document(args.matrix), read_document(args.checkpoint), current_sha,
                              require_current=args.require_current)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    main()
