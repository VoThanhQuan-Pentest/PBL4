#!/usr/bin/env python3
"""Insert two closed-window DEMO_ONLY evaluation fixtures, never normal training data."""
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / f'observability/scripts/{name}.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--phase', required=True)
    parser.add_argument('--pair', required=True, type=int)
    args = parser.parse_args()
    if ROOT != Path('/opt/flare') or 'FLARE_ENVIRONMENT=aws-lab' not in (ROOT / '.env').read_text().splitlines():
        parser.error('Run only on AWS Web via SSH')
    generator = load('seed-ueba-demo')
    if not generator.DATASET_RE.fullmatch(args.dataset) or not re.fullmatch('latency-[a-z0-9-]{4,32}', args.phase):
        parser.error('Invalid dataset/explicit evaluation phase')
    if not 0 <= args.pair < 30:
        parser.error('Use pairs 0 through 29 for 60 samples')
    seed = load('seed-aws-demo')
    if seed.sql("SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE status='ACTIVE' AND data_provenance='DEMO_ONLY';") != '1':
        parser.error('An ACTIVE DEMO_ONLY model is required')
    now = datetime.now(timezone.utc)
    directory = ROOT / 'observability/runtime/private-latency-fixtures'
    os.umask(0o077)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = directory / (args.phase + '.json')
    if not manifest.exists():
        if args.pair != 0:
            parser.error('Start a fresh phase at pair zero')
        actors = [generator.account_id(args.dataset, index) for index in range(1, 5)]
        rows = seed.sql("SELECT target_user_id,DATE_FORMAT(bucket_start,'%Y-%m-%dT%H:00:00') FROM siem_incidents WHERE origin='UEBA';")
        existing = {tuple(row.split('\t')) for row in rows.splitlines() if row}
        chosen = []
        for hours in range(1, 49):
            start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours)
            stamp = start.replace(tzinfo=None).isoformat()
            for account, actor in enumerate(actors, 1):
                if (actor, stamp) not in existing:
                    chosen.append(dict(account=account, actor=actor, start=stamp))
                if len(chosen) == 30:
                    break
            if len(chosen) == 30:
                break
        if len(chosen) != 60:
            parser.error('Need 60 fresh account/hour combinations')
        with manifest.open('x') as stream:
            json.dump(dict(dataset=args.dataset, samples=chosen), stream)
    schedule = json.loads(manifest.read_text())
    if schedule['dataset'] != args.dataset or len(schedule.get('samples', [])) != 60:
        parser.error('Manifest must belong to this dataset and contain 60 unique combinations')
    samples = []
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        print('START TRANSACTION;')
        for sample in range(args.pair * 2, args.pair * 2 + 2):
            planned = schedule['samples'][sample]
            account, actor = planned['account'], planned['actor']
            # Never reuse an already visible incident: that would fabricate near-zero latency.
            start = datetime.fromisoformat(planned['start']).replace(tzinfo=timezone.utc)
            source = f'198.51.100.{100 + sample}'
            for index in range(65):
                generator.emit_event(args.dataset, args.phase, account, sample * 100 + index,
                    start + timedelta(seconds=index), actor, None, source,
                    'HTTP_REQUEST', 'API_REQUEST', 'FAILURE' if index < 11 else 'SUCCESS',
                    'profile', 403 if index < 11 else 200, 'SCANNER')
            for index in range(6):
                generator.emit_event(args.dataset, args.phase, account, sample * 100 + 65 + index,
                    start + timedelta(minutes=5, seconds=index), None, actor, source,
                    'AUTH', 'LOGIN', 'FAILURE', 'auth', None, 'SCANNER')
            samples.append(dict(sample=sample + 1, target_user_id=actor, source_ip=source,
                                window_start=start.replace(tzinfo=None).isoformat()))
        print('COMMIT;')
    seed.sql(buffer.getvalue())
    # Eligibility requires both a closed window and committed input; the windows are historic.
    print(json.dumps(dict(phase=args.phase, data_provenance='DEMO_ONLY', demo_label='ABNORMAL',
                          eligible_at=datetime.now(timezone.utc).isoformat(), samples=samples)))

if __name__ == '__main__':
    main()
