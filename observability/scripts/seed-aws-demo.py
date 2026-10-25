#!/usr/bin/env python3
"""Explicit AWS-only fixture wrapper. Leaves local-lab seed restrictions intact."""
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def compose(*args, data=None):
    result = subprocess.run([str(ROOT / 'observability/scripts/aws-compose.sh'), 'web', *args],
                            input=data, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('AWS Compose operation failed; inspect container logs (credentials omitted)')
    return result.stdout.strip()

def sql(query):
    return compose('exec', '-T', 'db', 'sh', '-ceu',
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -Ns -u "$MYSQL_USER" "$MYSQL_DATABASE"', data=query)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('normal', 'abnormal', 'verify-normal', 'verify-abnormal'))
    p.add_argument('--dataset', required=True)
    args = p.parse_args()
    if ROOT != Path('/opt/flare') or 'FLARE_ENVIRONMENT=aws-lab' not in (ROOT / '.env').read_text().splitlines():
        p.error('Run only on AWS Web EC2 via SSH')
    spec = importlib.util.spec_from_file_location('demo_generator', ROOT / 'observability/scripts/seed-ueba-demo.py')
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    if not generator.DATASET_RE.fullmatch(args.dataset):
        p.error('Invalid dataset')
    ids = ','.join(generator.quote(generator.account_id(args.dataset, index)) for index in range(1, 5))
    if args.action.startswith('verify-'):
        phase = args.action.removeprefix('verify-').upper()
        events = int(sql(f"SELECT COUNT(*) FROM siem_security_events WHERE demo_label='{phase}' AND (actor_user_id IN ({ids}) OR target_user_id IN ({ids})) AND exported_at IS NOT NULL AND aggregated_at IS NOT NULL;"))
        windows = int(sql(f"SELECT COUNT(*) FROM siem_account_behavior_windows WHERE account_id IN ({ids}) AND demo_label='{phase}' " +
                          ("AND baseline_established=1 AND failed_login_count<=1 AND http_4xx_count<=1 AND http_5xx_count=0 AND sensitive_action_count=0 AND new_ip_flag=0 AND new_user_agent_flag=0 AND unusual_hour_flag=0 AND request_count<60 AND (risk_score IS NULL OR risk_score<30);" if phase == 'NORMAL' else "AND score_status='SCORED_MODEL' AND risk_score>=60;")))
        passed = events >= (2532 if phase == 'NORMAL' else 136) and windows >= (600 if phase == 'NORMAL' else 1)
        print(json.dumps(dict(dataset=args.dataset, phase=phase, exported_aggregated_events=events, qualifying_windows=windows, passed=passed)))
        if not passed:
            raise SystemExit(1)
        return
    os.umask(0o077)
    directory = ROOT / 'observability/runtime/private-credentials'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials_file = directory / f'customers-{args.dataset}.json'
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        print('START TRANSACTION;')
        if args.action == 'normal':
            if not credentials_file.exists():
                if int(sql(f'SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id IN ({ids});')):
                    raise RuntimeError('Dataset already exists without its credential file; choose a fresh ID')
                accounts = [{'username': f'ueba_demo_{args.dataset}_{i}', 'password': 'Aa1#' + secrets.token_urlsafe(24)} for i in range(1, 6)]
                fd = os.open(credentials_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(accounts, stream)
            accounts = json.loads(credentials_file.read_text())
            if len(accounts) != 5:
                raise RuntimeError('Expected four baseline accounts and one cold-start account; use a new dataset')
            hashes = [compose('exec', '-T', 'app', 'java',
                '-Dloader.main=com.flarefitness.backend.ops.AwsLabBootstrap', '-cp', '/app/app.jar',
                'org.springframework.boot.loader.launch.PropertiesLauncher', 'hash-password', data=item['password']) for item in accounts]
            if any(not generator.HASH_RE.fullmatch(value) for value in hashes):
                raise RuntimeError('Unexpected password encoder output')
            now = datetime.now(timezone.utc)
            generator.emit_normal(args.dataset, hashes[:4], now)
            generator.emit_user(args.dataset, 5, hashes[4], now)
            generator.emit_event(args.dataset, 'normal', 5, 0, now - timedelta(minutes=30),
                                 generator.account_id(args.dataset, 5), None, '198.51.100.15',
                                 'HTTP_REQUEST', 'API_REQUEST', 'SUCCESS', 'products', 200, 'CHROMIUM')
        else:
            if int(sql(f'SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id IN ({ids});')) != 4:
                raise RuntimeError('Seed normal dataset first')
            if int(sql("SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE status='ACTIVE' AND data_provenance='DEMO_ONLY';")) != 1:
                raise RuntimeError('Activate a DEMO_ONLY candidate before abnormal fixtures')
            generator.emit_abnormal(args.dataset, datetime.now(timezone.utc))
        print('COMMIT;')
    sql(buffer.getvalue())
    print(f'{args.action} synthetic fixture inserted for {args.dataset}; credentials remain private.')

if __name__ == '__main__':
    main()
