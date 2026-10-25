#!/usr/bin/env python3
"""One-time, backup-gated correction of this fresh AWS lab's legacy SIEM date metadata."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def main():
    if ROOT != Path('/opt/flare') or 'FLARE_ENVIRONMENT=aws-lab' not in (ROOT / '.env').read_text().splitlines():
        raise RuntimeError('AWS lab only')
    marker = ROOT / 'observability/runtime/private-backups/utc-direct-jdbc-correction.json'
    if marker.exists():
        raise RuntimeError('Correction journal already exists; do not shift dates twice')
    spec = importlib.util.spec_from_file_location('seed', ROOT / 'observability/scripts/seed-aws-demo.py')
    seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(seed)
    strangers = seed.sql("SELECT COUNT(*) FROM tbl_nguoi_dung WHERE username NOT LIKE 'aws\\_%' AND username NOT LIKE 'ueba\\_demo\\_aws-demo01\\_%';")
    if strangers != '0':
        raise RuntimeError('Refuse correction in a database containing non-lab accounts')
    os.umask(0o077)
    marker.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    subprocess.run([str(ROOT / 'observability/scripts/aws-compose.sh'), 'web', 'stop', 'app'], check=True)
    # A fresh snapshot is taken after the only application writer is stopped.
    backup = marker.parent / 'mysql-before-utc-direct-jdbc.sql.gz'
    with backup.open('xb') as output:
        dumped = subprocess.run([str(ROOT / 'observability/scripts/aws-compose.sh'), 'web', 'exec', '-T',
            'db', 'sh', '-ceu', 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump --single-transaction --quick --no-tablespaces --routines --triggers --events -u root "$MYSQL_DATABASE"'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output.write(gzip.compress(dumped.stdout))
    with gzip.open(backup, 'rb') as stream:
        stream.read()
    journal = dict(status='PREPARED', backup=str(backup), sha256=hashlib.sha256(backup.read_bytes()).hexdigest(),
                   scope='AWS-only SIEM operational fields; shared business ngay_tao mapping untouched')
    with marker.open('x') as stream:
        json.dump(journal, stream, indent=2)
    seed.sql('''START TRANSACTION;
UPDATE siem_security_events SET exported_at=DATE_SUB(exported_at,INTERVAL 7 HOUR), aggregated_at=DATE_SUB(aggregated_at,INTERVAL 7 HOUR);
UPDATE siem_account_behavior_windows SET scored_at=DATE_SUB(scored_at,INTERVAL 7 HOUR), updated_at=DATE_SUB(updated_at,INTERVAL 7 HOUR);
UPDATE siem_ueba_model_jobs SET training_from=DATE_SUB(training_from,INTERVAL 7 HOUR), training_to=DATE_SUB(training_to,INTERVAL 7 HOUR), activated_at=DATE_SUB(activated_at,INTERVAL 7 HOUR), updated_at=DATE_SUB(updated_at,INTERVAL 7 HOUR);
UPDATE siem_test_windows SET starts_at=DATE_SUB(starts_at,INTERVAL 7 HOUR), ends_at=DATE_SUB(ends_at,INTERVAL 7 HOUR), updated_at=DATE_SUB(updated_at,INTERVAL 7 HOUR);
UPDATE siem_ingestion_checkpoint SET last_event_timestamp=DATE_SUB(last_event_timestamp,INTERVAL 7 HOUR), last_success_at=DATE_SUB(last_success_at,INTERVAL 7 HOUR), last_error_at=DATE_SUB(last_error_at,INTERVAL 7 HOUR), updated_at=DATE_SUB(updated_at,INTERVAL 7 HOUR);
UPDATE siem_alert_refs SET event_timestamp=DATE_SUB(event_timestamp,INTERVAL 7 HOUR);
UPDATE siem_incidents SET updated_at=DATE_SUB(updated_at,INTERVAL 7 HOUR);
UPDATE siem_incidents SET bucket_start=DATE_SUB(bucket_start,INTERVAL 7 HOUR), first_seen=DATE_SUB(first_seen,INTERVAL 7 HOUR), last_seen=DATE_SUB(last_seen,INTERVAL 7 HOUR) WHERE origin<>'UEBA';
UPDATE siem_incidents SET grouping_key=CONCAT('utc-upgrade:',id) WHERE origin='UEBA';
UPDATE siem_incidents SET grouping_key=CONCAT('ueba:',target_user_id,':',DATE_FORMAT(bucket_start,'%Y-%m-%dT%H:00')) WHERE origin='UEBA';
COMMIT;''')
    journal['status'] = 'APPLIED'
    # The existing PREPARED journal intentionally survives any failure before this atomic update.
    temporary = marker.with_suffix('.next')
    with temporary.open('x') as stream:
        json.dump(journal, stream, indent=2)
    os.replace(temporary, marker)
    print('AWS SIEM date correction applied once; private full backup and journal retained. Start the tested updated app image.')

if __name__ == '__main__':
    main()
