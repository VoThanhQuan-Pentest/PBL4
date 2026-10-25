#!/usr/bin/env python3
"""Preserve source, model identity and local DB before implementation changes."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from postlogin_impl_control import REPO, OUTPUT, FIT_LEDGER, held
from postlogin_preparation_audit import checked
from ueba_research_artifacts import commit, digest, private_directory


def check():
    if held():raise RuntimeError('OPERATOR_HOLD')
    if shutil.disk_usage(OUTPUT).free < 10000000000:raise RuntimeError('PRECHECK_NEEDS10GB_FREE')


def main():
    private_directory(OUTPUT);check()
    snapshot = OUTPUT / 'preimplementation-source-v1'
    marker = OUTPUT / 'preimplementation-source-v1.commit.private.json'
    if not marker.exists():
        snapshot.mkdir(mode=0o700, exist_ok=True)
        directories = ['backend/src', 'ueba-worker/app', 'frontend/src', 'desktop-client/src']
        files = ['backend/pom.xml', 'ueba-worker/Dockerfile', 'frontend/package.json', 'frontend/package-lock.json',
                 'desktop-client/pom.xml', 'docker-compose.yml', 'docker-compose.otp-local.yml',
                 'observability/docker-compose.local.yml', 'observability/scripts/local-otp-site.py',
                 'observability/scripts/local-soc-demo.py', 'observability/scripts/postlogin_research_step.py',
                 'observability/scripts/postlogin_impl_control.py']
        for name in directories:
            check();target = snapshot / name
            if target.exists():shutil.rmtree(target)  # Only this uncommitted, owned source copy.
            shutil.copytree(REPO / name, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in files:
            check();target = snapshot / name;target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, target)
        manifest = {str(p.relative_to(snapshot)): digest(p) for p in snapshot.rglob('*') if p.is_file()}
        commit(OUTPUT, {'status': 'SOURCE_PRESERVED_BEFORE_IMPLEMENTATION', 'files_sha256': manifest,
                        'secret_or_env_files_copied': False}, phase='preimplementation-source-v1')
    retained = checked(OUTPUT, 'preimplementation-source-v1')
    for name, value in retained['files_sha256'].items():
        if digest(snapshot / name) != value:raise RuntimeError('PRESERVED_SOURCE_CHANGED')

    old = REPO / 'observability/runtime/postlogin-risk-ratio-20261021-r1'
    evidence = checked(old / 'forward-validation-v1', 'model-binding-v1')
    bundle = old / 'factorial-v1/projection-fit-fold3-candidate.bundle.zip'
    if digest(bundle) != evidence['candidate']['bundle_sha256']:raise RuntimeError('OLD_MODEL_IDENTITY_CHANGED')
    commit(OUTPUT, {'status': 'FIXED_MODEL_AND_LEDGER_BOUND', 'bundle': str(bundle),
        'bundle_sha256': digest(bundle), 'fit_ledger_sha256': digest(FIT_LEDGER),
        'new_fit_cap': 0, 'original_recipe_version': 8,
        'thresholds': {'READY': 99.99, 'COLD': 99.9995}, 'new_model_version': 'postlogin-legacy-f3-project-v1',
        'data_provenance': 'DEMO_ONLY_RULE_DISTILLATION'}, phase='fixed-model-binding-v1')

    spec = importlib.util.spec_from_file_location('local_soc_protection', REPO / 'observability/scripts/local-soc-demo.py')
    soc = importlib.util.module_from_spec(spec);spec.loader.exec_module(soc)
    soc.guard()
    protection = soc.reserved_demo_snapshot()
    practice_file = soc.STATE / 'latest-practice.private.json'
    if practice_file.exists():
        practice = json.loads(practice_file.read_text())
        protection['practice_cases'] = {c['incident_id']: soc.sql(
            "SELECT status,queue_tier,COALESCE(assignee_user_id,''),version FROM siem_incidents WHERE id="
            + soc.literal(c['incident_id']) + ';') for c in practice['cases']}
    commit(OUTPUT, {'status': 'DEMO_AND_PRACTICE_STATE_PRESERVED', 'snapshot': protection}, phase='protected-demo-before-v1')

    backup = OUTPUT / 'local-site-before-implementation.sql.gz'
    if not (OUTPUT / 'database-backup-v1.commit.private.json').exists():
        check();pending = OUTPUT / '.database-backup.pending'
        if pending.exists():pending.unlink()  # Interrupted private output, never the source DB.
        process = subprocess.Popen(['docker', 'exec', 'flare-otp-local-db-1', 'sh', '-ceu',
            'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --single-transaction --no-tablespaces --skip-lock-tables '
            '--default-character-set=utf8mb4 -u "$MYSQL_USER" "$MYSQL_DATABASE"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as raw:
                with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
                    while True:
                        check();chunk = process.stdout.read(1024 * 1024)
                        if not chunk:break
                        compressed.write(chunk)
                        if raw.tell() > 1024**3:raise RuntimeError('DATABASE_BACKUP_BYTE_CAP')
                raw.flush();os.fsync(raw.fileno())
            process.wait(timeout=30)
            if process.returncode:raise RuntimeError('DATABASE_BACKUP_FAILED')
            os.replace(pending, backup)
            directory = os.open(OUTPUT, os.O_DIRECTORY);os.fsync(directory);os.close(directory)
        finally:
            if process.poll() is None:process.terminate();process.wait(timeout=10)
        count = 0
        with gzip.open(backup, 'rb') as source:
            while chunk := source.read(1024 * 1024):count += len(chunk)
        if count < 1000:raise RuntimeError('DATABASE_BACKUP_EMPTY')
        commit(OUTPUT, {'status': 'PRIVATE_DATABASE_BACKUP_READBACK_PASS', 'path': backup.name,
            'sha256': digest(backup), 'compressed_bytes': backup.stat().st_size,
            'uncompressed_bytes': count, 'source_database_modified': False,
            'backup_contents_exposed': False}, phase='database-backup-v1')
    proof = checked(OUTPUT, 'database-backup-v1')
    if digest(backup) != proof['sha256']:raise RuntimeError('DATABASE_BACKUP_CHANGED')
    commit(OUTPUT, {'status': 'IMPLEMENTATION_P0_PREFLIGHT_PASS', 'new_fits': 0,
        'source_files_preserved': len(retained['files_sha256']), 'backup_sha256': proof['sha256'],
        'fixed_model_sha256': digest(bundle), 'disk_free_bytes': shutil.disk_usage(OUTPUT).free,
        'quota_policy': 'NOT_USED', 'aws_changed': False}, phase='implementation-p0-result-v1')
    print('IMPLEMENTATION_P0_PREFLIGHT_PASS: source/model/DB/demo evidence preserved;0fit', flush=True)


if __name__ == '__main__':main()
