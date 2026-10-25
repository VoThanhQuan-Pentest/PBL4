#!/usr/bin/env python3
"""Restore a private AWS SQL snapshot into a disposable network-isolated local MySQL container."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from mysql_snapshot_inventory import FORMAT, MysqlReadOnly, capture, compare, compare_schema, validate_inventory

IMAGE = 'mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af'

def run(args, data=None, check=True):
    return subprocess.run(args, input=data, capture_output=True, check=check)

def prepare_private_output(path):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Private restore output path cannot traverse symlinks')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ValueError('Private restore output must be a new regular-file path')
    return path

def validate_reference(expected, scope, backup_sha):
    if expected is None:
        if scope == 'SAME_IMMUTABLE_BACKUP': raise ValueError('A bound snapshot inventory is required')
        return
    if scope == 'SAME_IMMUTABLE_BACKUP':
        if expected.get('inventory_origin') != 'DISPOSABLE_LOCAL_FULL_IMPORT' or expected.get('backup_sha256') != backup_sha:
            raise ValueError('Reference inventory belongs to another backup or source')
    elif expected.get('inventory_origin') == 'DISPOSABLE_LOCAL_FULL_IMPORT':
        raise ValueError('A restored inventory cannot be mislabeled as a live-source checkpoint')

def validate_current_format(value):
    """Read legacy evidence without upgrading it into a new equality claim."""
    if value is not None and value['format'] != FORMAT:
        raise ValueError('Legacy inventory requires a new live capture; do not rewrite original evidence')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected-inventory', type=Path)
    p.add_argument('--expected-backup-sha256')
    p.add_argument('--write-restored-inventory', type=Path)
    p.add_argument('--inventory-reference-scope', choices=('SOURCE_CHECKPOINT', 'SAME_IMMUTABLE_BACKUP'), default='SOURCE_CHECKPOINT')
    p.add_argument('--source-schema-inventory', type=Path)
    p.add_argument('--private-schema-diagnostics-dir', type=Path)
    args = p.parse_args()
    os.umask(0o077)
    args.output = prepare_private_output(args.output)
    if args.write_restored_inventory is not None:
        args.write_restored_inventory = prepare_private_output(args.write_restored_inventory)
        if args.write_restored_inventory == args.output:
            p.error('Restore evidence and inventory must use distinct files')
    backup_bytes = args.backup.read_bytes()
    backup_sha = hashlib.sha256(backup_bytes).hexdigest()
    if args.expected_backup_sha256 and backup_sha != args.expected_backup_sha256:
        p.error('Private backup checksum does not match the expected source')
    expected = None
    if args.expected_inventory:
        if args.expected_inventory.is_symlink() or args.expected_inventory.stat().st_size > 1024 * 1024:
            p.error('Bounded regular inventory required')
        expected = validate_inventory(json.loads(args.expected_inventory.read_bytes()))
    validate_reference(expected, args.inventory_reference_scope, backup_sha)
    validate_current_format(expected)
    source_schema = None
    if args.source_schema_inventory:
        if args.source_schema_inventory.is_symlink() or args.source_schema_inventory.stat().st_size > 1024 * 1024:
            p.error('Bounded regular source schema inventory required')
        source_schema = validate_inventory(json.loads(args.source_schema_inventory.read_bytes()))
        validate_current_format(source_schema)
    payload = gzip.decompress(backup_bytes)
    if b'CREATE TABLE' not in payload or b'flyway_schema_history' not in payload:
        p.error('Expected a complete SQL schema/data snapshot')
    name = 'flare-aws-restore-' + secrets.token_hex(6)
    container = None
    with tempfile.TemporaryDirectory(prefix='flare-aws-restore-') as directory:
        env = Path(directory) / 'mysql.env'
        env.write_text('MYSQL_ROOT_PASSWORD=' + secrets.token_hex(24) + '\nMYSQL_DATABASE=flare_restore\n')
        env.chmod(0o600)
        try:
            container = run(['docker','run','-d','--network','none','--name',name,'--env-file',str(env),IMAGE]).stdout.decode().strip()
            for _ in range(60):
                ready = run(['docker','exec',container,'sh','-ceu',
                    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql --default-character-set=utf8mb4 -Ns -uroot "$MYSQL_DATABASE" -e "SELECT 1"'],check=False)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Isolated restore MySQL not ready')
            command = ['docker','exec','-i',container,'sh','-ceu',
                'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --default-character-set=utf8mb4 -Ns -uroot "$MYSQL_DATABASE"']
            run(command,payload)
            counts = {}
            for table in ('tbl_nguoi_dung','tbl_san_pham','siem_security_events',
                          'siem_account_behavior_windows','siem_ueba_model_jobs','siem_attack_signatures'):
                counts[table] = int(run(command, ('SELECT COUNT(*) FROM ' + table + ';').encode()).stdout)
            active = int(run(command,b"SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE status='ACTIVE' AND data_provenance='DEMO_ONLY';").stdout)
            schema = run(command,b"SELECT version FROM flyway_schema_history WHERE success=1 ORDER BY installed_rank DESC LIMIT 1;").stdout.decode().strip()
            passed = active == 1 and schema == '27' and counts['tbl_nguoi_dung'] >= 8 and counts['tbl_san_pham'] >= 3 and counts['siem_security_events'] >= 2668
            exact = None
            schema_matches = None
            if expected is not None or args.write_restored_inventory is not None or source_schema is not None:
                with MysqlReadOnly(container) as mysql: exact = capture(mysql.query, schema_export_dir=args.private_schema_diagnostics_dir)
                validate_inventory(exact)
                if expected is not None: passed = compare(expected, exact)
                else: passed = None  # Collection, never an inferred source-equality PASS.
                if source_schema is not None:
                    schema_matches = compare_schema(source_schema, exact)
                    if not schema_matches: passed = False
                if args.write_restored_inventory is not None:
                    manifest = {**exact, 'inventory_origin': 'DISPOSABLE_LOCAL_FULL_IMPORT', 'backup_sha256': backup_sha}
                    with args.write_restored_inventory.open('x') as output: json.dump(manifest, output, indent=2)
            scope = 'LEGACY_SIX_TABLE_MINIMUMS_ONLY'
            if exact is not None:
                scope = ('RESTORED_INVENTORY_CAPTURE_ONLY' if expected is None else
                         'ALL_TABLES_REPEATABLE_IMMUTABLE_BACKUP' if args.inventory_reference_scope == 'SAME_IMMUTABLE_BACKUP' else
                         'ALL_BASE_TABLES_SOURCE_CHECKPOINT_SCHEMA_AND_ROW_SHA256')
            result = dict(passed=passed, method='Full SQL import in an isolated local MySQL with no network or published ports',
                source_environment='AWS', target_environment='DISPOSABLE_LOCAL', observed_at=datetime.now(timezone.utc).isoformat(),
                source_sha256=backup_sha, schema_version=schema,
                active_demo_models=active, counts=counts,
                verification_scope=scope,
                exact_table_count=len(exact['tables']) if exact is not None else None,
                expected_inventory_sha256=expected['content_sha256'] if expected is not None else None,
                restored_inventory_sha256=exact['content_sha256'] if exact is not None else None,
                source_schema_fingerprints_match=schema_matches)
            result['inventory_format'] = exact['format'] if exact is not None else None
            result['schema_fingerprint_format'] = exact['schema_fingerprint_format'] if exact is not None else None
            result['raw_ddl_diagnostics_affect_semantic_equality'] = False if exact is not None else None
            with args.output.open('x') as output:
                json.dump(result,output,indent=2)
            print(json.dumps(result))
            if passed is False:
                raise SystemExit(1)
        finally:
            if container:
                run(['docker','rm','-f',container],check=False)
                print('Disposable restored container removed; original private SQL snapshot retained.')

if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as failure:
        codes = re.findall(rb'ERROR\s+\d{3,5}', (failure.stderr or b'')[:16384])
        safe = ', '.join(value.decode() for value in codes) or 'non-SQL error'
        raise SystemExit(f'Restore command failed ({safe}); private SQL/credential output intentionally omitted')
    except (ValueError, RuntimeError, KeyError, OSError) as failure:
        raise SystemExit('Private restore verification failed: ' + type(failure).__name__ + '; SQL/credential output omitted') from None
