#!/usr/bin/env python3
"""Opt-in local rehearsal of an immutable schema-27 or schema-31 SQL checkpoint with real Flyway.

No AWS calls, active database addresses, application startup, deployment, model activation,
public ports, checksum repair, or migration bypass are supported. Only disposable containers
created by this process are removed. Private SQL and command output are never printed.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
MYSQL_IMAGE = 'mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af'
JAVA_IMAGE = 'sha256:973e4842cf2aac59888e254b49dd2b724718f2e5e1f60ba74315e04c65a88151'
HELPER = ROOT / 'backend/src/test/java/com/flarefitness/backend/integration/AwsBackupUpgradeRehearsal.java'
MIGRATIONS = ROOT / 'backend/src/main/resources/db/migration'
E2E_SEEDS = ROOT / 'backend/src/main/resources/db/seed/e2e'
MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
MAX_SQL_BYTES = 128 * 1024 * 1024
JAVA_FAILURE_MARKERS = (
    (b'Could not find or load main class', 'JAVA_MAIN_CLASS_UNAVAILABLE'),
    (b'Could not create the Java Virtual Machine', 'JAVA_VM_START_FAILED'),
    (b'UnsupportedClassVersionError', 'JAVA_VERSION_INCOMPATIBLE'),
    (b'NoClassDefFoundError', 'JAVA_CLASS_LINKAGE_FAILURE'),
    (b'ClassNotFoundException', 'JAVA_CLASS_NOT_FOUND'),
    (b'OutOfMemoryError', 'JAVA_HEAP_EXHAUSTED'),
    (b'AccessDeniedException', 'JAVA_ACCESS_DENIED'),
    (b'SQLException', 'JAVA_DATABASE_ERROR'),
    (b'CommunicationsException', 'JAVA_DATABASE_CONNECTION_FAILED'),
)


def run(command, data=None, check=True, timeout=300):
    """Capture all subprocess output, including private MySQL/Flyway diagnostics."""
    return subprocess.run(command, input=data, capture_output=True, check=check, timeout=timeout)


def classify_java_failure(stderr):
    """Return only a constant failure class, never subprocess diagnostics."""
    if not isinstance(stderr, bytes):
        return 'JAVA_PROCESS_FAILED_UNCLASSIFIED'
    for marker, code in JAVA_FAILURE_MARKERS:
        if marker in stderr[:65536]:
            return code
    return 'JAVA_PROCESS_FAILED_UNCLASSIFIED'


def regular_file(path, maximum):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('Bounded regular file required')
    return path


def read_backup(path, expected_sha):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
        raise ValueError('Explicit lowercase SHA-256 required')
    compressed = regular_file(path, MAX_COMPRESSED_BYTES).read_bytes()
    checksum = hashlib.sha256(compressed).hexdigest()
    if checksum != expected_sha:
        raise ValueError('Backup checksum differs; no database created')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode='rb') as stream:
        sql = stream.read(MAX_SQL_BYTES + 1)
    if len(sql) > MAX_SQL_BYTES or b'CREATE TABLE' not in sql or b'flyway_schema_history' not in sql:
        raise ValueError('Bounded complete SQL backup required')
    return sql, checksum


def frozen_jars(directory):
    """Use the retained dependency manifest, without installing or updating dependencies."""
    manifest_path = regular_file(directory / 'snapshot.json', 1024 * 1024)
    manifest = json.loads(manifest_path.read_bytes())
    expected = manifest.get('jars')
    if not isinstance(expected, dict) or not expected or len(expected) > 256:
        raise ValueError('Frozen dependency manifest required')
    jars = []
    for name, checksum in sorted(expected.items()):
        if not re.fullmatch(r'[a-zA-Z0-9_.+-]+\.jar', name) or not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise ValueError('Invalid frozen dependency identity')
        jar = regular_file(directory / 'jars' / name, 128 * 1024 * 1024)
        if hashlib.sha256(jar.read_bytes()).hexdigest() != checksum:
            raise ValueError('Frozen dependency checksum differs')
        jars.append(jar)
    names = [jar.name for jar in jars]
    if not any(name.endswith('flyway-core-11.20.3.jar') for name in names):
        raise ValueError('Current Flyway 11.20.3 required')
    if not any(name.endswith('flyway-mysql-11.20.3.jar') for name in names):
        raise ValueError('Current MySQL Flyway extension required')
    return jars, hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def database_command(container, interactive=False):
    return ['docker', 'exec', *(['-i'] if interactive else []), container, 'sh', '-ceu',
            'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --local-infile=0 '
            '--default-character-set=utf8mb4 -Ns -uroot "$MYSQL_DATABASE"']


def mysql_container_command(name, env_file):
    return ['docker', 'run', '-d', '--pull=never', '--network', 'none', '--name', name,
            '--label', 'flare.scope=disposable-local-backup-upgrade', '--env-file', str(env_file),
            '--memory', '1024m', '--memory-swap', '1024m', '--cpus', '0.75',
            '--tmpfs', '/var/lib/mysql:rw,noexec,nosuid,size=1g',
            MYSQL_IMAGE, '--local-infile=0', '--secure-file-priv=NULL']


def java_container_command(name, database, env_file, work, frozen, *, include_e2e_seed=False):
    command = ['docker', 'run', '--pull=never', '--name', name,
            '--label', 'flare.scope=disposable-local-backup-upgrade',
            '--network', 'container:' + database, '--user', f'{os.getuid()}:{os.getgid()}',
            '--memory', '768m', '--memory-swap', '768m', '--cpus', '0.75', '--pids-limit', '128',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--env-file', str(env_file),
            '--mount', f'type=bind,src={work / "classes"},dst=/rehearsal/classes,readonly',
            '--mount', f'type=bind,src={MIGRATIONS},dst=/rehearsal/migrations,readonly',
            '--mount', f'type=bind,src={frozen / "jars"},dst=/rehearsal/jars,readonly',
            '--mount', f'type=bind,src={work / "evidence"},dst=/evidence',
            '--entrypoint', 'java', JAVA_IMAGE,
            '-Duser.timezone=UTC', '-cp', '/rehearsal/classes:/rehearsal/jars/*',
            'com.flarefitness.backend.integration.AwsBackupUpgradeRehearsal']
    if include_e2e_seed:
        entrypoint = command.index('--entrypoint')
        command[entrypoint:entrypoint] = [
            '--mount', f'type=bind,src={E2E_SEEDS},dst=/rehearsal/e2e-seed,readonly']
    return command


def validate_disposable_network(container):
    state = json.loads(run(['docker', 'inspect', container]).stdout)[0]
    if (state['HostConfig']['NetworkMode'] != 'none'
            or state['HostConfig'].get('PortBindings')
            or state['NetworkSettings'].get('Networks')
            and set(state['NetworkSettings']['Networks']) != {'none'}):
        raise ValueError('Disposable database must have no external network or published ports')
    if state['Config']['Labels'].get('flare.scope') != 'disposable-local-backup-upgrade':
        raise ValueError('Unowned database target rejected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-disposable-local-upgrade', action='store_true', required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--expected-backup-sha256', required=True)
    parser.add_argument('--frozen-dependencies', type=Path, required=True)
    parser.add_argument('--source-schema', choices=('27', '31'), default='27')
    parser.add_argument('--source-environment', choices=('AWS_BACKUP', 'LOCAL'))
    parser.add_argument('--output', type=Path, required=True,
                        help='New private JSON technical evidence file under observability/runtime')
    args = parser.parse_args()
    if args.source_schema == '31' and args.source_environment is None:
        parser.error('Schema-31 rehearsals require explicit --source-environment')
    source_environment = args.source_environment or 'AWS_BACKUP'
    include_e2e_seed = source_environment == 'LOCAL'
    os.umask(0o077)
    runtime = (ROOT / 'observability/runtime').resolve()
    output = args.output.absolute()
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to(runtime):
        parser.error('Evidence must be a new private file under observability/runtime')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.parent.stat().st_mode & 0o077:
        parser.error('Evidence parent must have private mode 0700')
    evidence = {'passed': False,
                'scope': f'LOCAL_ONLY_IMMUTABLE_BACKUP_SCHEMA_{args.source_schema}_TO_36',
                'observed_at': datetime.now(timezone.utc).isoformat(), 'source_environment': source_environment,
                'target_environment': 'DISPOSABLE_LOCAL', 'mysql_image': MYSQL_IMAGE,
                'java_image': JAVA_IMAGE, 'external_network': False, 'published_ports': False,
                'active_database_touched': False, 'aws_mutation': False, 'deployment': False,
                'source_backup_modified': False, 'checksum_bypass': False}
    evidence['local_e2e_repeatable_location_included'] = include_e2e_seed
    if include_e2e_seed:
        repeatables = sorted(E2E_SEEDS.glob('R__*.sql'))
        if len(repeatables) != 1:
            parser.error('Schema-31 local rehearsal requires exactly one E2E repeatable migration.')
        evidence['local_e2e_repeatable_sha256'] = hashlib.sha256(repeatables[0].read_bytes()).hexdigest()
    evidence['database_storage'] = 'DISPOSABLE_TMPFS_NO_PERSISTENT_DATA_VOLUME'
    stage = 'INPUT_IDENTITY'
    database = java_name = None
    cleanup_ok = True
    with tempfile.TemporaryDirectory(prefix='flare-local-backup-upgrade-') as temp:
        work = Path(temp)
        try:
            payload, backup_sha = read_backup(args.backup, args.expected_backup_sha256)
            jars, dependency_sha = frozen_jars(args.frozen_dependencies.resolve())
            evidence['source_backup_sha256'] = backup_sha
            evidence['frozen_dependency_manifest_sha256'] = dependency_sha
            evidence['helper_source_sha256'] = hashlib.sha256(HELPER.read_bytes()).hexdigest()
            evidence['migration_source_sha256'] = {
                migration.name: hashlib.sha256(migration.read_bytes()).hexdigest()
                for migration in sorted(MIGRATIONS.glob('V*.sql'))}
            stage = 'COMPILE_CURRENT_HELPER'
            (work / 'classes').mkdir(mode=0o700)
            (work / 'evidence').mkdir(mode=0o700)
            run(['javac', '--release', '21', '-cp', ':'.join(str(jar) for jar in jars),
                 '-d', str(work / 'classes'), str(HELPER)])
            env_file = work / 'mysql.env'
            env_file.write_text('MYSQL_ROOT_PASSWORD=' + secrets.token_hex(32)
                                + '\nMYSQL_DATABASE=flare_rehearsal\nREHEARSAL_MODE=DISPOSABLE_LOCAL_ONLY\n'
                                + 'REHEARSAL_SOURCE_SCHEMA=' + args.source_schema + '\n'
                                + 'REHEARSAL_INCLUDE_E2E_SEED=' + str(include_e2e_seed).lower() + '\n')
            env_file.chmod(0o600)
            stage = 'CREATE_DISPOSABLE_MYSQL'
            db_name = 'flare-local-upgrade-db-' + secrets.token_hex(6)
            # Record the exact random name before create, so timed-out creation is still cleaned up.
            database = db_name
            run(mysql_container_command(db_name, env_file))
            validate_disposable_network(database)
            stage = 'WAIT_DISPOSABLE_MYSQL'
            for _ in range(60):
                ready = run(database_command(database, True), b'SELECT 1;', check=False, timeout=10)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Disposable MySQL not ready')
            stage = 'IMPORT_IMMUTABLE_BACKUP'
            run(database_command(database, True), payload)
            stage = 'CURRENT_FLYWAY_AND_PRESERVATION'
            java_name = 'flare-local-upgrade-java-' + secrets.token_hex(6)
            process = run(java_container_command(java_name, database, env_file, work,
                                                args.frozen_dependencies.resolve(),
                                                include_e2e_seed=include_e2e_seed), check=False)
            helper_output = work / 'evidence/helper.json'
            if helper_output.is_file():
                helper = json.loads(regular_file(helper_output, 1024 * 1024).read_bytes())
                evidence['verification'] = helper
                evidence['passed'] = process.returncode == 0 and helper.get('passed') is True
            if not evidence['passed']:
                if not helper_output.is_file():
                    evidence['java_process_exit_code'] = process.returncode
                    evidence['java_failure_class'] = classify_java_failure(process.stderr)
                raise RuntimeError('Actual Flyway or preservation verification failed')
            stage = 'RECHECK_SOURCE_BACKUP'
            regular_file(args.backup, MAX_COMPRESSED_BYTES)
            if hashlib.sha256(args.backup.read_bytes()).hexdigest() != backup_sha:
                evidence['passed'] = False
                raise ValueError('Source changed during rehearsal')
            stage = 'COMPLETE'
        except (ValueError, RuntimeError, KeyError, OSError, subprocess.SubprocessError) as failure:
            evidence['passed'] = False
            evidence['failure_class'] = type(failure).__name__
        finally:
            for owned_container in (java_name, database):
                if owned_container:
                    try:
                        removed = run(['docker', 'rm', '-fv', owned_container], check=False, timeout=30)
                        cleanup_ok = cleanup_ok and removed.returncode == 0
                    except (OSError, subprocess.SubprocessError):
                        cleanup_ok = False
            evidence['stage'] = stage
            evidence['disposable_containers_removed'] = cleanup_ok
            if not cleanup_ok:
                evidence['passed'] = False
            with output.open('x') as stream:
                json.dump(evidence, stream, indent=2)
    print(json.dumps({'passed': evidence['passed'], 'stage': stage,
                      'disposable_containers_removed': cleanup_ok,
                      'private_evidence': str(output.relative_to(ROOT))}))
    return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
