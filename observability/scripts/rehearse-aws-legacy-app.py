#!/usr/bin/env python3
"""Opt-in LOCAL startup of the exact trusted AWS app image on an upgraded SQL copy.

No AWS calls, build/pull/tag, source changes, published ports, migration policy
overrides, or activation are supported. Private values and diagnostics are never
printed. SIEM/background integrations are disabled: this checks isolated app
startup/backward-schema compatibility, NOT full production acceptance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
PRIVATE_ROOT = ROOT / 'observability/runtime/private-backups'
SCOPE = 'disposable-local-legacy-app'
REDIS_IMAGE = 'redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99'
CONFIG_MEMBERS = frozenset(('.env', '.secrets/observability/web/ca.crt',
    '.secrets/observability/web/filebeat-web.crt', '.secrets/observability/web/filebeat-web.key',
    '.secrets/observability/web/siem-reader.password', '.secrets/ueba/worker.token',
    '.secrets/prevention/gateway.token', '.secrets/prevention/ipinfo.token',
    '.secrets/prevention/abuseipdb.key'))
APP_KEYS = frozenset(('SPRING_PROFILES_ACTIVE', 'APP_JWT_SECRET', 'APP_MAIL_USERNAME',
    'APP_MAIL_FROM', 'APP_MAIL_PASSWORD', 'APP_AUTH_COOKIE_SECURE', 'APP_CORS_ALLOWED_ORIGINS',
    'MANAGEMENT_HEALTH_MAIL_ENABLED'))


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


upgrade = module('legacy_app_upgrade', 'rehearse-aws-backup-upgrade.py')
image_verifier = module('legacy_app_image_verifier', 'verify-docker-checkpoint-image.py')
inventory = module('legacy_app_inventory', 'mysql_snapshot_inventory.py')


def run(command, data=None, check=True, timeout=300, stdin=None):
    return subprocess.run(command, input=data, stdin=stdin, capture_output=True,
                          check=check, timeout=timeout)


def private_hash(path, expected, maximum):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('Explicit artifact SHA-256 required')
    with image_verifier._private_archive(path, PRIVATE_ROOT) as (stream, before):
        if before.st_size > maximum:
            raise ValueError('Private input exceeds bound')
        digest = image_verifier._hash_archive(stream, before)
        if digest != expected:
            raise ValueError('Private artifact checksum differs')
        if image_verifier._metadata_identity(before) != image_verifier._metadata_identity(os.fstat(stream.fileno())):
            raise ValueError('Private artifact changed')
    return digest


def dotenv(body):
    """Bounded Compose-compatible simple values; never execute/interpolate a file."""
    if len(body) > 65536:
        raise ValueError('Private configuration exceeds bound')
    values = {}
    for line in body.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, raw = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key) or key in values:
            raise ValueError('Simple unique private environment keys required')
        lexer = shlex.shlex(raw, posix=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
        if len(tokens) > 1 or '$' in raw or '\x00' in raw:
            raise ValueError('Configuration interpolation or multiline values unsupported')
        value = tokens[0] if tokens else ''
        if '\n' in value or '\r' in value:
            raise ValueError('Single-line environment values required')
        values[key] = value
    return values


def read_configuration(path, expected):
    private_hash(path, expected, 1024 * 1024)
    with image_verifier._private_archive(path, PRIVATE_ROOT) as (stream, before):
        if image_verifier._hash_archive(stream, before) != expected:
            raise ValueError('Private configuration changed before read')
        members = image_verifier._scan_tar(stream, before.st_size)
        if set(members) != CONFIG_MEMBERS or any(member.directory for member in members.values()):
            raise ValueError('Exact bounded private configuration inventory required')
        values = dotenv(image_verifier._read_member(stream, members, '.env', 65536))
        if image_verifier._metadata_identity(before) != image_verifier._metadata_identity(os.fstat(stream.fileno())):
            raise ValueError('Private configuration changed')
    if values.get('FLARE_ENVIRONMENT') != 'aws-lab':
        raise ValueError('AWS lab source configuration required')
    for key in APP_KEYS | {'SPRING_DATASOURCE_USERNAME', 'SPRING_DATASOURCE_PASSWORD', 'REDIS_PASSWORD'}:
        if key not in values:
            raise ValueError('Required original app configuration missing')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,31}', values['SPRING_DATASOURCE_USERNAME']):
        raise ValueError('Safe non-root disposable app username required')
    if values['SPRING_DATASOURCE_USERNAME'].lower() == 'root':
        raise ValueError('Original app must use a non-root database account')
    return values


def read_image_metadata(path, expected_id, expected_sha):
    result = image_verifier.verify_image(path, expected_id, expected_sha256=expected_sha)
    if not result['image_archive_verified']:
        raise ValueError('Trusted image graph verification failed')
    with image_verifier._private_archive(path, PRIVATE_ROOT) as (stream, before):
        if image_verifier._hash_archive(stream, before) != expected_sha:
            raise ValueError('Image archive changed before metadata read')
        members = image_verifier._scan_tar(stream, before.st_size)
        manifest = image_verifier._json(image_verifier._read_member(stream, members, 'manifest.json'))[0]
        # Never allow docker load to overwrite an existing tag, even if it currently matches.
        if manifest['RepoTags'] not in (None, []):
            raise ValueError('Untagged immutable image archive required')
        config = image_verifier._json(image_verifier._read_member(stream, members, manifest['Config']))
        config_id = 'sha256:' + hashlib.sha256(image_verifier._read_member(stream, members, manifest['Config'])).hexdigest()
        runtime = config['config']
        if (runtime.get('Entrypoint') != ['java', '-jar', '/app/app.jar']
                or runtime.get('Cmd') not in (None, []) or runtime.get('User') != 'appuser'
                or runtime.get('Volumes')):
            raise ValueError('Expected original immutable app runtime required')
        if any('FLYWAY' in entry.upper() for entry in runtime.get('Env', [])):
            raise ValueError('Image migration policy requires explicit review')
        if image_verifier._metadata_identity(before) != image_verifier._metadata_identity(os.fstat(stream.fileno())):
            raise ValueError('Image changed before load')
    return result, config_id, config


def tagged_images():
    values = [json.loads(line) for line in run(
        ['docker', 'image', 'ls', '--no-trunc', '--format', 'json']).stdout.decode().splitlines()]
    return sorted((item['Repository'], item['Tag'], item['ID']) for item in values
                  if item['Repository'] != '<none>' and item['Tag'] != '<none>')


def inspect_image(identity):
    process = run(['docker', 'image', 'inspect', identity], check=False)
    return json.loads(process.stdout)[0] if process.returncode == 0 else None


def matching_runtime_configuration(loaded, saved):
    # Moby inspect renders absent optional config fields as null. Neither form
    # adds a command, volume, build trigger, environment or runtime behavior.
    null_defaults = {'Cmd', 'OnBuild', 'Volumes'}
    def normalized(value):
        return {key: item for key, item in value.items()
                if not (key in null_defaults and item is None)}
    return normalized(loaded) == normalized(saved)


def load_image(path, expected_sha, expected_id, config_id, config):
    before_tags = tagged_images()
    state = inspect_image(expected_id) or inspect_image(config_id)
    loaded = False
    if state is None:
        with image_verifier._private_archive(path, PRIVATE_ROOT) as (stream, before):
            if image_verifier._hash_archive(stream, before) != expected_sha:
                raise ValueError('Image changed before docker load')
            run(['docker', 'image', 'load'], stdin=stream)
            if image_verifier._metadata_identity(before) != image_verifier._metadata_identity(os.fstat(stream.fileno())):
                raise ValueError('Image changed during docker load')
        loaded = True
        state = inspect_image(expected_id) or inspect_image(config_id)
    if (state is None or state['RootFS']['Layers'] != config['rootfs']['diff_ids']
            or not matching_runtime_configuration(state['Config'], config['config'])
            or tagged_images() != before_tags):
        raise ValueError('Loaded runtime identity or existing repository tags differ')
    if state['Id'] not in (expected_id, config_id):
        raise ValueError('Loaded image is not the trusted index/config identity')
    return state['Id'], loaded


def write_env(path, values):
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', key)
           or any(character in value for character in '\r\n\x00') for key, value in values.items()):
        raise ValueError('Single-line private environment required')
    with path.open('x') as stream:
        stream.write(''.join(key + '=' + value + '\n' for key, value in sorted(values.items())))
    path.chmod(0o600)


def fixture_environment(source, root_password):
    mysql = {'MYSQL_ROOT_PASSWORD': root_password, 'MYSQL_DATABASE': 'flare_rehearsal',
             'MYSQL_USER': source['SPRING_DATASOURCE_USERNAME'],
             'MYSQL_PASSWORD': source['SPRING_DATASOURCE_PASSWORD'], 'REHEARSAL_MODE': 'DISPOSABLE_LOCAL_ONLY'}
    app = {key: source[key] for key in APP_KEYS}
    app.update(SERVER_PORT='8080', FLARE_ENVIRONMENT='aws-lab',
        SPRING_DATASOURCE_URL='jdbc:mysql://db:3306/flare_rehearsal?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=Asia/Ho_Chi_Minh&characterEncoding=UTF-8',
        SPRING_DATASOURCE_USERNAME=source['SPRING_DATASOURCE_USERNAME'],
        SPRING_DATASOURCE_PASSWORD=source['SPRING_DATASOURCE_PASSWORD'],
        SPRING_DATA_REDIS_HOST='redis', SPRING_DATA_REDIS_PORT='6379',
        SPRING_DATA_REDIS_PASSWORD=source['REDIS_PASSWORD'],
        APP_TRUSTED_PROXY_CIDRS='127.0.0.1/32', SIEM_ENABLED='false',
        SIEM_SECURITY_EVENTS_ENABLED='false', SIEM_UEBA_ENABLED='false', SIEM_PREVENTION_ENABLED='false',
        SIEM_ELASTICSEARCH_URL='https://disabled-siem:9200', SIEM_UEBA_URL='http://ueba-worker:8091')
    return mysql, app


def labels(nonce):
    return ['--label', 'flare.scope=' + SCOPE, '--label', 'flare.rehearsal=' + nonce]


def mysql_command(name, network, nonce, env_file):
    command = upgrade.mysql_container_command(name, env_file)
    command[command.index('--network') + 1] = network
    command[command.index('flare.scope=disposable-local-backup-upgrade')] = 'flare.scope=' + SCOPE
    position = command.index('--env-file')
    command[position:position] = ['--label', 'flare.rehearsal=' + nonce, '--network-alias', 'db']
    return command


def redis_command(name, network, nonce, env_file):
    return ['docker', 'run', '-d', '--pull=never', '--name', name, '--network', network,
            '--network-alias', 'redis', '--network-alias', 'ueba-worker', *labels(nonce), '--env-file', str(env_file),
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--tmpfs', '/data:rw,noexec,nosuid,size=64m', '--entrypoint', 'redis-server',
            '--mount', 'type=bind,src=' + str(env_file.parent / 'redis.conf')
            + ',dst=/run/rehearsal/redis.conf,readonly', REDIS_IMAGE, '/run/rehearsal/redis.conf']


def app_command(name, network, nonce, env_file, image_id):
    return ['docker', 'run', '-d', '--pull=never', '--name', name, '--network', network,
            '--network-alias', 'legacy-app', *labels(nonce), '--env-file', str(env_file),
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', image_id]


def owned_container(name, network, nonce):
    state = json.loads(run(['docker', 'inspect', '--type', 'container', name]).stdout)[0]
    if (state['Config']['Labels'].get('flare.scope') != SCOPE
            or state['Config']['Labels'].get('flare.rehearsal') != nonce
            or state['HostConfig'].get('PortBindings')
            or set(state['NetworkSettings']['Networks']) != {network}):
        raise ValueError('Exact owned internal-network container required')
    return state


def owned_network(name, nonce):
    state = json.loads(run(['docker', 'network', 'inspect', name]).stdout)[0]
    if (state.get('Internal') is not True or state['Driver'] != 'bridge'
            or state['Labels'].get('flare.scope') != SCOPE
            or state['Labels'].get('flare.rehearsal') != nonce):
        raise ValueError('Exact owned egress-disabled network required')
    return state


def capture(database, network, nonce):
    owned_container(database, network, nonce)
    with inventory.MysqlReadOnly(database) as client:
        return inventory.capture(client.query)


def cleanup(containers, network, nonce):
    success = True
    for name in reversed(containers):
        try:
            process = run(['docker', 'inspect', '--type', 'container', name], check=False, timeout=10)
            if process.returncode != 0:
                success = (b'No such container: ' + name.encode() in process.stderr
                           or b'No such object: ' + name.encode() in process.stderr) and success
                continue
            state = json.loads(process.stdout)[0]
            if (state['Config']['Labels'].get('flare.scope') != SCOPE
                    or state['Config']['Labels'].get('flare.rehearsal') != nonce):
                success = False
                continue
            success = run(['docker', 'rm', '-fv', state['Id']], check=False, timeout=30).returncode == 0 and success
        except (ValueError, KeyError, OSError, subprocess.SubprocessError):
            success = False
    if network:
        try:
            process = run(['docker', 'network', 'inspect', network], check=False, timeout=10)
            if process.returncode == 0:
                state = owned_network(network, nonce)
                if state.get('Containers'):
                    success = False
                else:
                    success = run(['docker', 'network', 'rm', state['Id']], check=False, timeout=30).returncode == 0 and success
            else:
                success = b'network ' + network.encode() + b' not found' in process.stderr and success
        except (ValueError, KeyError, OSError, subprocess.SubprocessError):
            success = False
    return success


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-disposable-local-startup', action='store_true', required=True)
    for name in ('backup', 'image', 'configuration', 'models', 'frozen-dependencies', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('backup', 'image', 'configuration', 'models'):
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    parser.add_argument('--expected-image-id', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.absolute()
    if (output.exists() or output.is_symlink()
            or not output.resolve().is_relative_to((ROOT / 'observability/runtime').resolve())):
        parser.error('New private runtime evidence path required')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.parent.stat().st_mode & 0o077:
        parser.error('Private 0700 evidence parent required')
    evidence = {'passed': False, 'scope': 'LOCAL_LEGACY_APP_V34_ON_UPGRADED_SCHEMA_36',
        'observed_at': datetime.now(timezone.utc).isoformat(), 'aws_calls': False,
        'active_database_touched': False, 'deployment': False, 'model_activation': False,
        'public_ports': False, 'network_egress': False, 'full_production_acceptance': False,
        'siem_background_tasks': False, 'flyway_policy': 'IMAGE_PACKAGED_DEFAULT_UNCHANGED',
        'checksum_repair_or_bypass': False, 'source_artifacts_modified': False,
        'existing_image_tags_modified': False, 'mysql_image': upgrade.MYSQL_IMAGE, 'redis_image': REDIS_IMAGE}
    stage, containers, network = 'INPUT_IDENTITY', [], None
    nonce = secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix='flare-local-legacy-app-') as temporary:
        work = Path(temporary)
        try:
            identities = {name: private_hash(getattr(args, name), getattr(args, 'expected_' + name + '_sha256'),
                {'backup': upgrade.MAX_COMPRESSED_BYTES, 'configuration': 1024 * 1024,
                 'models': 64 * 1024 * 1024, 'image': image_verifier.MAX_ARCHIVE_BYTES}[name])
                for name in ('backup', 'configuration', 'models', 'image')}
            payload, _ = upgrade.read_backup(args.backup, identities['backup'])
            if (not payload.startswith(b'-- MySQL dump') or not payload.rstrip().splitlines()[-1].startswith(b'-- Dump completed on ')
                    or b'\nUSE ' in payload or b'CREATE DATABASE' in payload or payload.count(b'CREATE TABLE') != 43):
                raise ValueError('Complete non-redirecting schema-27 source dump required')
            source = read_configuration(args.configuration, identities['configuration'])
            image_check, config_id, image_config = read_image_metadata(args.image, args.expected_image_id, identities['image'])
            jars, dependency_sha = upgrade.frozen_jars(args.frozen_dependencies.resolve())
            evidence.update(source_sha256=identities, trusted_source_image_id=args.expected_image_id,
                source_image_config_id=config_id, image_verification=image_check,
                frozen_dependency_manifest_sha256=dependency_sha,
                helper_source_sha256=hashlib.sha256(upgrade.HELPER.read_bytes()).hexdigest(),
                migration_source_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(upgrade.MIGRATIONS.glob('V*.sql'))},
                preserved_configuration_keys=sorted(APP_KEYS),
                configuration_overrides='DISPOSABLE_DB_REDIS_PROXY_AND_DISABLED_SIEM_ONLY')
            stage = 'COMPILE_CURRENT_FLYWAY_HELPER'
            (work / 'classes').mkdir(mode=0o700)
            (work / 'evidence').mkdir(mode=0o700)
            run(['javac', '--release', '21', '-cp', ':'.join(str(jar) for jar in jars),
                '-d', str(work / 'classes'), str(upgrade.HELPER)])
            stage = 'LOAD_EXACT_UNTAGGED_IMAGE'
            app_id, loaded = load_image(args.image, identities['image'], args.expected_image_id, config_id, image_config)
            evidence.update(local_runtime_image_id=app_id, image_loaded=loaded,
                            immutable_identity_mapping='TRUSTED_BUILT_INDEX_TO_VERIFIED_CONFIG_AND_ROOTFS')
            mysql_env, app_env = fixture_environment(source, secrets.token_hex(32))
            write_env(work / 'mysql.env', mysql_env)
            write_env(work / 'app.env', app_env)
            write_env(work / 'redis.env', {'REDIS_PASSWORD': source['REDIS_PASSWORD']})
            password = source['REDIS_PASSWORD']
            if any(ord(character) < 32 or ord(character) == 127 for character in password):
                raise ValueError('Printable Redis credential required')
            with (work / 'redis.conf').open('x') as stream:
                stream.write('save ""\nappendonly no\nloglevel warning\nrequirepass "'
                    + password.replace('\\', '\\\\').replace('"', '\\"') + '"\n')
            (work / 'redis.conf').chmod(0o600)
            stage = 'CREATE_OWNED_INTERNAL_FIXTURES'
            network = 'flare-local-legacy-network-' + nonce
            run(['docker', 'network', 'create', '--internal', '--driver', 'bridge', *labels(nonce), network])
            owned_network(network, nonce)
            database, redis, java, app = ('flare-local-legacy-' + role + '-' + nonce for role in ('db', 'redis', 'java', 'app'))
            containers.append(database)
            run(mysql_command(database, network, nonce, work / 'mysql.env'))
            owned_container(database, network, nonce)
            for _ in range(60):
                if run(upgrade.database_command(database, True), b'SELECT 1;', check=False, timeout=10).returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Disposable database not ready')
            stage = 'RESTORE_PRIVATE_COPY_AND_MIGRATE_27_TO_36'
            run(upgrade.database_command(database, True), payload)
            containers.append(java)
            command = upgrade.java_container_command(java, database, work / 'mysql.env', work, args.frozen_dependencies.resolve())
            command[command.index('flare.scope=disposable-local-backup-upgrade')] = 'flare.scope=' + SCOPE
            command[command.index('--env-file'):command.index('--env-file')] = ['--label', 'flare.rehearsal=' + nonce]
            run(command)
            verification = json.loads(upgrade.regular_file(work / 'evidence/helper.json', 1024 * 1024).read_bytes())
            if verification.get('passed') is not True:
                raise RuntimeError('Current Flyway preservation verification failed')
            evidence['upgrade_verification'] = verification
            before = capture(database, network, nonce)
            if before['schema_version'] != '36' or len(before['tables']) != 45 or len(before['primary_models']) != 1:
                raise ValueError('Upgraded schema and original primary required')
            stage = 'START_DISPOSABLE_REDIS'
            containers.append(redis)
            run(redis_command(redis, network, nonce, work / 'redis.env'))
            owned_container(redis, network, nonce)
            for _ in range(30):
                ready = run(['docker', 'exec', redis, 'sh', '-ceu',
                    'REDISCLI_AUTH="$REDIS_PASSWORD" exec redis-cli ping'], check=False, timeout=5)
                if ready.returncode == 0 and ready.stdout.strip() == b'PONG':
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Disposable Redis not ready')
            stage = 'START_ACTUAL_OLD_APP_WITH_DEFAULT_FLYWAY_POLICY'
            containers.append(app)
            run(app_command(app, network, nonce, work / 'app.env', app_id))
            state = owned_container(app, network, nonce)
            if state['Image'] != app_id or state['Config']['Entrypoint'] != image_config['config']['Entrypoint']:
                raise ValueError('App is not the exact trusted immutable runtime')
            for _ in range(120):
                health = run(['docker', 'exec', app, 'curl', '--silent', '--output', '/dev/null',
                    '--max-time', '3', '--write-out', '%{http_code}', 'http://127.0.0.1:8080/actuator/health'],
                    check=False, timeout=5)
                if health.returncode == 0 and health.stdout == b'200':
                    break
                if not owned_container(app, network, nonce)['State']['Running']:
                    raise RuntimeError('Exact old application exited before health')
                time.sleep(1)
            else:
                raise RuntimeError('Exact old application did not report HTTP 200')
            evidence['actual_app_health_http_status'] = 200
            response = run(['docker', 'logs', '--tail', '200', app])
            diagnostics = response.stdout + response.stderr
            if b'Successfully validated 34 migrations' not in diagnostics:
                raise ValueError('Actual packaged Flyway validation evidence required')
            evidence.update(actual_old_app_flyway_validated_migrations=34,
                actual_old_app_future_schema_warning=b'newer than the latest available migration' in diagnostics,
                disabled_ueba_alias='OWNED_REDIS_FIXTURE_PORT_8091_CLOSED_NO_WORKER')
            stage = 'VERIFY_SCHEMA_PRIMARY_AND_ALL_TABLES_AFTER_OLD_APP_STARTUP'
            after = capture(database, network, nonce)
            if not inventory.compare(before, after):
                raise ValueError('Schema, primary binding or table population changed on old-app startup')
            owned_network(network, nonce)
            owned_container(redis, network, nonce)
            owned_container(app, network, nonce)
            evidence.update(schema_version_after_startup=after['schema_version'],
                preserved_table_count=len(after['tables']), schema_and_all_rows_preserved=True,
                primary_binding_preserved=True, before_startup_inventory_sha256=before['content_sha256'],
                after_startup_inventory_sha256=after['content_sha256'])
            stage = 'RECHECK_ALL_SOURCE_IDENTITIES'
            for name, digest in identities.items():
                private_hash(getattr(args, name), digest, image_verifier.MAX_ARCHIVE_BYTES)
            stage = 'COMPLETE'
            evidence['passed'] = True
        except (ValueError, RuntimeError, KeyError, OSError, subprocess.SubprocessError) as failure:
            evidence['failure_class'] = type(failure).__name__
            if isinstance(failure, subprocess.CalledProcessError):
                evidence['failed_command_returncode'] = failure.returncode
            # Private fixture logs help diagnose a local failure without ever
            # displaying credentials, addresses, SQL or application diagnostics.
            diagnostic = output.with_name(output.stem + '-private-diagnostics.json')
            with diagnostic.open('x') as stream:
                logs = {}
                for name in containers:
                    try:
                        response = run(['docker', 'logs', '--tail', '200', name], check=False, timeout=10)
                        logs[name] = (response.stdout + response.stderr).decode('utf-8', errors='replace')
                    except (OSError, subprocess.SubprocessError):
                        logs[name] = 'LOCAL_DIAGNOSTIC_CAPTURE_FAILED'
                json.dump(logs, stream)
            diagnostic.chmod(0o600)
        finally:
            evidence['owned_disposable_resources_removed'] = cleanup(containers, network, nonce)
            if not evidence['owned_disposable_resources_removed']:
                evidence['passed'] = False
            evidence['stage'] = stage
            with output.open('x') as stream:
                json.dump(evidence, stream, indent=2)
    print(json.dumps({'passed': evidence['passed'], 'stage': stage,
        'owned_disposable_resources_removed': evidence['owned_disposable_resources_removed'],
        'private_evidence': str(output.relative_to(ROOT))}))
    return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
