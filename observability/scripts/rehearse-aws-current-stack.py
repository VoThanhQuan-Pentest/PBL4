#!/usr/bin/env python3
"""Opt-in disposable current app/worker rehearsal of trusted private AWS copies.

Supply newly built immutable current image IDs and the freshly packaged app JAR
hash. This helper never builds, pulls, retags, deploys, contacts AWS, publishes
ports, or accesses an active database. It reuses the existing real-Flyway backup
rehearsal and inventories. Current packaged Java gateway code calls the real
current worker with the retained schema-1 model. SIEM/provider integrations are
disabled and scheduled UEBA mutations delayed; this is NOT full AWS acceptance.
Only caller-trusted, explicitly hash-bound owned pickle artifacts are executed,
inside an unprivileged read-only container on an owned internal network.
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
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = Path(__file__).resolve().parent
SCOPE = 'disposable-local-current-stack'
MAX_JAR = 128 * 1024 * 1024


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


legacy = module('current_stack_legacy', SCRIPTS / 'rehearse-aws-legacy-app.py')
upgrade = legacy.upgrade
inventory = legacy.inventory
verifier = legacy.image_verifier


def run(command, data=None, check=True, timeout=300):
    return legacy.run(command, data, check=check, timeout=timeout)


def labels(nonce):
    return ['--label', 'flare.scope=' + SCOPE, '--label', 'flare.rehearsal=' + nonce]


def owned_network(network, nonce):
    state = json.loads(run(['docker', 'network', 'inspect', network]).stdout)[0]
    if (not state.get('Internal') or state['Driver'] != 'bridge'
            or state.get('Labels', {}).get('flare.scope') != SCOPE
            or state.get('Labels', {}).get('flare.rehearsal') != nonce):
        raise ValueError('Owned internal rehearsal network required')
    return state


def owned_container(name, network, nonce):
    state = json.loads(run(['docker', 'inspect', '--type', 'container', name]).stdout)[0]
    if (state['Config'].get('Labels', {}).get('flare.scope') != SCOPE
            or state['Config']['Labels'].get('flare.rehearsal') != nonce
            or state['HostConfig'].get('PortBindings')
            or set(state['NetworkSettings']['Networks']) != {network}):
        raise ValueError('Exact owned no-published-port fixture required')
    owned_network(network, nonce)
    return state


def cleanup(containers, network, nonce):
    good = True
    for name in reversed(containers):
        try:
            process = run(['docker', 'inspect', '--type', 'container', name], check=False, timeout=10)
            if process.returncode:
                good = (b'No such' in process.stderr) and good
                continue
            state = json.loads(process.stdout)[0]
            config = state['Config'].get('Labels', {})
            if config.get('flare.scope') != SCOPE or config.get('flare.rehearsal') != nonce:
                raise ValueError('Unowned fixture cleanup rejected')
            if state['HostConfig']['NetworkMode'].startswith('container:'):
                # Docker normalizes namespace sharing to the owned DB ID.
                # The helper's exact randomly named Java fixture is the only
                # namespace-sharing resource, recorded before its creation.
                target = state['HostConfig']['NetworkMode'].split(':', 1)[1]
                database = owned_container(target, network, nonce)
                if (name != 'flare-local-current-java-' + nonce
                        or database['Name'] != '/flare-local-current-db-' + nonce
                        or state['HostConfig'].get('PortBindings')):
                    raise ValueError('Unexpected namespace-sharing fixture')
            else:
                owned_container(name, network, nonce)
            good = run(['docker', 'rm', '-fv', name], check=False, timeout=30).returncode == 0 and good
        except (ValueError, KeyError, OSError, subprocess.SubprocessError):
            good = False
    if network:
        try:
            state = owned_network(network, nonce)
            good = not state.get('Containers') and good
            if not state.get('Containers'):
                good = run(['docker', 'network', 'rm', state['Id']], check=False, timeout=30).returncode == 0 and good
        except (ValueError, KeyError, OSError, subprocess.SubprocessError):
            good = False
    return good


def immutable_image(identity, kind):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', identity):
        raise ValueError('Immutable local image ID required')
    state = legacy.inspect_image(identity)
    if state is None or state['Id'] != identity:
        raise ValueError('Exact current image must already exist locally')
    config = state['Config']
    if any('FLYWAY' in entry.upper() for entry in config.get('Env', [])):
        raise ValueError('Image Flyway policy must remain unchanged')
    if config.get('Volumes') or config.get('OnBuild'):
        raise ValueError('No inherited anonymous volumes or build triggers permitted')
    if kind == 'app' and config.get('Entrypoint') != ['java', '-jar', '/app/app.jar']:
        raise ValueError('Expected current app image entrypoint required')
    if kind == 'worker' and config.get('Cmd') != ['uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8091', '--workers', '1']:
        raise ValueError('Expected current worker image command required')
    return state


def protected_output(path):
    path = path.absolute()
    runtime = ROOT / 'observability/runtime'
    if path.exists() or path.is_symlink() or not path.is_relative_to(runtime):
        raise ValueError('New private runtime output required')
    for candidate in (path.parent, *path.parent.parents):
        if candidate.is_symlink():
            raise ValueError('Symlinked evidence path rejected')
        if candidate == runtime:
            break
    if (not path.parent.is_dir() or path.parent.stat().st_mode & 0o077
            or path.parent.stat().st_uid != os.geteuid()):
        raise ValueError('Existing owned 0700 evidence parent required')
    return path


def source_hashes():
    paths = [ROOT / 'backend/pom.xml', ROOT / 'backend/Dockerfile',
             ROOT / 'ueba-worker/Dockerfile', ROOT / 'ueba-worker/requirements.lock']
    paths += sorted((ROOT / 'backend/src/main').rglob('*'))
    paths += sorted((ROOT / 'ueba-worker/app').glob('*.py'))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file() and not path.is_symlink()}


def existing_services():
    # Other agents may run disposable test containers concurrently. Preserve
    # only this workstation's established long-running application stack.
    identities = run(['docker', 'ps', '--quiet', '--no-trunc',
                      '--filter', 'label=com.docker.compose.project=flare-local-elk',
                      '--filter', 'name=flare-local-elk-']).stdout.decode().splitlines()
    return {identity: service_state(identity) for identity in identities}


def service_state(identity):
    # Read only selected state; never emit or retain effective configuration.
    template = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}}}'
    return json.loads(run(['docker', 'inspect', '--type', 'container', '--format', template, identity]).stdout)


def fixture_command(name, network, nonce, image, *, alias=None, env=None):
    command = ['docker', 'run', '-d', '--pull=never', '--name', name, '--network', network,
               *labels(nonce), '--user', f'{os.getuid()}:{os.getgid()}', '--read-only',
               '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit', '256',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m']
    if alias:
        command += ['--network-alias', alias]
    if env:
        command += ['--env-file', str(env)]
    return command


def database_command(name, network, nonce, env):
    command = legacy.mysql_command(name, network, nonce, env)
    command[command.index('flare.scope=' + legacy.SCOPE)] = 'flare.scope=' + SCOPE
    return command


def redis_command(name, network, nonce, env):
    command = legacy.redis_command(name, network, nonce, env)
    command[command.index('flare.scope=' + legacy.SCOPE)] = 'flare.scope=' + SCOPE
    # In the legacy rehearsal Redis deliberately occupies the disabled worker
    # alias. Here only the actual worker may resolve as ueba-worker.
    position = command.index('ueba-worker')
    del command[position - 1:position + 1]
    return command


def wait_database(database):
    for _ in range(60):
        if run(upgrade.database_command(database, True), b'SELECT 1;', check=False, timeout=10).returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError('Disposable database not ready')


def capture(database, network, nonce):
    owned_container(database, network, nonce)
    with inventory.MysqlReadOnly(database) as client:
        return inventory.capture(client.query)


def wait_app(app, network, nonce):
    for _ in range(120):
        state = owned_container(app, network, nonce)
        if not state['State']['Running']:
            raise RuntimeError('Current app exited before health')
        result = run(['docker', 'exec', app, 'curl', '--silent', '--output', '/dev/null',
                      '--max-time', '3', '--write-out', '%{http_code}',
                      'http://127.0.0.1:8080/actuator/health'], check=False, timeout=5)
        if result.returncode == 0 and result.stdout == b'200':
            return
        time.sleep(1)
    raise RuntimeError('Current app did not report HTTP 200')


MODEL_UNPACK = r'''
import hashlib,json,os,sys
from pathlib import Path
from app.restore_check import unpack_owned_backup
os.umask(0o077)
root=Path('/fixture/models')
unpack_owned_backup(Path('/fixture/archive.tar.gz'),root,sys.argv[1])
selection=json.loads((root/'active.json').read_text())
if selection != {'model_version':sys.argv[2]}: raise ValueError('exact retained primary required')
print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}))
'''


# Profile actual current functions without replacing them or mocking scoring.
# Counts distinguish loading an existing selection (persist=False) from promotion.
WORKER_LAUNCH = r'''
import json,os,sys,threading
from pathlib import Path
os.umask(0o077)
sys.path.insert(0,'/service')
counter=Path('/fixture/metrics/calls.json')
counts={'model_fit_calls':0,'training_calls':0,'persistent_activation_calls':0,'retained_selection_load_calls':0,'score_samples_calls':0}
def save():
    temporary=counter.with_suffix('.tmp')
    temporary.write_text(json.dumps(counts,sort_keys=True)); temporary.chmod(0o600)
    os.replace(temporary,counter)
def profile(frame,event,arg):
    if event!='call': return
    name=frame.f_code.co_name; module=frame.f_globals.get('__name__',''); key=None
    if name=='fit' and module.startswith('sklearn.'): key='model_fit_calls'
    elif name=='train' and module=='app.model': key='training_calls'
    elif name=='activate' and module=='app.model':
        key='persistent_activation_calls' if frame.f_locals.get('persist',True) else 'retained_selection_load_calls'
    elif name=='score_samples' and module=='sklearn.ensemble._iforest': key='score_samples_calls'
    if key: counts[key]+=1; save()
save();sys.setprofile(profile);threading.setprofile(profile)
import uvicorn
uvicorn.run('app.main:app',host='0.0.0.0',port=8091,workers=1,access_log=False)
'''


GATEWAY_PROBE = r'''
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.service.siem.SiemUebaGateway;
import java.util.List;
import java.util.Map;
public class CurrentStackGatewayProbe {
    public static void main(String[] args) throws Exception {
        var gateway = new SiemUebaGateway(true, "http://ueba-worker:8091", "/fixture/ueba.token", new ObjectMapper());
        var health = gateway.health();
        if (!health.workerAvailable() || !health.modelAvailable() || health.featureSchemaVersion()!=1
                || !args[0].equals(health.activeModelVersion())) throw new IllegalStateException("retained worker primary unavailable");
        var normal = List.of(4d,0d,0d,0d,1d,0d,1d,1d,0d,0d,0d);
        var rows = List.of(normal,List.of(40d,0d,0d,0d,1d,0d,2d,1d,0d,0d,0d),normal);
        var first = gateway.score(rows,1); var second = gateway.score(rows,1);
        if (!first.available() || !second.available() || first.featureSchemaVersion()!=1 || second.featureSchemaVersion()!=1
                || !args[0].equals(first.modelVersion()) || !args[0].equals(second.modelVersion())
                || first.results().size()!=3 || second.results().size()!=3 || first.policy()==null
                || first.calibrationSha256()==null || !first.calibrationSha256().matches("[0-9a-f]{64}")
                || !first.calibrationSha256().equals(second.calibrationSha256())) throw new IllegalStateException("real score binding failed");
        for (int i=0;i<3;i++) {
            var a=first.results().get(i);var b=second.results().get(i);
            if (a.rawAnomalyScore()!=b.rawAnomalyScore() || a.normalPercentile()!=b.normalPercentile()
                    || !a.level().equals(b.level())) throw new IllegalStateException("unstable score");
        }
        var a=first.results().get(0);var b=first.results().get(2);
        if (a.rawAnomalyScore()!=b.rawAnomalyScore() || a.normalPercentile()!=b.normalPercentile()
                || !a.level().equals(b.level())) throw new IllegalStateException("duplicate score mismatch");
        System.out.println(new ObjectMapper().writeValueAsString(Map.of("passed",true,"actual_vectors_scored",6,
                "http_score_batches",2,"feature_schema_version",1,"model_version",first.modelVersion(),
                "calibration_sha256",first.calibrationSha256(),"duplicate_and_repeated_batch_stable",true,
                "scope","EXACT_CURRENT_PACKAGED_JAVA_GATEWAY_REAL_CURRENT_WORKER")));
    }
}
'''


def expand_jar(jar, root):
    # The app JAR is explicitly caller-hash-bound before parsing. Still forbid
    # duplicate/traversal/oversized entries and extract only classpath material.
    total = 0
    names = set()
    with zipfile.ZipFile(jar) as archive:
        for entry in archive.infolist():
            name = entry.filename
            if name in names:
                raise ValueError('Duplicate packaged JAR member')
            names.add(name)
            if not (name.startswith('BOOT-INF/classes/') or name.startswith('BOOT-INF/lib/')) or entry.is_dir():
                continue
            path = Path(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or entry.file_size > MAX_JAR:
                raise ValueError('Unsafe packaged JAR member')
            total += entry.file_size
            if total > 256 * 1024 * 1024:
                raise ValueError('Bounded app classpath required')
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as destination:
                destination.write(archive.read(entry))
            target.chmod(0o600)
    classes = root / 'BOOT-INF/classes'
    jars = sorted((root / 'BOOT-INF/lib').glob('*.jar'))
    if not jars or not (classes / 'com/flarefitness/backend/service/siem/SiemUebaGateway.class').is_file():
        raise ValueError('Current packaged gateway and dependencies required')
    return classes, jars


def current_worker_hashes(worker):
    code = "import pathlib,hashlib,json;print(json.dumps({str(p.relative_to('/service')):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(pathlib.Path('/service/app').glob('*.py'))}))"
    return json.loads(run(['docker', 'exec', worker, 'python', '-c', code]).stdout)


def dependency_pins(body):
    if not isinstance(body, str) or len(body) > 65536:
        raise ValueError('Bounded exact worker dependency lock required')
    pins, names = {}, set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not re.fullmatch(r'[A-Za-z0-9_.-]+==[A-Za-z0-9.+-]+', line):
            raise ValueError('Exact worker package/version lock required')
        name, version = line.split('==')
        canonical = re.sub(r'[-_.]+', '-', name).lower()
        if canonical in names or len(pins) >= 256:
            raise ValueError('Unique bounded worker dependency pins required')
        names.add(canonical); pins[name] = version
    if not pins:
        raise ValueError('Nonempty worker dependency lock required')
    return pins


def installed_worker_dependencies(worker, expected):
    # Package names are source-controlled exact pins, never shell fragments.
    code = "import importlib.metadata,json,sys;names=json.loads(sys.argv[1]);print(json.dumps({name:importlib.metadata.version(name) for name in names}))"
    installed = json.loads(run(['docker', 'exec', worker, 'python', '-c', code,
                                json.dumps(sorted(expected))]).stdout)
    if installed != expected:
        raise ValueError('Installed current worker versions differ from locked versions')
    return installed


def model_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-disposable-local-startup', action='store_true', required=True)
    for name in ('backup', 'configuration', 'models', 'frozen-dependencies', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('backup', 'configuration', 'models', 'app-jar'):
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    for name in ('app-image', 'worker-image', 'expected-primary'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        output = protected_output(args.output)
        if os.getuid() == 0 or not re.fullmatch(r'[a-z0-9_-]{8,64}', args.expected_primary):
            raise ValueError('Non-root caller and exact safe primary required')
        if not re.fullmatch(r'[0-9a-f]{64}', args.expected_app_jar_sha256):
            raise ValueError('Current freshly packaged app JAR checksum required')
    except (ValueError, OSError):
        parser.error('Invalid or unprotected rehearsal input/output')
    evidence = {'passed': False, 'scope': 'LOCAL_CURRENT_APP_AND_WORKER_RETAINED_AWS_PRIMARY_ONLY',
        'observed_at': datetime.now(timezone.utc).isoformat(), 'full_aws_acceptance': False,
        'aws_calls': False, 'deployment': False, 'active_database_touched': False,
        'public_ports': False, 'network_egress': False, 'provider_calls': False,
        'flyway_policy': 'CURRENT_IMAGE_PACKAGED_DEFAULT_UNCHANGED', 'checksum_repair_or_bypass': False,
        'siem_ueba_enabled': True, 'siem_background_integrations_enabled': False,
        'ueba_scheduled_mutations_delayed_ms': 3600000, 'worker_model_mount_read_only': True,
        'fixture_os_user': 'CALLER_NON_ROOT_UID_GID', 'image_build_pull_or_retag': False,
        'preserved_running_services_scope': 'LONG_RUNNING_LOCAL_COMPOSE_PROJECT_FLARE_LOCAL_ELK',
        'live_app_http_ueba_endpoint_exercised': False, 'gateway_probe_separate_jvm': True,
        'catalogue_java_workspace_integrations_tested': False, 'scheduled_ueba_jobs_exercised': False,
        'helper_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    source = source_hashes()
    tags = legacy.tagged_images()
    services = existing_services()
    stage, network, containers = 'INPUT_IDENTITIES', None, []
    nonce = secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix='flare-local-current-stack-') as temporary:
        work = Path(temporary)
        try:
            immutable_image(args.app_image, 'app'); immutable_image(args.worker_image, 'worker')
            identities = {name: legacy.private_hash(getattr(args, name), getattr(args, 'expected_' + name + '_sha256'),
                {'backup': upgrade.MAX_COMPRESSED_BYTES, 'configuration': 1024 * 1024, 'models': 64 * 1024 * 1024}[name])
                for name in ('backup', 'configuration', 'models')}
            payload, _ = upgrade.read_backup(args.backup, identities['backup'])
            if (not payload.startswith(b'-- MySQL dump') or not payload.rstrip().splitlines()[-1].startswith(b'-- Dump completed on ')
                    or b'\nUSE ' in payload or b'CREATE DATABASE' in payload or payload.count(b'CREATE TABLE') != 43):
                raise ValueError('Complete non-redirecting schema-27 source required')
            source_env = legacy.read_configuration(args.configuration, identities['configuration'])
            jars, frozen_sha = upgrade.frozen_jars(args.frozen_dependencies.resolve())
            for directory in ('classes', 'evidence', 'models', 'metrics', 'jar'):
                (work / directory).mkdir(mode=0o700)
            token = work / 'ueba.token'
            token.write_text(secrets.token_hex(32)); token.chmod(0o600)
            (work / 'worker-launch.py').write_text(WORKER_LAUNCH); (work / 'worker-launch.py').chmod(0o600)
            mysql_env, app_env = legacy.fixture_environment(source_env, secrets.token_hex(32))
            app_env.update(SIEM_UEBA_ENABLED='true', SIEM_UEBA_SERVICE_TOKEN_FILE='/fixture/ueba.token',
                           JAVA_TOOL_OPTIONS='-Dsiem.ueba.initial-delay-ms=3600000')
            legacy.write_env(work / 'mysql.env', mysql_env); legacy.write_env(work / 'app.env', app_env)
            legacy.write_env(work / 'redis.env', {'REDIS_PASSWORD': source_env['REDIS_PASSWORD']})
            password = source_env['REDIS_PASSWORD']
            if any(ord(c) < 32 or ord(c) == 127 for c in password):
                raise ValueError('Printable Redis credential required')
            (work / 'redis.conf').write_text('save ""\nappendonly no\nloglevel warning\nrequirepass "'
                + password.replace('\\', '\\\\').replace('"', '\\"') + '"\n')
            (work / 'redis.conf').chmod(0o600)
            evidence.update(source_sha256=identities, current_app_image_id=args.app_image,
                current_worker_image_id=args.worker_image, current_app_jar_sha256=args.expected_app_jar_sha256,
                frozen_dependency_manifest_sha256=frozen_sha, current_source_sha256=source)
            stage = 'CREATE_OWNED_INTERNAL_FIXTURES'
            network = 'flare-local-current-network-' + nonce
            run(['docker', 'network', 'create', '--internal', '--driver', 'bridge', *labels(nonce), network])
            owned_network(network, nonce)
            database, redis, java, unpack, worker, app, bridge = ('flare-local-current-' + role + '-' + nonce
                for role in ('db', 'redis', 'java', 'unpack', 'worker', 'app', 'gateway'))
            containers.append(database); run(database_command(database, network, nonce, work / 'mysql.env'))
            owned_container(database, network, nonce); wait_database(database)
            stage = 'RESTORE_AND_REAL_FLYWAY_UPGRADE'
            run(upgrade.database_command(database, True), payload)
            run(['javac', '--release', '21', '-cp', ':'.join(str(jar) for jar in jars),
                 '-d', str(work / 'classes'), str(upgrade.HELPER)])
            containers.append(java)
            command = upgrade.java_container_command(java, database, work / 'mysql.env', work, args.frozen_dependencies.resolve())
            command[command.index('--network') + 1] = network
            command[command.index('flare.scope=disposable-local-backup-upgrade')] = 'flare.scope=' + SCOPE
            command[command.index('--env-file'):command.index('--env-file')] = ['--label', 'flare.rehearsal=' + nonce]
            # Existing Java helper uses 127.0.0.1; share the exact owned database
            # network namespace instead, as the established rehearsal does.
            command[command.index('--network') + 1] = 'container:' + database
            run(command)
            verification = json.loads((work / 'evidence/helper.json').read_bytes())
            if verification.get('passed') is not True:
                raise RuntimeError('Real Flyway preservation verification failed')
            evidence['upgrade_verification'] = verification
            before = capture(database, network, nonce)
            if before['schema_version'] != '36' or len(before['tables']) != 45 or before['primary_models'] != [[args.expected_primary, 1, 'DEMO_ONLY']]:
                raise ValueError('Exact retained upgraded primary required')
            stage = 'UNPACK_OWNED_MODELS_WITH_CURRENT_WORKER'
            containers.append(unpack)
            command = fixture_command(unpack, network, nonce, args.worker_image)
            command += ['--mount', f'type=bind,src={args.models.resolve()},dst=/fixture/archive.tar.gz,readonly',
                '--mount', f'type=bind,src={work / "models"},dst=/fixture/models', '--entrypoint', 'python',
                args.worker_image, '-c', MODEL_UNPACK, identities['models'], args.expected_primary]
            run(command)
            owned_container(unpack, network, nonce)
            result = run(['docker', 'wait', unpack]); status = int(result.stdout)
            if status != 0:
                raise RuntimeError('Current owned-model unpack failed')
            restored_hashes = json.loads(run(['docker', 'logs', unpack]).stdout)
            if restored_hashes != model_hashes(work / 'models'):
                raise ValueError('Current restore file identities differ')
            evidence['retained_model_files_sha256'] = restored_hashes
            stage = 'START_CURRENT_WORKER_AND_REDIS'
            containers.append(redis); run(redis_command(redis, network, nonce, work / 'redis.env'))
            owned_container(redis, network, nonce)
            for _ in range(30):
                ready = run(['docker', 'exec', redis, 'sh', '-ceu',
                    'REDISCLI_AUTH="$REDIS_PASSWORD" exec redis-cli ping'], check=False, timeout=5)
                if ready.returncode == 0 and ready.stdout.strip() == b'PONG': break
                time.sleep(1)
            else: raise RuntimeError('Disposable Redis not ready')
            containers.append(worker)
            command = fixture_command(worker, network, nonce, args.worker_image, alias='ueba-worker')
            command += ['--env', 'UEBA_MODEL_DIR=/fixture/models', '--env', 'UEBA_SERVICE_TOKEN_FILE=/fixture/ueba.token',
                '--mount', f'type=bind,src={work / "models"},dst=/fixture/models,readonly',
                '--mount', f'type=bind,src={work / "metrics"},dst=/fixture/metrics',
                '--mount', f'type=bind,src={token},dst=/fixture/ueba.token,readonly',
                '--mount', f'type=bind,src={work / "worker-launch.py"},dst=/fixture/worker-launch.py,readonly',
                '--entrypoint', 'python', args.worker_image, '/fixture/worker-launch.py']
            run(command); owned_container(worker, network, nonce)
            expected_worker = {str(path.relative_to(ROOT / 'ueba-worker')): hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in sorted((ROOT / 'ueba-worker/app').glob('*.py'))}
            if current_worker_hashes(worker) != expected_worker:
                raise ValueError('Worker image source does not equal current worker code')
            lock = run(['docker', 'exec', worker, 'sha256sum', '/service/requirements.lock']).stdout.decode().split()[0]
            if lock != source['ueba-worker/requirements.lock']:
                raise ValueError('Worker image dependency lock differs')
            installed = installed_worker_dependencies(worker,
                dependency_pins((ROOT / 'ueba-worker/requirements.lock').read_text()))
            evidence['current_worker_code_verified'] = True
            evidence['current_worker_dependency_lock_verified'] = True
            evidence['current_worker_installed_versions_verified'] = True
            evidence['current_worker_installed_versions'] = installed
            stage = 'START_CURRENT_APP_WITH_DEFAULT_FLYWAY_AND_UEBA_ENABLED'
            containers.append(app)
            command = fixture_command(app, network, nonce, args.app_image, alias='current-app', env=work / 'app.env')
            command += ['--mount', f'type=bind,src={token},dst=/fixture/ueba.token,readonly', args.app_image]
            run(command); state = owned_container(app, network, nonce)
            if state['Image'] != args.app_image or 'SIEM_UEBA_ENABLED=true' not in state['Config']['Env']:
                raise ValueError('Exact app image with UEBA enabled required')
            jar = work / 'current-app.jar'
            run(['docker', 'cp', app + ':/app/app.jar', str(jar)]); jar.chmod(0o600)
            if jar.stat().st_size > MAX_JAR or hashlib.sha256(jar.read_bytes()).hexdigest() != args.expected_app_jar_sha256:
                raise ValueError('Packaged current app JAR identity differs')
            classes, app_jars = expand_jar(jar, work / 'jar')
            migration_files = sorted(upgrade.MIGRATIONS.glob('V*.sql'))
            packaged = classes / 'db/migration'
            if {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in packaged.glob('V*.sql')} != {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in migration_files}:
                raise ValueError('Current app packaged migration identity differs')
            wait_app(app, network, nonce)
            logs = run(['docker', 'logs', '--tail', '300', app])
            if b'Successfully validated 36 migrations' not in logs.stdout + logs.stderr:
                raise ValueError('Actual current app Flyway validation required')
            evidence.update(actual_current_app_health_http_status=200, actual_current_app_flyway_validated_migrations=36,
                            current_app_packaged_migrations_verified=True)
            stage = 'REAL_CURRENT_PACKAGED_JAVA_GATEWAY_TO_CURRENT_WORKER'
            probe = work / 'CurrentStackGatewayProbe.java'; probe.write_text(GATEWAY_PROBE); probe.chmod(0o600)
            run(['javac', '--release', '21', '-cp', ':'.join(str(p) for p in [classes, *app_jars]),
                 '-d', str(work / 'classes'), str(probe)])
            containers.append(bridge)
            command = fixture_command(bridge, network, nonce, args.app_image)
            command += ['--mount', f'type=bind,src={work / "classes"},dst=/fixture/classes,readonly',
                '--mount', f'type=bind,src={work / "jar"},dst=/fixture/jar,readonly',
                '--mount', f'type=bind,src={token},dst=/fixture/ueba.token,readonly', '--entrypoint', 'java',
                args.app_image, '-cp', '/fixture/classes:/fixture/jar/BOOT-INF/classes:/fixture/jar/BOOT-INF/lib/*',
                'CurrentStackGatewayProbe', args.expected_primary]
            run(command); owned_container(bridge, network, nonce)
            if int(run(['docker', 'wait', bridge]).stdout) != 0:
                raise RuntimeError('Current packaged gateway integration failed')
            gateway = json.loads(run(['docker', 'logs', bridge]).stdout)
            if gateway.get('passed') is not True:
                raise ValueError('Real current gateway score evidence required')
            evidence['gateway_verification'] = gateway
            stage = 'VERIFY_ALL_ORIGINAL_ROWS_AND_RETAINED_ARTIFACTS'
            after = capture(database, network, nonce)
            if not inventory.compare(before, after) or model_hashes(work / 'models') != restored_hashes:
                raise ValueError('Schema, data, primary or retained model artifact changed')
            counts = json.loads((work / 'metrics/calls.json').read_bytes())
            if (counts['model_fit_calls'] != 0 or counts['training_calls'] != 0
                    or counts['persistent_activation_calls'] != 0 or counts['retained_selection_load_calls'] != 1
                    or counts['score_samples_calls'] != 2):
                raise ValueError('Unexpected worker fit, promotion, restore or scoring count')
            evidence.update(worker_call_counts=counts, schema_version_after_startup=after['schema_version'],
                preserved_table_count=len(after['tables']), schema_and_all_rows_preserved=True,
                primary_binding_preserved=True, before_startup_inventory_sha256=before['content_sha256'],
                after_startup_inventory_sha256=after['content_sha256'], retained_model_files_unchanged=True)
            for name, digest in identities.items():
                legacy.private_hash(getattr(args, name), digest, verifier.MAX_ARCHIVE_BYTES)
            if source_hashes() != source or legacy.tagged_images() != tags:
                raise ValueError('Source tree or existing image tags changed during rehearsal')
            if any(service_state(identity) != state for identity, state in services.items()):
                raise ValueError('An existing service changed during rehearsal')
            evidence.update(source_artifacts_modified=False, existing_image_tags_modified=False,
                            existing_running_services_unchanged=True, existing_running_services_count=len(services))
            stage = 'COMPLETE'; evidence['passed'] = True
        except (ValueError, RuntimeError, KeyError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as failure:
            evidence['failure_class'] = type(failure).__name__
            if isinstance(failure, subprocess.CalledProcessError):
                evidence['failed_command_returncode'] = failure.returncode
            diagnostics = {}
            for name in containers:
                result = run(['docker', 'logs', '--tail', '300', name], check=False, timeout=10)
                diagnostics[name] = (result.stdout + result.stderr).decode(errors='replace')
            if isinstance(failure, subprocess.CalledProcessError):
                diagnostics['failed_subprocess'] = ((failure.stdout or b'') + (failure.stderr or b'')).decode(errors='replace')
            with output.with_name(output.stem + '-private-diagnostics.json').open('x') as stream:
                json.dump(diagnostics, stream, indent=2)
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
