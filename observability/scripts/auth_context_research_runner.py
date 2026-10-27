#!/usr/bin/env python3
"""Run one isolated research stage with bounded resources and split mounts.

This supervisor only creates short-lived containers named by this process. It
never operates on an application container or mounts model releases writable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
RESEARCH_ROOT = Path('/home/quan/.codex/research/model-capability-assessment')
PUBLICATIONS = Path('/home/quan/PBL4(UpdateFromPBL3)/observability/runtime/postlogin-project-runtime')
BASELINE = PUBLICATIONS / 'model-v1'
SHADOW = PUBLICATIONS / 'auth-shadow-20261024-a-42-b07e6bfac1b9'
BASELINE_SHA = '7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784'
SHADOW_SHA = 'e63df6cac025deee2b7a474b02a073ae1f8bc8213d931498d7f530cdf615f600'
WORKER_IMAGE = 'sha256:4a37528fba90444305c2bf7eb685e1fad6750cc146435c582ee024dcf82acd2b'
PRODUCER_IMAGE = 'sha256:02495bec4b4ec7024f86829b10464c7a283d1a2ecc398858b4eada2f2ae7e628'
JDK_IMAGE = 'sha256:4efe8769cc3208b00c72c06813da9e4f65da0007a474645e1e9ff3f8e59fbf5b'
ADMISSION_MEMORY = 11 * 1024**3 // 2
RESERVE_MEMORY = 3 * 1024**3
DISK_FREE = 9 * 1024**3
ARTIFACT_LIMIT = 4 * 1024**3
MAX_SECONDS = 5400
FIT_SECONDS = 1800
METADATA = ('manifest.json', 'protocol.json', 'producer-parity.json')
SPLITS = {'select': ('train.jsonl.gz', 'calibration.jsonl.gz', 'development.jsonl.gz'),
          'evaluate': ('evaluation.jsonl.gz', 'controls.jsonl.gz'),
          'benchmark': ('evaluation.jsonl.gz',)}


def available_memory() -> int:
    for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('STOP_RESOURCE: MemAvailable unavailable')


def safe_path(path: Path, parent: Path, *, exists: bool = True) -> Path:
    path = path.absolute()
    if ('..' in path.parts or path == parent or parent not in path.parents
            or ',' in str(path) or '\n' in str(path)):
        raise ValueError('path must be a child of the isolated research directory')
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('symlink paths are not allowed')
    if exists and not path.exists():
        raise ValueError('research path is missing')
    return path


def size_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlinks are not allowed in research artifacts')
        if path.is_file():
            total += path.stat().st_size
            if total > ARTIFACT_LIMIT:
                break
    return total


def resource_check(job: Path, *, admission: bool) -> None:
    required = ADMISSION_MEMORY if admission else RESERVE_MEMORY
    if available_memory() < required:
        raise RuntimeError('STOP_RESOURCE: insufficient host memory')
    if admission and shutil.disk_usage(job).free < DISK_FREE:
        raise RuntimeError('STOP_RESOURCE: insufficient free disk')
    if size_bytes(job) > ARTIFACT_LIMIT:
        raise RuntimeError('STOP_RESOURCE: research artifact quota exceeded')


def file_sha(path: Path, maximum: int = 65536) -> str:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('bounded regular file required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_classpath(job: Path, classpath: str, jar_sha: str | None) -> None:
    receipt = safe_path(job / 'classpath-receipt.json', job)
    if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 2 * 1024**2:
        raise ValueError('bounded classpath preparation receipt required')
    value = json.loads(receipt.read_bytes())
    if (value.get('status') != 'CLASSPATH_PREPARED' or value.get('app_image') != PRODUCER_IMAGE
            or value.get('classpath') != classpath or value.get('commit') != '60b505998f5e64cc8cff75f38dafcd1563de8929'
            or value.get('jdk_image') != JDK_IMAGE
            or value.get('jdk_major') != 21
            or value.get('preparer_sha256') != file_sha(ROOT / 'observability/scripts/auth_context_research_classpath.py', 1024 * 1024)
            or jar_sha is not None and value.get('application_jar_sha256') != jar_sha):
        raise ValueError('classpath preparation identity differs')
    class_dir = safe_path(job / 'classpath', RESEARCH_ROOT)
    paths = [safe_path(Path(entry), class_dir) for entry in classpath.split(os.pathsep)]
    jar = class_dir / 'app.jar'
    library_dir = class_dir / 'lib'
    libraries = sorted(library_dir.glob('*.jar'))
    if (library_dir.is_symlink() or not library_dir.is_dir() or not 1 <= len(libraries) <= 512
            or paths != [class_dir / 'harness', class_dir / 'classes', *libraries, jar]):
        raise ValueError('prepared classpath entries differ')
    last_check = time.monotonic()
    def streaming_sha(path):
        nonlocal last_check
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024**2:
            raise ValueError('bounded classpath file required')
        checksum = hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                checksum.update(chunk)
                if time.monotonic() - last_check >= 2:
                    resource_check(job, admission=False)
                    last_check = time.monotonic()
        return checksum.hexdigest()
    if streaming_sha(jar) != value.get('application_jar_sha256'):
        raise ValueError('producer jar checksum differs')
    source = class_dir / 'AuthShadowLabCaptureServer.java'
    compiled = class_dir / 'harness/com/flarefitness/backend/ops/AuthShadowLabCaptureServer.class'
    if (file_sha(source, 1024 * 1024) != value.get('harness_source_sha256')
            or file_sha(compiled, 1024 * 1024) != value.get('harness_class_sha256')):
        raise ValueError('harness source or class checksum differs')
    if ([{'name': path.name, 'sha256': streaming_sha(path)} for path in libraries]
            != value.get('libraries')):
        raise ValueError('producer libraries differ from preparation receipt')
    class_root = class_dir / 'classes'
    classes = []
    for path in sorted(class_root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink in producer classes')
        if path.is_file():
            classes.append((str(path.relative_to(class_root)), streaming_sha(path)))
            if len(classes) > 100000:
                raise ValueError('producer class inventory too large')
    class_hash = hashlib.sha256(json.dumps(classes, separators=(',', ':')).encode()).hexdigest()
    if len(classes) != value.get('application_class_files') or class_hash != value.get('application_classes_sha256'):
        raise ValueError('producer classes differ from preparation receipt')


def bind(source: Path, target: str, *, writable: bool = False) -> list[str]:
    if ',' in str(source) or '\n' in str(source) or ',' in target or '\n' in target:
        raise ValueError('invalid bind path')
    spec = f'type=bind,src={source},dst={target}' + ('' if writable else ',readonly')
    return ['--mount', spec]


def verify_models() -> None:
    if file_sha(BASELINE / 'manifest.json') != BASELINE_SHA:
        raise ValueError('baseline manifest changed')
    if file_sha(SHADOW / 'manifest.json') != SHADOW_SHA:
        raise ValueError('shadow manifest changed')


def check_fit_deadlines(result: Path, first_seen: dict[str, float], now: float) -> None:
    for name in ('A-42', 'A-43', 'B-42', 'B-43'):
        reservation = result / (name + '-fit-reserved.json')
        state = result / (name + '-state.json')
        if reservation.is_file() and not state.is_file():
            first_seen.setdefault(name, now)
            if now - first_seen[name] > FIT_SECONDS:
                raise RuntimeError('STOP_RESOURCE: fit deadline exceeded')


def container_command(stage: str, job: Path, classpath: str | None, jar_sha: str | None, name: str) -> list[str]:
    memory, cpus, threads = ('512m', '1', '1') if stage == 'benchmark' else ('2g', '2', '2')
    args = ['docker', 'run', '--rm', '--name', name, '--label', 'auth.research.owner=' + name,
            '--network', 'none', '--memory', memory,
            '--cpus', cpus, '--pids-limit', '256', '--user', f'{os.getuid()}:{os.getgid()}',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--tmpfs', '/tmp:rw,nosuid,size=64m', '--workdir', '/service',
            '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', 'AUTH_RESEARCH_SUPERVISED=1', '-e', 'OMP_NUM_THREADS=' + threads,
            '-e', 'OPENBLAS_NUM_THREADS=' + threads]
    if stage in ('capture', 'parity'):
        if not classpath:
            raise ValueError('classpath is required for capture and parity')
        verify_classpath(job, classpath, jar_sha)
        args += bind(ROOT, '/workspace') + bind(job, str(job), writable=True)
        args += [WORKER_IMAGE, 'python', '/workspace/observability/scripts/auth_context_research_v2.py', stage]
        data = job / 'corpus'
        args += ['--output' if stage == 'capture' else '--data', str(data), '--java-classpath', classpath]
        if stage == 'parity':
            if not jar_sha or not re.fullmatch('[a-f0-9]{64}', jar_sha):
                raise ValueError('pinned application jar SHA-256 is required')
            args += ['--application-jar-sha256', jar_sha]
        return args

    verify_models()
    corpus, result = job / 'corpus', job / 'result'
    safe_path(corpus, RESEARCH_ROOT)
    safe_path(result, RESEARCH_ROOT)
    for filename in METADATA + SPLITS[stage]:
        source = safe_path(corpus / filename, corpus)
        if not source.is_file():
            raise ValueError('required corpus file is missing')
        args += bind(source, '/research/data/' + filename)
    module = ROOT / 'ueba-worker/app/auth_shadow_research.py'
    args += bind(module, '/service/app/auth_shadow_research.py')
    args += bind(BASELINE, '/run/model') + bind(SHADOW, '/run/auth-shadow')
    args += bind(result, '/research/result', writable=True)
    args += ['-e', 'UEBA_POSTLOGIN_MODEL_DIR=/run/model', '-e', 'UEBA_POSTLOGIN_MANIFEST_SHA256=' + BASELINE_SHA,
             '-e', 'UEBA_AUTH_SHADOW_MODEL_DIR=/run/auth-shadow', '-e', 'UEBA_AUTH_SHADOW_MANIFEST_SHA256=' + SHADOW_SHA,
             WORKER_IMAGE, 'python', '-m', 'app.auth_shadow_research', stage,
             '--data', '/research/data', '--output', '/research/result']
    return args


def run(stage: str, job: Path, classpath: str | None = None, jar_sha: str | None = None) -> None:
    job = safe_path(job, RESEARCH_ROOT)
    if not job.is_dir() or job.stat().st_uid != os.getuid() or job.stat().st_mode & 0o077:
        raise ValueError('owner-only research job directory required')
    resource_check(job, admission=True)
    name = 'auth-research-' + uuid.uuid4().hex
    args = container_command(stage, job, classpath, jar_sha, name)
    return run_command(args,job,stage,fit_result=job/'result' if stage=='select' else None)


def run_command(args,job,stage,*,fit_result=None):
    """Shared supervisor for registered research adapters, never a shell command."""
    job=safe_path(job,RESEARCH_ROOT)
    if not job.is_dir() or job.stat().st_uid!=os.getuid() or job.stat().st_mode&0o077:
        raise ValueError('owner-only research job directory required')
    if not re.fullmatch('[a-z0-9-]{1,64}',stage) or args[:2]!=['docker','run']:
        raise ValueError('registered Docker stage required')
    name=args[args.index('--name')+1]
    if not re.fullmatch('auth-research-[a-f0-9]{32}',name):raise ValueError('private container identity required')
    resource_check(job,admission=True)
    log_path = job / (stage + '-supervisor.log')
    receipt_path = job / (stage + '-supervisor.json')
    started = time.monotonic()
    failure = None
    with log_path.open('x', encoding='utf-8') as log:
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        first_seen: dict[str, float] = {}
        previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        def interrupt(_signum, _frame):
            raise KeyboardInterrupt
        for sig in previous_handlers:
            signal.signal(sig, interrupt)
        try:
            try:
                while process.poll() is None:
                    now = time.monotonic()
                    try:
                        resource_check(job, admission=False)
                        if now - started > MAX_SECONDS:
                            raise RuntimeError('STOP_RESOURCE: stage deadline exceeded')
                        if fit_result is not None:
                            check_fit_deadlines(fit_result, first_seen, now)
                    except (RuntimeError, ValueError) as error:
                        failure = str(error)
                        break
                    time.sleep(2)
            except KeyboardInterrupt:
                failure = 'STOP_INTERRUPTED'
            if failure:
                # Only this randomly named research container is ever targeted.
                subprocess.run(['docker', 'kill', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, check=False)
            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait(timeout=10)
                failure = failure or 'STOP_RESOURCE: container shutdown timeout'
        finally:
            if process.poll() is None:
                subprocess.run(['docker', 'kill', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=20, check=False)
                process.wait(timeout=30)
            for sig, previous in previous_handlers.items():
                signal.signal(sig, previous)
    value = {'stage': stage, 'status': failure or ('COMPLETED' if code == 0 else 'STAGE_FAILED'),
             'exit_code': code, 'seconds': round(time.monotonic() - started, 2),
             'worker_image': WORKER_IMAGE, 'source_sha256': file_sha(Path(__file__), 1024 * 1024)}
    with receipt_path.open('x', encoding='utf-8') as file:
        os.chmod(receipt_path, 0o600)
        json.dump(value, file, sort_keys=True, allow_nan=False)
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(value))
    if failure or code:
        raise RuntimeError(value['status'])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('capture', 'parity', 'select', 'evaluate', 'benchmark'))
    parser.add_argument('--job', required=True, type=Path)
    parser.add_argument('--java-classpath')
    parser.add_argument('--application-jar-sha256')
    args = parser.parse_args()
    try:
        run(args.stage, args.job, args.java_classpath, args.application_jar_sha256)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
