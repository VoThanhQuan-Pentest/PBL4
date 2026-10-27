#!/usr/bin/env python3
"""Prepare a pinned, isolated Java classpath for offline auth research.

Usage: python auth_context_research_classpath.py --job <research-root/job> --init-job
Then:  python auth_context_research_classpath.py --job <research-root/job>
Pass the receipt's classpath and application_jar_sha256 to the research runner.
Preparation creates only its own temporary containers; it never starts the app.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
import zipfile

from auth_context_research_runner import (ARTIFACT_LIMIT, JDK_IMAGE, MAX_SECONDS, RESEARCH_ROOT,
                                          ROOT, bind, resource_check, safe_path)

APP_IMAGE = 'sha256:02495bec4b4ec7024f86829b10464c7a283d1a2ecc398858b4eada2f2ae7e628'
COMMIT = '60b505998f5e64cc8cff75f38dafcd1563de8929'
HARNESS = 'backend/src/test/java/com/flarefitness/backend/ops/AuthShadowLabCaptureServer.java'
MAX_ENTRY = 512 * 1024**2
MAX_EXTRACTED = 2 * 1024**3
BLOCK = 1024 * 1024


def sha(path: Path, check=None) -> str:
    digest = hashlib.sha256()
    checked = time.monotonic()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(BLOCK), b''):
            digest.update(chunk)
            if check and time.monotonic() - checked >= 2:
                check()
                checked = time.monotonic()
    return digest.hexdigest()


def init_job(job: Path) -> None:
    if '..' in job.parts:
        raise ValueError('parent traversal is forbidden')
    job = safe_path(job, RESEARCH_ROOT, exists=False)
    if job.parent != RESEARCH_ROOT or any(p.is_symlink() for p in (RESEARCH_ROOT, *RESEARCH_ROOT.parents)):
        raise ValueError('job must be a direct child of the research root')
    RESEARCH_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if RESEARCH_ROOT.stat().st_uid != os.getuid() or RESEARCH_ROOT.stat().st_mode & 0o077:
        raise ValueError('owner-only research root required')
    job.mkdir(mode=0o700)


def guard(job: Path, started: float) -> None:
    resource_check(job, admission=False)
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError('STOP_RESOURCE: classpath preparation deadline exceeded')


def command(args: list[str], job: Path, started: float, log, *, container: str | None = None) -> None:
    process = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    try:
        while process.poll() is None:
            guard(job, started)
            time.sleep(2)
        if process.returncode:
            raise RuntimeError('classpath preparation command failed: ' + args[0])
    except BaseException:
        if container is not None:
            # Only this invocation's random compiler container can be targeted.
            subprocess.run(['docker', 'kill', container], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=20)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)
        raise


def archive_target(info: zipfile.ZipInfo) -> Path | None:
    name = info.filename
    mode = info.external_attr >> 16
    if ('\\' in name or '\x00' in name or name.startswith('/')
            or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))
            or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
        raise ValueError('unsafe archive entry')
    parts = PurePosixPath(name).parts
    if len(parts) < 3 or parts[:2] not in (('BOOT-INF', 'classes'), ('BOOT-INF', 'lib')):
        return None
    if parts[1] == 'lib' and (len(parts) != 3 or not parts[2].endswith('.jar')):
        raise ValueError('unexpected library entry')
    if info.file_size > MAX_ENTRY:
        raise ValueError('archive entry too large')
    return Path(parts[1], *parts[2:])


def extract(jar: Path, destination: Path, job: Path, started: float) -> None:
    seen: set[Path] = set()
    total = 0
    last_guard = time.monotonic()
    with zipfile.ZipFile(jar) as archive:
        for info in archive.infolist():
            target = archive_target(info)
            if target is None or info.is_dir():
                continue
            if target in seen:
                raise ValueError('duplicate archive entry')
            seen.add(target)
            total += info.file_size
            if total > MAX_EXTRACTED or total > ARTIFACT_LIMIT:
                raise RuntimeError('STOP_RESOURCE: extracted classpath too large')
            path = destination / target
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            copied = 0
            with archive.open(info) as source, path.open('xb') as out:
                os.chmod(path, 0o600)
                while chunk := source.read(BLOCK):
                    copied += len(chunk)
                    if copied > info.file_size:
                        raise ValueError('archive entry expanded beyond declared size')
                    out.write(chunk)
                    if time.monotonic() - last_guard >= 2:
                        guard(job, started)
                        last_guard = time.monotonic()
            if copied != info.file_size:
                raise ValueError('archive entry size differs')
    if not (destination / 'classes').is_dir() or not list((destination / 'lib').glob('*.jar')):
        raise ValueError('application jar lacks classes or libraries')
    guard(job, started)


def classpath_entries(folder: Path) -> list[Path]:
    return [folder / 'harness', folder / 'classes', *sorted((folder / 'lib').glob('*.jar')),
            folder / 'app.jar']


def prepare(job: Path) -> dict:
    if '..' in job.parts:
        raise ValueError('parent traversal is forbidden')
    job = safe_path(job, RESEARCH_ROOT)
    if not job.is_dir() or job.stat().st_uid != os.getuid() or job.stat().st_mode & 0o077:
        raise ValueError('owner-only research job directory required')
    folder = job / 'classpath'
    receipt = job / 'classpath-receipt.json'
    log_path = job / 'classpath-prepare.log'
    if any(path.exists() or path.is_symlink() for path in (folder, receipt, log_path)):
        raise ValueError('classpath or preparation marker already exists')
    resource_check(job, admission=True)
    started = time.monotonic()
    folder.mkdir(mode=0o700)
    name = 'auth-classpath-' + uuid.uuid4().hex
    compiler = 'auth-compiler-' + uuid.uuid4().hex
    created = False
    attempted = False
    jar = folder / 'app.jar'
    source = folder / 'AuthShadowLabCaptureServer.java'
    check = lambda: guard(job, started)
    with log_path.open('x', encoding='utf-8') as log:
        os.chmod(log_path, 0o600)
        try:
            attempted = True
            command(['docker', 'create', '--name', name, '--label', 'auth.research.owner=' + name, '--network', 'none',
                     '--entrypoint', '/bin/true', APP_IMAGE], job, started, log)
            created = True
            command(['docker', 'cp', name + ':/app/app.jar', str(jar)], job, started, log)
            if jar.is_symlink() or not jar.is_file() or not 0 < jar.stat().st_size <= MAX_ENTRY:
                raise ValueError('invalid application jar')
            os.chmod(jar, 0o600)
            jar_hash = sha(jar, check)
            extract(jar, folder, job, started)
            # Git supplies exactly the committed harness source, not checkout edits.
            with source.open('xb') as out:
                os.chmod(source, 0o600)
                command(['git', 'show', COMMIT + ':' + HARNESS], job, started, out)
            if not 0 < source.stat().st_size <= 1024 * 1024:
                raise ValueError('invalid committed harness source')
            (folder / 'harness').mkdir(mode=0o700)
            args = ['docker', 'run', '--rm', '--name', compiler, '--network', 'none',
                    '--memory', '2g', '--cpus', '2', '--pids-limit', '256',
                    '--user', f'{os.getuid()}:{os.getgid()}', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--tmpfs', '/tmp:rw,nosuid,size=64m', '--workdir', '/work']
            args += bind(folder, '/work', writable=True)
            args += ['--entrypoint', '/bin/sh', JDK_IMAGE, '-c',
                     'javac -version && exec javac -proc:none -cp "classes:lib/*" -d harness AuthShadowLabCaptureServer.java']
            command(args, job, started, log, container=compiler)
            log.flush()
            if not re.search(r'\bjavac 21(?:[.\s]|$)', log_path.read_text(encoding='utf-8')):
                raise ValueError('expected Java 21 compiler')
            klass = folder / 'harness/com/flarefitness/backend/ops/AuthShadowLabCaptureServer.class'
            if not klass.is_file() or klass.is_symlink():
                raise ValueError('compiled harness missing')
            guard(job, started)
            if sha(jar, check) != jar_hash:
                raise ValueError('application jar changed during preparation')
            command(['docker', 'rm', name], job, started, log)
            created = False
            attempted = False
            libraries = sorted((folder / 'lib').glob('*.jar'))
            # Parity binds the original application jar SHA as well as its
            # extracted classes and libraries. Include it in the classpath
            # fingerprint even though Java loads its nested classes separately.
            entries = classpath_entries(folder)
            classes = []
            last_guard = time.monotonic()
            for path in sorted((folder / 'classes').rglob('*')):
                if path.is_file():
                    classes.append((str(path.relative_to(folder / 'classes')), sha(path, check)))
                if time.monotonic() - last_guard >= 2:
                    check()
                    last_guard = time.monotonic()
            classes_sha = hashlib.sha256(json.dumps(classes, separators=(',', ':')).encode()).hexdigest()
            result = {'status': 'CLASSPATH_PREPARED', 'commit': COMMIT, 'app_image': APP_IMAGE,
                      'jdk_image': JDK_IMAGE, 'jdk_major': 21, 'application_jar_sha256': jar_hash,
                      'harness_source_sha256': sha(source), 'harness_class_sha256': sha(klass),
                      'application_classes_sha256': classes_sha, 'application_class_files': len(classes),
                      'classpath': os.pathsep.join(map(str, entries)),
                      'libraries': [{'name': p.name, 'sha256': sha(p, check)} for p in libraries],
                      'preparer_sha256': sha(Path(__file__))}
            with receipt.open('x', encoding='utf-8') as out:
                os.chmod(receipt, 0o600)
                json.dump(result, out, sort_keys=True, allow_nan=False)
                out.flush()
                os.fsync(out.fileno())
            return result
        finally:
            # A timed-out docker create may have succeeded after its client died.
            # Inspect the private label before touching an uncertain container.
            if attempted and not created:
                probe = subprocess.run(['docker', 'inspect', '--format', '{{ index .Config.Labels "auth.research.owner" }}', name],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                       check=False, timeout=20)
                created = probe.returncode == 0 and probe.stdout.strip() == name
            if created:
                subprocess.run(['docker', 'rm', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--init-job', action='store_true', help='create one empty private job; do not build classpath')
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.init_job:
            init_job(args.job)
            print(json.dumps({'status': 'JOB_CREATED', 'job': str(args.job)}))
        else:
            print(json.dumps(prepare(args.job)))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print('STOP_INTERRUPTED', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
