#!/usr/bin/env python3
"""Copy only explicitly SHA-pinned JVM classes/JARs into a new private workspace.

No compilation, source-data reads, original chmod, overwrite, or model action.
The original snapshot bytes stay identical; an absolute copied-JAR classpath is
a separately hashed technical artifact, never a rewrite of the source snapshot.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ueba-worker'))
from app.catalog import parse_json
from app.package_catalog import copy_checked
from app.policy import canonical

SHA = re.compile(r'[a-f0-9]{64}')
CLASS = re.compile(r'(?:[A-Za-z0-9_$]+/)*[A-Za-z0-9_$]+\.class')
JAR = re.compile(r'[0-9]{4}-[A-Za-z0-9_.-]+\.jar')


def private_directory(path):
    path = Path(path).absolute()
    if '..' in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('canonical private Java workspace directory required')
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('owner-only Java workspace directory required')
    return path


def digest(path, maximum):
    path = Path(path).absolute()
    if '..' in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('canonical declared JVM file required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or not 0 < before.st_size <= maximum:
            raise ValueError('bounded owner-controlled declared JVM file required')
        checksum = hashlib.sha256(); size = 0
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(block)
            if size > maximum: raise ValueError('JVM file changed beyond byte cap')
            checksum.update(block)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if size != before.st_size or signature(before) != signature(os.fstat(stream.fileno())) or signature(before) != signature(path.lstat()):
            raise ValueError('declared JVM file changed during read')
    return checksum.hexdigest(), size, stat.S_IMODE(before.st_mode)


def private_parents(root, path):
    current = root
    for part in path.relative_to(root).parent.parts:
        current /= part
        if not current.exists(): current.mkdir(mode=0o700)
        private_directory(current)


def write_private(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(body)
    path.chmod(0o600)


def freeze_workspace(source, parent, expected_snapshot_sha256, *, prefix='hybrid-execution-java-'):
    source, parent = private_directory(source), private_directory(parent)
    if type(expected_snapshot_sha256) is not str or SHA.fullmatch(expected_snapshot_sha256) is None:
        raise ValueError('explicit trusted Java snapshot SHA required')
    if type(prefix) is not str or re.fullmatch(r'[a-z0-9_-]{8,96}', prefix) is None:
        raise ValueError('bounded private execution workspace prefix required')
    snapshot_path = source / 'snapshot.json'
    snapshot_sha, _, _ = digest(snapshot_path, 1024 * 1024)
    if snapshot_sha != expected_snapshot_sha256: raise ValueError('Java source snapshot checksum mismatch')
    with snapshot_path.open('rb') as stream: raw = stream.read(1024 * 1024 + 1)
    if not 0 < len(raw) <= 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_snapshot_sha256:
        raise ValueError('Java source snapshot changed during bounded read')
    snapshot = parse_json(raw)
    if (type(snapshot) is not dict or set(snapshot) != {'classes', 'jars'}
            or type(snapshot['classes']) is not dict or not 1 <= len(snapshot['classes']) <= 2000
            or type(snapshot['jars']) is not dict or not 1 <= len(snapshot['jars']) <= 512):
        raise ValueError('bounded exact JVM snapshot inventory required')
    resources = [('snapshot.json', expected_snapshot_sha256, 1024 * 1024)]
    for name, checksum in snapshot['classes'].items():
        if type(name) is not str or CLASS.fullmatch(name) is None or type(checksum) is not str or SHA.fullmatch(checksum) is None:
            raise ValueError('exact pinned JVM class path/hash required')
        resources.append(('backend/target/classes/com/flarefitness/backend/' + name, checksum, 8 * 1024 * 1024))
    for name, checksum in sorted(snapshot['jars'].items()):
        if type(name) is not str or JAR.fullmatch(name) is None or type(checksum) is not str or SHA.fullmatch(checksum) is None:
            raise ValueError('exact pinned JVM JAR path/hash required')
        resources.append(('jars/' + name, checksum, 512 * 1024 * 1024))
    originals = {}
    for name, checksum, cap in resources:
        actual, size, mode = digest(source / name, cap)
        if actual != checksum: raise ValueError('declared source JVM bytes changed before copy')
        originals[name] = {'sha256': actual, 'bytes': size, 'source_mode': oct(mode)}
    destination = Path(tempfile.mkdtemp(prefix=prefix, dir=parent)); destination.chmod(0o700)
    for name, checksum, cap in resources:
        target = destination / name; private_parents(destination, target)
        # The source root is private and every source byte hash was pinned above.
        # Plain copy accepts historical0664 source modes without changing them.
        copy_checked(source / name, target, checksum, cap); target.chmod(0o600)
        actual, size, mode = digest(target, cap)
        if actual != checksum or size != originals[name]['bytes'] or mode != 0o600:
            raise ValueError('copied JVM bytes or private ownership changed')
    for name, checksum, cap in resources:
        actual, size, mode = digest(source / name, cap)
        if actual != checksum or size != originals[name]['bytes'] or oct(mode) != originals[name]['source_mode']:
            raise ValueError('original JVM bytes/modes changed during copy')
    classpath = destination / 'backend/target/ueba-experiment.classpath'
    body = ':'.join(str(destination / 'jars' / name) for name in sorted(snapshot['jars'])).encode()
    if not 0 < len(body) <= 65536: raise ValueError('bounded absolute copied-JAR classpath required')
    write_private(classpath, body)
    receipt = {'format': 'PRIVATE_JAVA_EXECUTION_COPY_V1', 'source_workspace': str(source), 'workspace': str(destination),
               'snapshot_sha256': expected_snapshot_sha256, 'class_count': len(snapshot['classes']), 'jar_count': len(snapshot['jars']),
               'declared_file_count': len(resources), 'declared_bytes': sum(item['bytes'] for item in originals.values()),
               'files': originals, 'derived_classpath_sha256': hashlib.sha256(body).hexdigest(),
               'derived_classpath_bytes': len(body), 'source_bytes_and_modes_unchanged': True,
               'numeric_resources_read': 0, 'compiled': False, 'models_changed': False}
    write_private(destination / 'copy.receipt.private.json', canonical(receipt).encode())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True); parser.add_argument('--destination-parent', type=Path, required=True)
    parser.add_argument('--expected-snapshot-sha256', required=True); parser.add_argument('--prefix', default='hybrid-execution-java-')
    args = parser.parse_args()
    receipt = freeze_workspace(args.source, args.destination_parent, args.expected_snapshot_sha256, prefix=args.prefix)
    print(canonical({key: receipt[key] for key in ('workspace', 'snapshot_sha256', 'class_count', 'jar_count', 'declared_file_count',
                                                'declared_bytes', 'derived_classpath_sha256', 'derived_classpath_bytes',
                                                'source_bytes_and_modes_unchanged', 'numeric_resources_read')}))


if __name__ == '__main__': main()
