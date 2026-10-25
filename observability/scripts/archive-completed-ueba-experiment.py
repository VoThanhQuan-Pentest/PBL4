#!/usr/bin/env python3
"""Archive one explicitly approved completed experiment, verify every restored byte.

No model/holdout interpretation, scoring, fitting or AWS calls. Optional removal
is allowed only after full archive and per-file filesystem restoration checks.
The CLI's only source is the exact approved completed experiment below.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'observability/runtime/ueba-experiments/ueba-strict-20261001-v2b1'
BACKUPS = ROOT / 'observability/runtime/private-backups'
BLOCK = 1024 * 1024


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(BLOCK):
            digest.update(block)
    return digest.hexdigest()


def signature(path):
    value = path.lstat()
    if path.is_symlink():
        raise ValueError('symlink refused')
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def inventory(source):
    files, directories = {}, {}
    if source.resolve(strict=True) != source.absolute() or not source.is_dir():
        raise ValueError('regular non-symlink source directory required')
    for base, names, filenames in os.walk(source, followlinks=False):
        directory = Path(base)
        relative = str(directory.relative_to(source))
        directories[relative] = signature(directory)[:2]
        for name in names:
            if (directory / name).is_symlink():
                raise ValueError('source directory symlink refused')
        for name in filenames:
            path = directory / name
            before = signature(path)
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('nonregular source member refused')
            checksum = sha(path)
            if signature(path) != before:
                raise ValueError('source changed during inventory')
            files[str(path.relative_to(source))] = {'size': before[2], 'sha256': checksum, 'signature': before}
    if not files:
        raise ValueError('empty source refused')
    return files, directories


def verify_restoration(source, archive, files, directories, scratch):
    process = subprocess.Popen(['zstd', '--decompress', '--stdout', '--quiet', str(archive)], stdout=subprocess.PIPE)
    seen_files, seen_directories, restored_bytes = set(), set(), 0
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as stream:
            for member in stream:
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != source.name:
                    raise ValueError('archive path mismatch')
                relative = str(Path(*path.parts[1:]))
                if member.isdir():
                    if relative not in directories or relative in seen_directories:
                        raise ValueError('archive directory mismatch')
                    seen_directories.add(relative)
                    continue
                if not member.isfile() or relative not in files or relative in seen_files:
                    raise ValueError('archive file type or population mismatch')
                expected = files[relative]
                if member.size != expected['size']:
                    raise ValueError('archive file size mismatch')
                if shutil.disk_usage(scratch).free < member.size + 1024 * 1024 * 1024:
                    raise ValueError('insufficient per-file restoration headroom')
                payload = Path(scratch) / 'restored-payload.bin'
                digest, count = hashlib.sha256(), 0
                with stream.extractfile(member) as incoming, payload.open('xb') as outgoing:
                    while block := incoming.read(BLOCK):
                        count += len(block)
                        if count > expected['size']:
                            raise ValueError('restored file exceeds bound')
                        digest.update(block)
                        outgoing.write(block)
                if count != expected['size'] or digest.hexdigest() != expected['sha256'] or sha(payload) != expected['sha256']:
                    raise ValueError('restored bytes mismatch')
                payload.unlink()  # Only the newly created, verified scratch file.
                seen_files.add(relative)
                restored_bytes += count
                if len(seen_files) % 1000 == 0:
                    print(f'Actually restored and checked {len(seen_files)}/{len(files)} files', flush=True)
        # Drain any final tar record padding so closing the pipe cannot turn a
        # successful decoder into a spurious SIGPIPE failure.
        while process.stdout.read(BLOCK):
            pass
        process.stdout.close()
        if process.wait(timeout=30) or seen_files != set(files) or seen_directories != set(directories):
            raise ValueError('archive restoration did not conserve all members')
        return restored_bytes
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)


def archive_completed(source, destination, *, retire=False):
    os.umask(0o077)
    destination.mkdir(mode=0o700)
    files, directories = inventory(source)
    terminal = json.loads((source / 'strict-selection.json').read_bytes())
    if (terminal.get('status') != 'NO_QUALIFIED_CONFIG' or terminal.get('actual_fits_completed') != 360
            or terminal.get('validation_runs_completed') != 360 or terminal.get('holdout_scored') is not False):
        raise ValueError('exact completed nonselected experiment required')
    archive = destination / (source.name + '.tar.zst')
    if archive.exists():
        raise ValueError('new archive required')
    print(f'Archiving {len(files)} regular files, {sum(value["size"] for value in files.values())} bytes', flush=True)
    subprocess.run(['tar', '--create', '--hard-dereference', '--use-compress-program=zstd -T2 -6', '--file', str(archive),
                    '--directory', str(source.parent), source.name], check=True)
    archive.chmod(0o600)
    checksum = sha(archive)
    subprocess.run(['zstd', '--test', '--quiet', str(archive)], check=True)
    with tempfile.TemporaryDirectory(prefix='archive-restore-check-', dir=destination) as scratch:
        restored_bytes = verify_restoration(source, archive, files, directories, scratch)
    for relative, expected in files.items():
        if signature(source / relative) != tuple(expected['signature']):
            raise ValueError('source changed after archive verification')
    current_files = {str(Path(base, name).relative_to(source)) for base, _, names in os.walk(source) for name in names}
    if current_files != set(files) or sha(archive) != checksum:
        raise ValueError('source population or archive changed before retirement')
    result = {'status': 'ARCHIVE_AND_PER_FILE_RESTORATION_VERIFIED', 'archive': str(archive), 'archive_sha256': checksum,
              'source': str(source), 'regular_files': len(files), 'directories': len(directories),
              'restored_bytes_checked': restored_bytes, 'compressed_bytes': archive.stat().st_size,
              'fit_or_score_calls': 0, 'holdout_interpreted_or_scored': False, 'aws_changed': False,
              'uncompressed_source_removed': False}
    receipt = destination / 'restoration-evidence.json'
    with receipt.open('x') as stream:
        json.dump(result, stream, indent=2)
    if retire:
        if source != SOURCE or source.resolve(strict=True) != SOURCE or signature(source)[:2] != directories['.']:
            raise ValueError('exact approved source target identity required')
        shutil.rmtree(source)  # Explicit user-approved exact target, after restoration checks.
        result['uncompressed_source_removed'] = True
        with (destination / 'retirement-evidence.json').open('x') as stream:
            json.dump(result, stream, indent=2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--retire-uncompressed', action='store_true')
    args = parser.parse_args()
    destination = args.destination.absolute()
    if destination.parent != BACKUPS or destination.exists() or BACKUPS.resolve(strict=True) != BACKUPS:
        raise ValueError('fresh direct private-backup child required')
    print(json.dumps(archive_completed(SOURCE, destination, retire=args.retire_uncompressed)), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        raise SystemExit('Experiment archive failed: ' + type(failure).__name__ + '; source retained unless verified retirement already occurred') from None
