"""Small durable, private publications for bounded offline research receipts."""
import hashlib
import json
import os
from pathlib import Path
import tempfile


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def private_directory(path, *, create=False):
    path = Path(path).absolute()
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise ValueError("symlink ancestor refused")
    if create:
        path.mkdir(mode=0o700)
    stat = path.stat()
    if not path.is_dir() or stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise ValueError("owner-private research directory required")
    return path


def publish(path, value, *, maximum=8 * 1024):
    """Publish one self-contained document; never implies a multi-file commit."""
    path = Path(path)
    parent = private_directory(path.parent)
    if path.is_symlink() or path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("unsafe receipt destination")
    payload = (canonical(value) + "\n").encode()
    if len(payload) > maximum:
        raise ValueError("receipt byte cap exceeded")
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def commit(directory, document, *, phase):
    """Receipt bytes precede the commit marker; readers verify the pinned hash."""
    directory = private_directory(directory)
    receipt = directory / (phase + ".receipt.private.json")
    marker = directory / (phase + ".commit.private.json")
    if marker.exists():
        previous = json.loads(marker.read_text())
        if previous.get("receipt_sha256") != digest(receipt):
            raise ValueError("committed research receipt changed")
        if json.loads(receipt.read_text()) != document:
            raise ValueError("refusing to replace a committed research unit")
        return previous
    publish(receipt, document, maximum=256 * 1024)
    proof = {"phase": phase, "receipt": receipt.name, "receipt_sha256": digest(receipt)}
    publish(marker, proof)
    return proof
