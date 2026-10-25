"""Private, single-writer, durable pilot bundles; never used for strict adoption."""
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

from ueba_research_artifacts import canonical, digest, private_directory, publish

MAXIMUM_BUNDLE = 128 * 1024**2


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


@contextmanager
def writer(directory):
    directory = private_directory(directory)
    fd = os.open(directory / "pilot.writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def checked_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{7,95}", name):
        raise ValueError("bounded pilot unit identity required")
    return name


def read_bundle(directory, name, binding, *, allow_unmarked=False):
    directory = private_directory(directory); checked_name(name)
    marker = directory / (name + ".commit.private.json")
    bundle = directory / (name + ".bundle.zip")
    if not bundle.exists():
        if marker.exists(): raise ValueError("committed pilot bytes are missing")
        return None
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > MAXIMUM_BUNDLE:
        raise ValueError("invalid pilot bundle")
    checksum = digest(bundle)
    if marker.exists():
        proof = json.loads(marker.read_text())
        if proof != {"unit": name, "binding_sha256": hashlib.sha256(canonical(binding).encode()).hexdigest(), "bundle_sha256": checksum}:
            raise ValueError("pilot bundle or immutable binding changed")
    elif not allow_unmarked:
        raise ValueError("pilot bundle has no durable commit marker")
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names or len(names) > 16:
            raise ValueError("invalid bundle members")
        total = sum(member.file_size for member in archive.infolist())
        if total > MAXIMUM_BUNDLE or any(member.compress_type != zipfile.ZIP_STORED for member in archive.infolist()):
            raise ValueError("bounded uncompressed pilot members required")
        if any(not re.fullmatch(r"[a-z0-9_.-]{1,64}", member) for member in names):
            raise ValueError("unsafe bundle member path")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("unit") != name or manifest.get("binding") != binding or manifest.get("format") != "PRIVATE_PILOT_BUNDLE_V1":
            raise ValueError("pilot bundle provenance/binding mismatch")
        expected = manifest.get("members")
        if not isinstance(expected, dict) or set(expected) != set(names) - {"manifest.json"}:
            raise ValueError("pilot member inventory mismatch")
        contents = {key: archive.read(key) for key in expected}
        if any(hashlib.sha256(value).hexdigest() != expected[key] for key, value in contents.items()):
            raise ValueError("pilot member checksum mismatch")
    return contents


def publish_bundle(directory, name, binding, contents, *, fault=None):
    """Caller owns writer lock. File+metadata are one fsynced, hash-bound unit.

    An unmarked complete bundle is verified/adopted without recomputing a fit.
    Incomplete private temporary bytes remain evidence and are never loaded.
    """
    directory = private_directory(directory); checked_name(name)
    marker = directory / (name + ".commit.private.json")
    bundle = directory / (name + ".bundle.zip")
    existing = read_bundle(directory, name, binding, allow_unmarked=True)
    if existing is not None:
        if marker.exists(): return {"reused": True, "recovered": False, "bundle_sha256": digest(bundle)}
        recovered = True
    else:
        if not contents or len(contents) > 15 or "manifest.json" in contents or any(not isinstance(v, bytes) for v in contents.values()):
            raise ValueError("bounded byte members required")
        if any(not re.fullmatch(r"[a-z0-9_.-]{1,64}", key) for key in contents): raise ValueError("unsafe member name")
        if sum(len(v) for v in contents.values()) > MAXIMUM_BUNDLE - 65536: raise ValueError("pilot bundle byte cap exceeded")
        manifest = {"unit": name, "format": "PRIVATE_PILOT_BUNDLE_V1", "binding": binding,
                    "members": {key: hashlib.sha256(value).hexdigest() for key, value in contents.items()}}
        fd, temporary = tempfile.mkstemp(prefix=".pending-" + name + "-", dir=directory)
        # Deliberately retain pending bytes on interruption/error. Recovery only
        # trusts published, verified bundles; it never unpickles a pending file.
        with os.fdopen(fd, "wb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("manifest.json", canonical(manifest))
                for key, value in contents.items(): archive.writestr(key, value)
            stream.flush(); os.fsync(stream.fileno())
        if fault: fault("FILE_SYNCED")
        os.replace(temporary, bundle); sync_directory(directory)
        if fault: fault("BUNDLE_PUBLISHED")
        read_bundle(directory, name, binding, allow_unmarked=True)
        recovered = False
    proof = {"unit": name, "binding_sha256": hashlib.sha256(canonical(binding).encode()).hexdigest(), "bundle_sha256": digest(bundle)}
    publish(marker, proof)
    if fault: fault("MARKER_COMMITTED")
    return {"reused": False, "recovered": recovered, "bundle_sha256": proof["bundle_sha256"]}
