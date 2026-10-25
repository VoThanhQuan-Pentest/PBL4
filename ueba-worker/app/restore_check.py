"""Private owned-model backup smoke test; never a quality or cloud promotion."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
import zlib

from app.contract import validate_version
from app.model import ModelStore
from app.policy import canonical


_MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_EXPANDED_BYTES = 128 * 1024 * 1024
_MAX_HEADERS = 1024
_MAX_EXTENSION_BYTES = 64 * 1024
_MAX_TOTAL_EXTENSION_BYTES = 1024 * 1024
_MAX_EXTENSION_CHAIN = 16
_BLOCK_BYTES = 512
_COPY_BYTES = 65536
_EXTENSION_TYPES = {b"L", b"K", b"x", b"g", b"X"}


def _snapshot_owned_archive(archive, snapshot, expected_sha):
    # Pin one regular file and hash exactly the compressed bytes later decoded.
    # O_NONBLOCK also avoids blocking if a raced pathname becomes a FIFO.
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_COMPRESSED_BYTES:
            raise ValueError("bounded regular owned model archive required")
        digest = hashlib.sha256(); total = 0
        while block := source.read(min(_COPY_BYTES, _MAX_COMPRESSED_BYTES - total + 1)):
            total += len(block)
            if total > _MAX_COMPRESSED_BYTES:
                raise ValueError("bounded regular owned model archive required")
            digest.update(block); snapshot.write(block)
        if digest.hexdigest() != expected_sha:
            raise ValueError("owned model backup checksum mismatch")
    snapshot.seek(0)


def _decode_bounded_gzip(snapshot, expanded):
    # Read through gzip EOF, not merely tar EOF: concatenated gzip streams and
    # padding/hidden bytes after the tar end marker consume the same budget.
    total = 0
    try:
        with gzip.GzipFile(fileobj=snapshot, mode="rb") as source:
            while block := source.read(min(_COPY_BYTES, _MAX_EXPANDED_BYTES - total + 1)):
                total += len(block)
                if total > _MAX_EXPANDED_BYTES:
                    raise ValueError("expanded model backup exceeds private budget")
                expanded.write(block)
    except (OSError, EOFError, zlib.error) as failure:
        raise ValueError("invalid compressed model backup") from failure
    expanded.seek(0)
    return total


def _tar_number(field):
    # GNU base-256 positive numbers, or the usual NUL/space padded octal field.
    if field[0] == 0x80:
        return int.from_bytes(field[1:], "big")
    value, _, padding = field.partition(b"\0")
    value = value.strip(b" ")
    if any(byte not in b"01234567" for byte in value) or padding.strip(b"\0 "):
        raise ValueError("invalid model backup header number")
    return int(value or b"0", 8)


def _preflight_pax(body):
    position = 0
    while position < len(body):
        separator = body.find(b" ", position)
        length_field = body[position:separator] if separator != -1 else b""
        if not length_field.isdigit() or len(length_field) > 10:
            raise ValueError("invalid model backup PAX metadata")
        length = int(length_field); end = position + length
        if length < 5 or end > len(body) or separator >= end - 1 or body[end - 1:end] != b"\n":
            raise ValueError("invalid model backup PAX metadata")
        key, equals, value = body[separator + 1:end - 1].partition(b"=")
        if not key or not equals or b"\0" in key or b"\0" in value:
            raise ValueError("invalid model backup PAX metadata")
        if key == b"size" or key.startswith(b"GNU.sparse."):
            raise ValueError("model backup PAX layout overrides are not supported")
        position = end


def _preflight_tar(expanded, expanded_size):
    # tarfile resolves GNU/PAX extensions (and allocates their bodies) before
    # yielding TarInfo. Walk raw headers first, with no TarInfo parsing.
    if expanded_size % _BLOCK_BYTES:
        raise ValueError("incomplete model backup tar blocks")
    number = 0; extension_chain = 0; extension_bytes = 0
    while header := expanded.read(_BLOCK_BYTES):
        if header == bytes(_BLOCK_BYTES):
            if extension_chain or expanded.read(_BLOCK_BYTES) != bytes(_BLOCK_BYTES):
                raise ValueError("incomplete model backup tar end marker")
            while block := expanded.read(_COPY_BYTES):
                if any(block): raise ValueError("hidden data after model backup tar end marker")
            expanded.seek(0)
            return
        number += 1
        if number > _MAX_HEADERS:
            raise ValueError("too many model backup headers")
        checksum = _tar_number(header[148:156])
        checksum_bytes = header[:148] + b" " * 8 + header[156:]
        if checksum not in (sum(checksum_bytes), sum(byte if byte < 128 else byte - 256 for byte in checksum_bytes)):
            raise ValueError("invalid model backup header checksum")
        size = _tar_number(header[124:136]); kind = header[156:157]
        # tarfile treats old V7 NUL-type names ending in '/' as directories,
        # which do not consume a body. Match that rule before calculating offsets.
        if kind == b"\0" and header[:100].split(b"\0", 1)[0].endswith(b"/"):
            kind = b"5"
        if kind in _EXTENSION_TYPES:
            extension_chain += 1; extension_bytes += size
            if (size > _MAX_EXTENSION_BYTES or extension_bytes > _MAX_TOTAL_EXTENSION_BYTES
                    or extension_chain > _MAX_EXTENSION_CHAIN):
                raise ValueError("unbounded model backup extension metadata")
        elif kind not in (b"0", b"\0", b"7", b"5") or size > _MAX_MEMBER_BYTES or (kind == b"5" and size):
            raise ValueError("unsafe or unbounded model backup member")
        else:
            extension_chain = 0
        body_end = expanded.tell() + ((size + _BLOCK_BYTES - 1) // _BLOCK_BYTES) * _BLOCK_BYTES
        if body_end > expanded_size:
            raise ValueError("incomplete model backup member")
        if kind in (b"x", b"g", b"X"):
            _preflight_pax(expanded.read(size))
            # tarfile reads the whole padded block when parsing PAX records.
            # Nonzero padding could otherwise smuggle an unchecked size/sparse
            # override outside the declared extension body.
            if any(expanded.read(body_end - expanded.tell())):
                raise ValueError("invalid model backup PAX metadata padding")
        expanded.seek(body_end)
    raise ValueError("incomplete model backup tar end marker")


def unpack_owned_backup(archive, destination, expected_sha):
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("bounded regular owned model archive required")
    with tempfile.TemporaryFile() as snapshot, tempfile.TemporaryFile() as expanded:
        _snapshot_owned_archive(archive, snapshot, expected_sha)
        expanded_size = _decode_bounded_gzip(snapshot, expanded)
        _preflight_tar(expanded, expanded_size)
        _unpack_preflighted_tar(expanded, destination)


def _unpack_preflighted_tar(expanded, destination):
    total = 0; names = set()
    with tarfile.open(fileobj=expanded, mode="r:") as source:
        for number, member in enumerate(source):
            path = PurePosixPath(member.name)
            if (number >= _MAX_HEADERS or path.is_absolute() or ".." in path.parts or "\\" in member.name
                    or not (member.isfile() or member.isdir()) or member.size < 0 or member.size > _MAX_MEMBER_BYTES):
                raise ValueError("unsafe or unbounded model backup member")
            if not path.parts: continue
            name = str(path)
            if name in names: raise ValueError("duplicate model backup path")
            names.add(name); total += member.size
            if total > _MAX_EXPANDED_BYTES: raise ValueError("expanded model backup exceeds private budget")
            target = destination.joinpath(*path.parts)
            if member.isdir(): target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as stream, target.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        block = stream.read(min(_COPY_BYTES, remaining))
                        if not block: raise ValueError("incomplete model backup member")
                        output.write(block); remaining -= len(block)
                target.chmod(0o600)


def verify(archive, expected_sha, version):
    validate_version(version)
    with tempfile.TemporaryDirectory(prefix="owned-model-restore-") as directory:
        root = Path(directory); unpack_owned_backup(archive, root, expected_sha)
        selection = json.loads((root / "active.json").read_text())
        if selection.get("model_version") != version: raise ValueError("restored selection differs from actual source primary")
        store = ModelStore(root)
        if store.active_version != version or store.active_schema != 1:
            raise ValueError("legacy primary is not available in the current worker runtime")
        metadata, _ = store.load_candidate(version)
        normal = [4,0,0,0,1,0,1,1,0,0,0]
        score = store.score([normal, [40,0,0,0,1,0,2,1,0,0,0], normal], 1)
        if not score.get("available") or len(score["results"]) != 3 or score["results"][0] != score["results"][2]:
            raise ValueError("restored primary failed actual stable serving smoke")
        return {"passed": True, "scope": "LEGACY_BACKUP_AND_CURRENT_RUNTIME_COMPATIBILITY_ONLY", "quality_gate": "NOT_APPLICABLE",
                "archive_sha256": expected_sha, "model_version": version, "feature_schema_version": 1,
                "model_binary_sha256": metadata["sha256"], "actual_vectors_scored": 3, "model_fit_calls": 0,
                "cloud_primary_changed": False, "source_archive_changed": False, "private_disposable_restore_only": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True); parser.add_argument("--expected-primary", required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args(); os.umask(0o077)
    result = verify(args.archive, args.expected_sha256, args.expected_primary)
    with args.output.open("x") as stream: stream.write(canonical(result))
    print(canonical(result), flush=True)


if __name__ == "__main__":
    try: main()
    except Exception as failure:
        raise SystemExit("Private model backup verification failed: " + type(failure).__name__ + "; artifact contents omitted") from None
