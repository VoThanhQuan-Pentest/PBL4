"""Opt-in, two-hash-bound archive view of the unchanged ShardedDataset contract.

The ordinary manifest stays byte-identical. Only a missing approved JSON shard
can be restored from its fixed .json.xz sibling, authenticated by the separate
SHA-pinned private sidecar. Existing row/cohort/feature/count checks are inherited.
This class performs no registration, fitting, scoring, or automatic retirement.
"""
import lzma
import os
from pathlib import Path
import re
import stat

from app.catalog import MAX_MANIFEST_BYTES, MAX_SHARD_BYTES, ShardedDataset, parse_json, sha256

SIDECAR = "archives.private.json"
FORMAT = "OWNED_CATALOG_XZ_V1"
MAX_XZ_BYTES = MAX_SHARD_BYTES + 65536
XZ_MEMORY_LIMIT = 64 * 1024 * 1024
_SHA = re.compile(r"[a-f0-9]{64}")
_SHARD = re.compile(r"shards/[a-z0-9_-]{8,96}\.json")
_DOCUMENT_FIELDS = {"archive_schema_version", "archive_format", "dataset_manifest_sha256", "shards"}
_ENTRY_FIELDS = {"original_sha256", "original_bytes", "archive_path", "archive_sha256", "archive_bytes"}


def owned_root(root):
    """Canonical operator-owned 0700 root; ancestor symlinks are never followed."""
    root = Path(root).absolute()
    if ".." in root.parts or any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError("canonical private archive root required")
    try:
        info = root.stat(follow_symlinks=False)
    except OSError:
        raise ValueError("private archive root required") from None
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise ValueError("private owner-controlled archive root required")
    return root


def resource_path(root, relative):
    root = owned_root(root)
    if (type(relative) is not str or ".." in Path(relative).parts or Path(relative).is_absolute()
            or relative not in ("manifest.json", SIDECAR)
            and _SHARD.fullmatch(relative.removesuffix(".xz")) is None):
        raise ValueError("fixed catalogue resource path required")
    path = root / relative
    for parent in (path.parent, *path.parent.parents):
        if parent == root:
            break
        if not parent.is_relative_to(root):
            raise ValueError("archive resource escapes operator root")
        try:
            info = parent.stat(follow_symlinks=False)
        except OSError:
            raise ValueError("private archive resource directory required") from None
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.geteuid()):
            raise ValueError("private owner-controlled archive directory required")
    if path.is_symlink():
        raise ValueError("archive resource symlink refused")
    return path


def _private_stream(root, relative, maximum):
    path = resource_path(root, relative)
    if type(maximum) is not int or not 0 < maximum <= MAX_XZ_BYTES:
        raise ValueError("bounded archive resource read required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ValueError("private archive resource missing or inaccessible") from None
    source = os.fdopen(descriptor, "rb")
    info = os.fstat(source.fileno())
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid() or not 0 < info.st_size <= maximum):
        source.close()
        raise ValueError("bounded private owner-controlled archive file required")
    return source


def private_bytes(root, relative, maximum):
    """Read one fixed private resource with no-follow/fstat and a byte cap."""
    with _private_stream(root, relative, maximum) as source:
        data = source.read(maximum + 1)
    if not 0 < len(data) <= maximum:
        raise ValueError("archive resource exceeds byte bound")
    return data


def restore_xz(root, entry, maximum=MAX_SHARD_BYTES):
    """Bounded single-stream XZ decode; both compressed and original bytes bind."""
    if type(maximum) is not int or not 0 < maximum <= MAX_SHARD_BYTES or entry["original_bytes"] > maximum:
        raise ValueError("bounded original shard size required")
    encoded = private_bytes(root, entry["archive_path"], MAX_XZ_BYTES)
    if len(encoded) != entry["archive_bytes"] or sha256(encoded) != entry["archive_sha256"]:
        raise ValueError("archive byte checksum/size mismatch")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY_LIMIT)
    raw = bytearray()
    limit = min(maximum, entry["original_bytes"])
    try:
        for offset in range(0, len(encoded), 65536):
            if decoder.eof:
                raise ValueError("concatenated or trailing archive data refused")
            pending = encoded[offset:offset + 65536]
            while True:
                raw.extend(decoder.decompress(pending, max_length=limit + 1 - len(raw)))
                if len(raw) > limit:
                    raise ValueError("archive decompression exceeds original byte bound")
                if decoder.eof or decoder.needs_input:
                    break
                pending = b""
        if not decoder.eof or decoder.unused_data:
            raise ValueError("truncated concatenated or trailing archive data refused")
    except lzma.LZMAError:
        raise ValueError("bounded single-stream XZ archive required") from None
    if len(raw) != entry["original_bytes"] or sha256(raw) != entry["original_sha256"]:
        raise ValueError("restored original shard checksum/size mismatch")
    return bytes(raw)


class ArchivedShardedDataset(ShardedDataset):
    """Explicit private archive reader; never selected by a public path/ID.

    expected_sha256 pins the unchanged ordinary manifest. The separately trusted
    expected_archive_sha256 pins archive locations, sizes, and compressed hashes.
    Constructing a view reads only metadata, not any shard or holdout rows.
    """

    def __init__(self, root: Path, *, expected_sha256: str, expected_archive_sha256: str):
        if (type(expected_sha256) is not str or _SHA.fullmatch(expected_sha256) is None
                or type(expected_archive_sha256) is not str or _SHA.fullmatch(expected_archive_sha256) is None):
            raise ValueError("two explicit trusted catalogue/archive hashes required")
        root = owned_root(root)
        self._archive_entries = None
        super().__init__(root, expected_sha256=expected_sha256)
        raw = private_bytes(self.root, SIDECAR, MAX_MANIFEST_BYTES)
        if sha256(raw) != expected_archive_sha256:
            raise ValueError("archive sidecar binding mismatch")
        document = parse_json(raw)
        if (type(document) is not dict or set(document) != _DOCUMENT_FIELDS
                or type(document["archive_schema_version"]) is not int or document["archive_schema_version"] != 1
                or document["archive_format"] != FORMAT or document["dataset_manifest_sha256"] != self.sha256
                or type(document["shards"]) is not dict):
            raise ValueError("supported exact archive sidecar schema required")
        originals = {item["path"]: item["sha256"] for split in self.manifest["splits"].values() for item in split["shards"]}
        if set(document["shards"]) != set(originals):
            raise ValueError("archive sidecar must cover the unchanged manifest shard paths")
        for relative, entry in document["shards"].items():
            if (type(entry) is not dict or set(entry) != _ENTRY_FIELDS
                    or entry["original_sha256"] != originals[relative]
                    or type(entry["original_bytes"]) is not int or not 0 < entry["original_bytes"] <= MAX_SHARD_BYTES
                    or type(entry["archive_bytes"]) is not int or not 0 < entry["archive_bytes"] <= MAX_XZ_BYTES
                    or entry["archive_path"] != relative + ".xz"
                    or type(entry["archive_sha256"]) is not str or _SHA.fullmatch(entry["archive_sha256"]) is None):
                raise ValueError("exact bounded manifest-bound archive entry required")
            resource_path(self.root, entry["archive_path"])
        self._archive_entries = document["shards"]
        self.archive_sha256 = expected_archive_sha256

    def _read(self, relative, maximum):
        if type(relative) is not str or relative != "manifest.json" and (_SHARD.fullmatch(relative) is None
                or self._archive_entries is None or relative not in self._archive_entries):
            raise ValueError("approved original manifest resource required")
        path = resource_path(self.root, relative)
        if path.exists():
            # Add only private ownership checks; preserve the ordinary reader.
            with _private_stream(self.root, relative, maximum):
                pass
            return super()._read(relative, maximum)
        if relative == "manifest.json":
            raise ValueError("ordinary unmodified manifest must remain present")
        return restore_xz(self.root, self._archive_entries[relative], maximum)
