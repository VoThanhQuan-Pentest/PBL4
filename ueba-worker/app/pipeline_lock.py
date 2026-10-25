"""Opt-in offline consumer locks; not authority to restore or retire caches.

The source coordinator owns the dataset directory's parent. The fixed lock
names match staged-cache approval; default consumers do not touch these files.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from app.catalog import parse_json

CAMPAIGN_LOCKS = frozenset({"campaign.lock", "selection.lock", "evaluation.lock"})
MAX_SOURCE_METADATA_BYTES = 2 * 1024 * 1024


def _directory(path):
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private pipeline directory required")
    value = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise ValueError("owner-only pipeline directory required")


def _metadata(root, name):
    descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_SOURCE_METADATA_BYTES):
            raise ValueError("bounded owner-only source metadata required")
        body = source.read(MAX_SOURCE_METADATA_BYTES + 1)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(body) != before.st_size or signature(before) != signature(os.fstat(source.fileno()))
                or signature(before) != signature((root / name).lstat())):
            raise ValueError("pipeline source metadata changed during read")
    return parse_json(body)


def _completed_source(root):
    marker = _metadata(root, "predeclared.private.json")
    terminal = _metadata(root, "state.private.json")
    if (type(marker) is not dict or type(terminal) is not dict
            or marker.get("scope") != "FULL_STRICT_SOURCE" or type(marker.get("protocol")) is not dict
            or terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE" or terminal.get("stage") != "STRICT_SOURCE"
            or terminal.get("scope") != "FULL_STRICT_SOURCE" or terminal.get("folds_completed") != [1, 2, 3]
            or any(type(fold) is not int for fold in terminal["folds_completed"])
            or type(terminal.get("fit_or_score_calls")) is not int or terminal["fit_or_score_calls"] != 0
            or type(terminal.get("source_identity_before")) is not dict or not terminal["source_identity_before"]
            or terminal["source_identity_before"] != terminal.get("source_identity_after")
            or marker.get("source_identity") != terminal["source_identity_before"]):
        raise ValueError("completed independent FULL_STRICT_SOURCE required for coordination")


@contextmanager
def coordinated_stage(directory, stage, *, enabled=False):
    """Hold one fixed exclusive stage lock through the complete consumer lifetime.

    Yields the held descriptor (None when disabled). Search shares that open
    description with its child instead of reacquiring. Retirement still needs
    all three names and separate approval; this helper does not admit it.
    """
    if type(enabled) is not bool or type(stage) is not str or stage + ".lock" not in CAMPAIGN_LOCKS:
        raise ValueError("explicit known pipeline stage and boolean opt-in required")
    if not enabled:
        yield None
        return
    descriptor = None
    try:
        try:
            directory = Path(directory).absolute(); root = directory.parent
            _directory(directory); _directory(root); _completed_source(root)
            path = root / (stage + ".lock")
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            value = os.fstat(descriptor)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
                    or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1
                    or value.st_size > MAX_SOURCE_METADATA_BYTES
                    or (value.st_dev, value.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)):
                raise ValueError("private single-link regular pipeline lock required")
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ValueError("pipeline stage is already active") from None
            _completed_source(root)
        except OSError:
            raise ValueError("private completed pipeline source or lock unavailable") from None
        yield descriptor
        if (value.st_dev, value.st_ino) != (path.lstat().st_dev, path.lstat().st_ino):
            raise ValueError("pipeline lock changed while consumer was active")
    finally:
        if descriptor is not None: os.close(descriptor)
