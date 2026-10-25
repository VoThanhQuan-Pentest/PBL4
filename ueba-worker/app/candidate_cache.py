"""Bounded HTTP candidate cache, never a model integrity/admission bypass.

Each request hashes the actual binary, metadata and code dependencies. Expensive
numeric restoration/validation is reused only while all bytes are identical.
One lock prevents simultaneous requests from restoring the same large model.
No fitting, calibration, selection or activation is performed here.
"""
from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import stat
from threading import RLock

from app.contract import feature_array, validate_version
from app.model import ModelStore
from app.policy import ScorePolicy

MAX_CANDIDATES = 2
CODE_FILES = ("candidate_cache.py", "model.py", "semantic_model.py", "model_state_dispatch.py",
              "contract.py", "policy.py", "normal_support.py", "hybrid_incident.py", "hybrid_semantic.py")


def checked_hash(path, maximum):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("candidate artifact unavailable") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise ValueError("bounded regular candidate artifact required")
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
        after = os.fstat(stream.fileno())
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if signature(before) != signature(after) or signature(before) != signature(Path(path).lstat()):
            raise ValueError("candidate artifact changed during verification")
        return value.hexdigest()


class CandidateCache:
    def __init__(self):
        self._lock = RLock()
        self._entries = OrderedDict()

    def _binding(self, store, version):
        root = store.directory.absolute()
        if root.resolve(strict=True) != root:
            raise ValueError("canonical candidate directory required")
        directory = Path(__file__).resolve().parent
        return (checked_hash(root / (version + ".joblib"), 512 * 1024 * 1024),
                checked_hash(root / (version + ".json"), 8 * 1024 * 1024),
                tuple(checked_hash(directory / name, 4 * 1024 * 1024) for name in CODE_FILES))

    def score(self, store, version, rows, schema=1, cohorts=None):
        validate_version(version)
        features = feature_array(rows, 256, schema)
        key = (str(store.directory.absolute()), version)
        with self._lock:
            try:
                binding = self._binding(store, version)
                entry = self._entries.get(key)
                if entry is None or entry[0] != binding:
                    # The existing loader still verifies every original model,
                    # recipe, semantic, calibration and implementation gate.
                    metadata, payload = store.load_candidate(version)
                    if self._binding(store, version) != binding:
                        raise ValueError("candidate artifact changed during loading")
                    entry = (binding, metadata, payload)
                    self._entries[key] = entry
                self._entries.move_to_end(key)
                while len(self._entries) > MAX_CANDIDATES:
                    self._entries.popitem(last=False)
            except (ValueError, OSError):
                self._entries.pop(key, None)
                raise
            _, metadata, payload = entry
        if metadata["feature_schema_version"] != schema:
            raise ValueError("candidate feature schema mismatch")
        policy = ScorePolicy.from_wire(metadata["score_policy"]) if "score_policy" in metadata else ScorePolicy.legacy(schema)
        return ModelStore.score_payload(payload, features, version, schema, policy=policy, cohorts=cohorts)


# Python initializes a module once under its import lock. Returning this object
# avoids lru_cache's documented duplicate initial computation under contention.
HTTP_CANDIDATE_CACHE = CandidateCache()
