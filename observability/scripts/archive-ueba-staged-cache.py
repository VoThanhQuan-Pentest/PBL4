#!/usr/bin/env python3
"""Exact-byte archives for explicitly approved NEW completed STRICT caches.

CLI supports archival and explicit restoration of approved missing caches.
Material retirement additionally requires a separately pinned quiescent
coordinator checkpoint and the immutable source/archive/code/image bindings.
Internal fixture retirement alone never grants CLI admission.
No discovery, glob, recursive deletion, source-shard/model/manifest deletion,
live-writer bypass, or AWS operation exists.
"""
import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ueba-worker"))
from app.storage_budget import require_headroom
RUNTIME = ROOT / "observability/runtime"
MAX_METADATA = 1024 * 1024
MAX_CACHE = 8 * 1024 ** 3
MAX_ARCHIVE = MAX_CACHE + MAX_CACHE // 100 + 65536
MEMORY_LIMIT = 64 * 1024 ** 2
BLOCK = 65536
SHA = re.compile(r"[a-f0-9]{64}")
ROOT_NAME = re.compile(r"(?:hybrid|ueba-hybrid)-strict-[A-Za-z0-9_-]{8,128}")
LEAF = re.compile(r"(scores|vectors|integrity|rules)-[a-f0-9]{24}")
KINDS = {"scores": {"raw.f64", "scores.sqlite"}, "vectors": {"features.f64", "vectors.sqlite"},
         "integrity": {"episodes.sqlite"}, "rules": {"rules.sqlite", "rules.u8"}}
APPROVAL_FIELDS = {"approval_schema_version", "scope", "campaign_root", "source_marker_sha256",
    "source_terminal_sha256", "cache_roots", "campaign_locks", "targets", "retirement_approved", "user_approval_reference"}
TARGET_FIELDS = {"path", "sha256", "bytes"}
RECOVERY_FIELDS = {"original_sha256", "original_bytes", "original_signature", "archive_sha256", "archive_bytes"}
CAMPAIGN_LOCKS = {"campaign.lock", "selection.lock", "evaluation.lock"}


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def parse(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result: raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def digest(path, maximum=MAX_CACHE):
    result = hashlib.sha256()
    with checked_file(path, maximum) as source:
        for block in iter(lambda: source.read(BLOCK), b""): result.update(block)
    return result.hexdigest()


def directory(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private directory required")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise ValueError("private owner-controlled directory required")
    return path


def checked_file(path, maximum=MAX_CACHE, *, empty=False):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("file symlink refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or not (0 if empty else 1) <= info.st_size <= maximum):
        os.close(descriptor); raise ValueError("bounded private single-link regular file required")
    return os.fdopen(descriptor, "rb")


def signature(path):
    with checked_file(path) as source:
        value = os.fstat(source.fileno())
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def json_file(path, expected_sha):
    if type(expected_sha) is not str or SHA.fullmatch(expected_sha) is None:
        raise ValueError("explicit trusted metadata SHA required")
    with checked_file(path, MAX_METADATA) as source: raw = source.read(MAX_METADATA + 1)
    if len(raw) > MAX_METADATA or hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("metadata byte binding mismatch")
    return parse(raw)


def write_new(path, value):
    raw = canonical(value).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw); target.flush(); os.fsync(target.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)


def relative(value):
    if (type(value) is not str or Path(value).is_absolute() or ".." in Path(value).parts
            or not value or any(re.fullmatch(r"[a-z0-9_-]{1,96}", part) is None for part in value.split("/"))):
        raise ValueError("fixed relative cache directory required")
    if any(part in {"models", "shards", "normal", "supplement", "receipts", "pending", "abandoned", "secrets"} for part in value.split("/")):
        raise ValueError("source/model/receipt directory is not a cache root")
    return value


def approved_targets(approval):
    if (type(approval) is not dict or set(approval) != APPROVAL_FIELDS
            or type(approval["approval_schema_version"]) is not int or approval["approval_schema_version"] != 1
            or approval["scope"] != "NEW_STRICT_CAMPAIGN_CACHE_ONLY"
            or type(approval["retirement_approved"]) is not bool
            or type(approval["user_approval_reference"]) is not str or not 1 <= len(approval["user_approval_reference"]) <= 2000
            or type(approval["cache_roots"]) is not list or not 1 <= len(approval["cache_roots"]) <= 1000
            or type(approval["campaign_locks"]) is not list or len(approval["campaign_locks"]) != 3
            or any(type(value) is not str for value in approval["campaign_locks"])
            or set(approval["campaign_locks"]) != CAMPAIGN_LOCKS
            or type(approval["targets"]) is not list or not 1 <= len(approval["targets"]) <= 10000):
        raise ValueError("exact operator approval schema required")
    prefixes = {relative(value) for value in approval["cache_roots"]}
    if len(prefixes) != len(approval["cache_roots"]): raise ValueError("duplicate cache root")
    result = []
    for target in approval["targets"]:
        if type(target) is not dict or set(target) != TARGET_FIELDS or type(target["path"]) is not str:
            raise ValueError("exact approved target fields required")
        path = Path(target["path"])
        if path.is_absolute() or ".." in path.parts or len(path.parts) < 3:
            raise ValueError("fixed approved cache path required")
        prefix = str(Path(*path.parts[:-2])); match = LEAF.fullmatch(path.parts[-2])
        if (prefix not in prefixes or match is None or path.name not in KINDS[match.group(1)]
                or str(path) != target["path"] or type(target["sha256"]) is not str or SHA.fullmatch(target["sha256"]) is None
                or type(target["bytes"]) is not int or not 1 <= target["bytes"] <= MAX_CACHE):
            raise ValueError("unknown or unbounded cache target")
        result.append(target)
    if len({target["path"] for target in result}) != len(result): raise ValueError("duplicate target")
    return result


def source_binding(approval):
    root = directory(approval["campaign_root"])
    direct = root.parent == RUNTIME.absolute() and ROOT_NAME.fullmatch(root.name) is not None
    source_child = (root.name == "source" and root.parent.parent == RUNTIME.absolute()
                    and ROOT_NAME.fullmatch(root.parent.name) is not None)
    if not (direct or source_child):
        raise ValueError("only an approved NEW direct STRICT campaign root is allowed")
    marker = json_file(root / "predeclared.private.json", approval["source_marker_sha256"])
    terminal = json_file(root / "state.private.json", approval["source_terminal_sha256"])
    if (marker.get("scope") != "FULL_STRICT_SOURCE" or type(marker.get("protocol")) is not dict
            or terminal.get("status") != "COMPLETE_UNQUALIFIED_SOURCE" or terminal.get("stage") != "STRICT_SOURCE"
            or terminal.get("scope") != "FULL_STRICT_SOURCE" or terminal.get("folds_completed") != [1, 2, 3]
            or terminal.get("fit_or_score_calls") != 0 or terminal.get("source_identity_before") != terminal.get("source_identity_after")):
        raise ValueError("pinned complete full STRICT source required; live/nonterminal source refused")
    return root


def lock_file(stack, path):
    stream = stack.enter_context(checked_file(path, MAX_METADATA, empty=True))
    def verify():
        held = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != 0o600 or current.st_uid != os.geteuid()
                or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("held cache lock pathname/inode changed")
    verify()
    try: fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: raise ValueError("active writer lock refused") from None
    verify()
    stack.callback(verify)
    return verify


def target_path(root, target):
    path = root / target["path"]
    for parent in (path.parent, *path.parent.parents):
        directory(parent)
        if parent == root: break
        if not parent.is_relative_to(root): raise ValueError("cache path escape refused")
    if path.is_symlink(): raise ValueError("target symlink refused")
    if path.suffix == ".sqlite" and any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("SQLite must be closed and checkpointed")
    return path


def verify_archive(path, receipt, *, destination=None):
    if digest(path, MAX_ARCHIVE) != receipt["archive_sha256"] or path.stat().st_size != receipt["archive_bytes"]:
        raise ValueError("archive hash/size mismatch")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MEMORY_LIMIT)
    digest_value = hashlib.sha256(); total = 0
    try:
        with checked_file(path, MAX_ARCHIVE) as source:
            for block in iter(lambda: source.read(BLOCK), b""):
                if decoder.eof: raise ValueError("trailing or concatenated archive")
                pending = block
                while True:
                    raw = decoder.decompress(pending, max_length=min(BLOCK, receipt["original_bytes"] + 1 - total))
                    total += len(raw); digest_value.update(raw)
                    if total > receipt["original_bytes"]: raise ValueError("restore size budget exceeded")
                    if destination is not None: destination.write(raw)
                    if decoder.eof or decoder.needs_input: break
                    pending = b""
            if not decoder.eof or decoder.unused_data: raise ValueError("truncated or trailing archive")
    except lzma.LZMAError: raise ValueError("bounded single XZ stream required") from None
    if total != receipt["original_bytes"] or digest_value.hexdigest() != receipt["original_sha256"]:
        raise ValueError("restored original bytes mismatch")
    if digest(path, MAX_ARCHIVE) != receipt["archive_sha256"]:
        raise ValueError("archive changed during restoration")


def validate_recovery(receipt, target):
    """The trusted target, not an editable recovery receipt, pins original bytes."""
    if (type(receipt) is not dict or set(receipt) != RECOVERY_FIELDS
            or type(receipt["original_sha256"]) is not str or SHA.fullmatch(receipt["original_sha256"]) is None
            or receipt["original_sha256"] != target["sha256"]
            or type(receipt["original_bytes"]) is not int or receipt["original_bytes"] != target["bytes"]
            or not 1 <= receipt["original_bytes"] <= MAX_CACHE
            or type(receipt["archive_sha256"]) is not str or SHA.fullmatch(receipt["archive_sha256"]) is None
            or type(receipt["archive_bytes"]) is not int
            or not 1 <= receipt["archive_bytes"] <= min(MAX_ARCHIVE, target["bytes"] + target["bytes"] // 100 + 65536)
            or type(receipt["original_signature"]) is not list or len(receipt["original_signature"]) != 5
            or any(type(value) is not int or not 0 <= value < 2 ** 64 for value in receipt["original_signature"])
            or receipt["original_signature"][2] != target["bytes"]):
        raise ValueError("exact bounded recovery must match the trusted approved target")
    return receipt


def archive_one(source, target, archive):
    require_headroom(archive.parent, target["bytes"] + target["bytes"] // 100 + 65536)
    before = signature(source)
    if before[2] != target["bytes"] or digest(source) != target["sha256"]:
        raise ValueError("approved original hash/size mismatch")
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as outgoing, checked_file(source) as incoming:
        with lzma.LZMAFile(outgoing, "w", preset=3) as compressed:
            for block in iter(lambda: incoming.read(BLOCK), b""): compressed.write(block)
        outgoing.flush(); os.fsync(outgoing.fileno())
    receipt = {"original_sha256": target["sha256"], "original_bytes": target["bytes"],
        "original_signature": list(before), "archive_sha256": digest(archive, MAX_ARCHIVE), "archive_bytes": archive.stat().st_size}
    validate_recovery(receipt, target)
    verify_archive(archive, receipt)
    if signature(source) != before or digest(source) != target["sha256"]:
        raise ValueError("source changed during recovery proof")
    return receipt


def restore_one(root, target, archive, receipt, approval):
    """Recover exactly one approved missing cache without overwriting any file."""
    validate_recovery(receipt, target)
    source = target_path(root, target)
    verify_archive(archive, receipt)
    if source.exists():
        if signature(source)[2] != target["bytes"] or digest(source) != target["sha256"]:
            raise ValueError("existing cache differs from approved restoration target")
        return False
    require_headroom(source.parent, target["bytes"])
    descriptor, temporary_name = tempfile.mkstemp(prefix="." + source.name + ".restore-", suffix=".pending", dir=source.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as outgoing:
            verify_archive(archive, receipt, destination=outgoing)
            outgoing.flush(); os.fsync(outgoing.fileno())
        if signature(temporary)[2] != target["bytes"] or digest(temporary) != target["sha256"]:
            raise ValueError("temporary restored cache hash/size mismatch")
        source_binding(approval); target_path(root, target)
        # Same-filesystem link publishes complete bytes atomically and refuses
        # an existing target. It cannot replace a racing writer's file.
        try: os.link(temporary, source, follow_symlinks=False)
        except FileExistsError: raise ValueError("restoration destination appeared; overwrite refused") from None
        temporary.unlink()  # Only this call's exclusively created private sibling.
        parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
        if signature(source)[2] != target["bytes"] or digest(source) != target["sha256"]:
            raise ValueError("published restored cache hash/size mismatch")
        return True
    finally:
        if temporary.exists(): temporary.unlink()  # Failed own temporary, never an approved original.


def verify_filesystem_recovery(archive, receipt):
    """Write/fsync/read one private bounded restoration before material unlink."""
    require_headroom(archive.parent, receipt['original_bytes'])
    descriptor, temporary_name = tempfile.mkstemp(prefix='.cache-fs-recovery-', suffix='.pending', dir=archive.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as restored:
            verify_archive(archive, receipt, destination=restored)
            restored.flush(); os.fsync(restored.fileno())
        if signature(temporary)[2] != receipt['original_bytes'] or digest(temporary) != receipt['original_sha256']:
            raise ValueError('filesystem cache recovery byte checksum/size mismatch')
        return {'restored_bytes': receipt['original_bytes'], 'restored_sha256': receipt['original_sha256'],
                'filesystem_write_fsync_readback_verified': True}
    finally:
        if temporary.exists(): temporary.unlink()  # This call's exclusively created scratch only.


def closed_generation_paths(output, stem, generation):
    if generation == 0:
        return output / (stem + ".verified.private.json"), output
    parent = output / "closed-generations"
    if not parent.exists(): parent.mkdir(mode=0o700)
    directory(parent)
    leaf = parent / f"generation-{generation:06d}"
    if not leaf.exists(): leaf.mkdir(mode=0o700)
    directory(leaf)
    return leaf / (stem + ".verified.private.json"), leaf


def read_generation_receipt(path, target, approval_sha, generation, previous_sha=None):
    saved = json_file(path, digest(path))
    fields = {"approval_sha256", "target", "recovery"}
    if generation: fields |= {"closed_generation", "previous_receipt_sha256"}
    if (type(saved) is not dict or set(saved) != fields or saved["approval_sha256"] != approval_sha
            or saved["target"] != target or generation and (
                type(saved["closed_generation"]) is not int or saved["closed_generation"] != generation
                or saved["previous_receipt_sha256"] != previous_sha)):
        raise ValueError("recovery receipt target/approval/closed-generation mismatch")
    return validate_recovery(saved["recovery"], target)


def admit_cache_retirement(root, approval, approval_sha, checkpoint_path, checkpoint_sha, source_pins, lock_checks):
    """Reuse the source-only plan validator; an execution receipt grants no unlink."""
    fields = {'dataset_manifest_sha256', 'archive_sidecar_sha256', 'archive_result_sha256'}
    if (type(source_pins) is not dict or set(source_pins) != fields
            or any(type(value) is not str or SHA.fullmatch(value) is None for value in source_pins.values())):
        raise ValueError('Material cache deletion requires three explicit source/archive pins')
    path = ROOT / 'observability/scripts/retire-ueba-strict-source-shards.py'
    spec = importlib.util.spec_from_file_location('owned_cache_coordinator_admission', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    source = root / 'standard'
    for name, field, maximum in (
            ('manifest.json', 'dataset_manifest_sha256', module.S.MAX_MANIFEST_BYTES),
            (module.S.SIDECAR, 'archive_sidecar_sha256', module.S.MAX_MANIFEST_BYTES),
            (module.S.RESULT, 'archive_result_sha256', module.S.MAX_METADATA)):
        module.S.metadata(source / name, maximum, source_pins[field])
    adapter = {**source_pins, 'source_marker_sha256': approval['source_marker_sha256'],
               'source_terminal_sha256': approval['source_terminal_sha256']}
    snapshot, validate_code = module.coordinator_admission(
        source, adapter, approval_sha, checkpoint_path, checkpoint_sha,
        expected_scope='NEW_STRICT_CACHE_RETIREMENT_COORDINATOR', lock_checks=lock_checks)
    def verify():
        checkpoint, original = snapshot
        if module.S.read_bytes(checkpoint, module.S.MAX_METADATA) != original:
            raise ValueError('admitted cache coordinator checkpoint changed')
        for name, field, maximum in (
                ('manifest.json', 'dataset_manifest_sha256', module.S.MAX_MANIFEST_BYTES),
                (module.S.SIDECAR, 'archive_sidecar_sha256', module.S.MAX_MANIFEST_BYTES),
                (module.S.RESULT, 'archive_result_sha256', module.S.MAX_METADATA)):
            module.S.metadata(source / name, maximum, source_pins[field])
        validate_code()
        for check in lock_checks: check()
    verify()
    return verify


def run(approval_path, approval_sha, output, *, retire=False, resume=False, restore=False,
        closed_generation=0, production=False, coordinator_checkpoint=None, coordinator_checkpoint_sha256=None,
        source_pins=None):
    """Archive approved closed caches; material retirement needs sealed admission.

    Existing numeric_cache memmaps and selection/evaluation consumers are not
    universally coordinated yet. Advisory locks alone do not admit real reuse
    or retirement by an uncoordinated pipeline. The CLI requires a separate
    scoped source/code/image checkpoint; internal fixture mode is not admission.
    """
    if type(production) is not bool or production and not retire:
        raise ValueError('production admission is only for explicit approved retirement')
    if type(closed_generation) is not int or not 0 <= closed_generation <= 1024:
        raise ValueError("bounded explicit closed-generation number required")
    if closed_generation and not resume and not restore:
        raise ValueError("new closed generation requires explicit archive resume")
    if retire and restore: raise ValueError("retirement and restoration are separate operations")
    if restore: resume = True
    approval = json_file(approval_path, approval_sha); targets = approved_targets(approval); root = source_binding(approval)
    if retire and approval["retirement_approved"] is not True: raise ValueError("explicit per-target retirement approval required")
    output = Path(output).absolute(); directory(output.parent)
    if output.is_relative_to(root) or any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError("archives must remain outside the approved source root")
    if resume: directory(output)
    elif output.exists(): raise ValueError("fresh archive destination required")
    else: output.mkdir(mode=0o700)
    with ExitStack() as stack:
        # All locks are held through source rechecks and optional exact unlink.
        lock_checks = [lock_file(stack, root / "writer.lock")]
        for relative_lock in sorted(approval["campaign_locks"]):
            lock_checks.append(lock_file(stack, root / relative_lock))
        if production:
            lock_checks.append(lock_file(stack, root / 'standard' / 'generation.lock'))
        source_lock_checks = tuple(lock_checks)
        for leaf in sorted({str(Path(target["path"]).parent) for target in targets}):
            lock_checks.append(lock_file(stack, root / leaf / "writer.lock"))
        source_binding(approval)
        admitted = None
        if production:
            admitted = admit_cache_retirement(root, approval, approval_sha, coordinator_checkpoint,
                coordinator_checkpoint_sha256, source_pins, source_lock_checks)
        declaration = {"approval_sha256": approval_sha, "campaign_root": str(root), "targets": targets,
                       "retirement_approved": approval["retirement_approved"], "campaign_locks": approval["campaign_locks"]}
        declaration_path = output / "predeclared.private.json"
        if resume:
            if json_file(declaration_path, digest(declaration_path)) != declaration: raise ValueError("resume declaration differs")
        else: write_new(declaration_path, declaration)
        results = []
        for ordinal, target in enumerate(targets):
            source = target_path(root, target); stem = f"target-{ordinal:06d}"
            archive = output / (stem + ".xz")
            evidence, generation_root = closed_generation_paths(output, stem, closed_generation)
            pending = generation_root / (stem + ".retirement-pending.private.json")
            done = generation_root / (stem + ".retired.private.json")
            previous_sha = None
            prior = None
            if closed_generation:
                prior_path, _ = closed_generation_paths(output, stem, closed_generation - 1)
                if not prior_path.exists(): raise ValueError("prior closed-generation recovery receipt required")
                previous_sha = digest(prior_path)
                preceding_sha = None
                if closed_generation > 1:
                    preceding_path, _ = closed_generation_paths(output, stem, closed_generation - 2)
                    if not preceding_path.exists(): raise ValueError("prior closed-generation chain required")
                    preceding_sha = digest(preceding_path)
                prior = read_generation_receipt(prior_path, target, approval_sha, closed_generation - 1, preceding_sha)
                verify_archive(archive, prior)
            if evidence.exists():
                if not resume: raise ValueError("existing recovery receipt requires explicit resume")
                receipt = read_generation_receipt(evidence, target, approval_sha, closed_generation, previous_sha)
                verify_archive(archive, receipt)
            else:
                if restore: raise ValueError("restoration requires a prior verified recovery receipt")
                if not source.exists(): raise ValueError("missing source without prior verified archive refused")
                if closed_generation:
                    before = signature(source)
                    if before[2] != target["bytes"] or digest(source) != target["sha256"]:
                        raise ValueError("closed-generation bytes differ from approved original")
                    receipt = validate_recovery({**prior, "original_signature": list(before)}, target)
                    verify_archive(archive, receipt)
                    if signature(source) != before or digest(source) != target["sha256"]:
                        raise ValueError("closed-generation source changed during verification")
                    write_new(evidence, {"approval_sha256": approval_sha, "target": target, "recovery": receipt,
                                        "closed_generation": closed_generation, "previous_receipt_sha256": previous_sha})
                else:
                    receipt = archive_one(source, target, archive)
                    write_new(evidence, {"approval_sha256": approval_sha, "target": target, "recovery": receipt})
            if restore:
                restored = restore_one(root, target, archive, receipt, approval)
                results.append({"path": target["path"], "restored": restored, "retired": False, "recovery_verified": True})
                continue
            retirement_intent = {"approval_sha256": approval_sha, "target": target, "recovery": receipt}
            retirement_done = {"approval_sha256": approval_sha, "target": target, "retired": True}
            if production:
                retirement_intent['coordinator_checkpoint_sha256'] = coordinator_checkpoint_sha256
                retirement_intent['filesystem_recovery'] = {
                    'restored_bytes': receipt['original_bytes'], 'restored_sha256': receipt['original_sha256'],
                    'filesystem_write_fsync_readback_verified': True}
                retirement_done['coordinator_checkpoint_sha256'] = coordinator_checkpoint_sha256
            if not source.exists():
                if (not retire or not pending.exists()
                        or json_file(pending, digest(pending)) != retirement_intent):
                    raise ValueError("missing source requires exact prior approved retirement intent")
                if done.exists() and json_file(done, digest(done)) != retirement_done:
                    raise ValueError('completed cache retirement declaration changed')
                if not done.exists(): write_new(done, retirement_done)
                results.append({"path": target["path"], "retired": True, "recovery_verified": True}); continue
            if signature(source) != tuple(receipt["original_signature"]) or digest(source) != target["sha256"]:
                raise ValueError("source identity/hash changed before retirement")
            source_binding(approval); verify_archive(archive, receipt)
            if retire:
                filesystem_recovery = verify_filesystem_recovery(archive, receipt) if production else None
                intent = retirement_intent
                if production:
                    if filesystem_recovery != intent['filesystem_recovery']:
                        raise ValueError('filesystem cache recovery certificate mismatch')
                if pending.exists():
                    if json_file(pending, digest(pending)) != intent: raise ValueError("retirement intent differs")
                else: write_new(pending, intent)
                if signature(source) != tuple(receipt["original_signature"]) or digest(source) != target["sha256"]:
                    raise ValueError("source changed after durable retirement intent")
                for verify_lock in lock_checks: verify_lock()
                if admitted is not None:
                    if json_file(approval_path, approval_sha) != approval:
                        raise ValueError('approved cache target declaration changed')
                    admitted()
                source.unlink()  # Exact pinned NEW cache file only, under held writer locks.
                descriptor = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
                write_new(done, retirement_done)
            results.append({"path": target["path"], "retired": retire, "recovery_verified": True})
        if admitted is not None: admitted()
        return {"status": "COMPLETED", "scope": "NEW_STRICT_CACHE_RETIRED" if production else "STORAGE_ONLY", "approval_sha256": approval_sha,
                "targets": results, "original_files_retired": sum(item["retired"] for item in results),
                "original_files_restored": sum(item.get("restored", False) for item in results),
                "closed_generation": closed_generation, "fit_or_score_calls": 0, "aws_changed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approval", type=Path, required=True); parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retire-approved-files", action="store_true")
    parser.add_argument("--restore-approved-files", action="store_true")
    parser.add_argument("--closed-generation", type=int, default=0)
    parser.add_argument('--coordinator-checkpoint', type=Path)
    parser.add_argument('--coordinator-checkpoint-sha256')
    parser.add_argument('--dataset-sha256'); parser.add_argument('--archive-sha256'); parser.add_argument('--archive-result-sha256')
    args = parser.parse_args()
    production = args.retire_approved_files
    if production and any(value is None for value in (args.coordinator_checkpoint, args.coordinator_checkpoint_sha256,
            args.dataset_sha256, args.archive_sha256, args.archive_result_sha256)):
        raise SystemExit("coordinator restore integration not yet admitted")
    if not production and any(value is not None for value in (args.coordinator_checkpoint, args.coordinator_checkpoint_sha256,
            args.dataset_sha256, args.archive_sha256, args.archive_result_sha256)):
        raise SystemExit('retirement admission options require explicit --retire-approved-files')
    try: print(canonical(run(args.approval, args.approval_sha256, args.output, retire=args.retire_approved_files,
                            resume=args.resume, restore=args.restore_approved_files, closed_generation=args.closed_generation,
                            production=production, coordinator_checkpoint=args.coordinator_checkpoint,
                            coordinator_checkpoint_sha256=args.coordinator_checkpoint_sha256,
                            source_pins={'dataset_manifest_sha256': args.dataset_sha256,
                                         'archive_sidecar_sha256': args.archive_sha256,
                                         'archive_result_sha256': args.archive_result_sha256} if production else None)))
    except Exception as failure: raise SystemExit("Staged cache archive refused/failed: " + type(failure).__name__ + "; verified per-target receipts retained") from None
