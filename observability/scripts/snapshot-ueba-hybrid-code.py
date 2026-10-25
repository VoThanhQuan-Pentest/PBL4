#!/usr/bin/env python3
"""New private code-only HYBRID checkpoint; never model or lifecycle authority."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BACKUPS = ROOT / "observability/runtime/private-backups"
APP = ROOT / "ueba-worker/app"
IMAGE = "sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f"
TOOLS = ("observability/scripts/continue-ueba-strict.py", "observability/scripts/archive-ueba-strict-source.py",
         "observability/scripts/retire-ueba-strict-source-shards.py", "observability/scripts/archive-ueba-staged-cache.py",
         "ueba-worker/app/pipeline_lock.py")
MAX_FILE = 1024 * 1024
MAX_FILES = 256
RECEIPT = "checkpoint.private.json"


def signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink, value.st_uid, value.st_mode)


def directory(path, *, private=False):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical code checkpoint directory required")
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or private and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("owner-controlled code checkpoint directory required")
    return path


def stable_bytes(path, *, empty=False):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("code checkpoint refuses symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not (0 if empty else 1) <= before.st_size <= MAX_FILE):
            raise ValueError("bounded owner-controlled regular code file required")
        raw = source.read(MAX_FILE + 1)
        if (len(raw) != before.st_size or signature(before) != signature(os.fstat(source.fileno()))
                or signature(before) != signature(path.lstat())):
            raise ValueError("code file changed during bounded read")
    return raw, signature(before)


def source_names(app):
    app = directory(app)
    entries = list(app.iterdir())
    if len(entries) > MAX_FILES + 1: raise ValueError("bounded flat Python source inventory required")
    names, excluded = [], []
    for path in entries:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode): raise ValueError("source symlink refused")
        if path.name == "__pycache__" and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid():
            excluded.append(path.name)  # Known cache is not opened, copied, executed, or deleted.
            continue
        if not re.fullmatch(r"[a-z_][a-z0-9_]*\.py", path.name) or not stat.S_ISREG(info.st_mode):
            raise ValueError("unknown or nonregular flat app member refused")
        names.append(path.name)
    if not 1 <= len(names) <= MAX_FILES: raise ValueError("bounded nonempty Python source inventory required")
    return sorted(names), sorted(excluded)


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw); target.flush(); os.fsync(target.fileno())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def continuation():
    # Import only this trusted existing helper, never the source app modules.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("hybrid_code_snapshot_continuation", ROOT / TOOLS[0])
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def snapshot(output=None):
    helper = continuation()
    parent = directory(BACKUPS, private=True)
    names, excluded = source_names(APP)
    sources = {name: stable_bytes(APP / name, empty=name == "__init__.py") for name in names}
    tools = {name: stable_bytes(ROOT / name) for name in TOOLS}
    original_inventory = {"image_id": IMAGE, "python_sources": {name: hashlib.sha256(raw).hexdigest() for name, (raw, _) in sources.items()}}
    original_sha = hashlib.sha256(helper.canonical(original_inventory).encode()).hexdigest()
    planned = sum(len(raw) for raw, _ in (*sources.values(), *tools.values())) + 1024 * 1024
    if shutil.disk_usage(parent).free < 5_000_000_000 + planned: raise ValueError("code checkpoint preserves decimal5GB reserve")
    if output is None:
        output = Path(tempfile.mkdtemp(prefix="hybrid-execution-code-20261005-", dir=parent))
    else:
        output = Path(output).absolute()
        if output.parent != parent or output.exists() or output.is_symlink(): raise ValueError("fresh exact private checkpoint destination required")
        output.mkdir(mode=0o700)
    directory(output, private=True)
    app_copy = output / "app"; app_copy.mkdir(mode=0o700)
    tool_copy = output / "technical-tools"; tool_copy.mkdir(mode=0o700)
    readbacks = {}
    for name, (raw, _) in sources.items():
        destination = app_copy / name; write_new(destination, raw)
        actual, _ = stable_bytes(destination, empty=name == "__init__.py")
        if actual != raw or stat.S_IMODE(destination.stat().st_mode) != 0o600: raise ValueError("copied Python bytes/mode mismatch")
        readbacks[name] = hashlib.sha256(actual).hexdigest()
    tool_receipts = {}
    for relative, (raw, before) in tools.items():
        destination = tool_copy / Path(relative).name; write_new(destination, raw)
        actual, _ = stable_bytes(destination)
        if actual != raw: raise ValueError("technical tool readback differs")
        tool_receipts[relative] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                                  "copy": str(destination.relative_to(output)), "readback_sha256": hashlib.sha256(actual).hexdigest(),
                                  "original_signature_before": list(before)}
    inventory, copied_sha = helper.hybrid_code_identity(output, IMAGE)
    if inventory != original_inventory or copied_sha != original_sha: raise ValueError("canonical execution code inventory differs")
    after_names, after_excluded = source_names(APP)
    if after_names != names or after_excluded != excluded: raise ValueError("source app topology changed during copy")
    for name, (raw, before) in sources.items():
        if stable_bytes(APP / name, empty=name == "__init__.py") != (raw, before): raise ValueError("original Python source changed during copy")
    for name, (raw, before) in tools.items():
        actual, after = stable_bytes(ROOT / name)
        if actual != raw or after != before: raise ValueError("original technical tool changed during copy")
        tool_receipts[name]["original_signature_after"] = list(after)
    after_inventory = {"image_id": IMAGE, "python_sources": {name: hashlib.sha256(stable_bytes(APP / name, empty=name == "__init__.py")[0]).hexdigest() for name in names}}
    after_sha = hashlib.sha256(helper.canonical(after_inventory).encode()).hexdigest()
    if after_sha != original_sha: raise ValueError("original source inventory changed before publication")
    result = {"checkpoint_schema_version": 1, "scope": "HYBRID_PYTHON_EXECUTION_CODE_ONLY", "status": "VERIFIED_CODE_CHECKPOINT",
              "created_at_utc": datetime.now(timezone.utc).isoformat(), "image_id": IMAGE, "code_directory": str(output),
              "canonical_code_inventory_sha256": copied_sha, "original_code_inventory_sha256_before": original_sha,
              "original_code_inventory_sha256_after": after_sha, "inventory": inventory, "copy_readback_sha256": readbacks,
              "copied_python_files": len(names), "copied_python_bytes": sum(len(raw) for raw, _ in sources.values()),
              "excluded_known_source_members": excluded, "technical_tool_pins": tool_receipts,
              "original_bytes_unchanged": True, "execution_approved": False, "retirement_approved": False,
              "models_copied": 0, "fit_or_score_calls": 0, "holdout_numeric_records_read": 0, "files_deleted": 0, "aws_changed": False}
    write_new(output / RECEIPT, helper.canonical(result).encode())
    for path in (app_copy, tool_copy, output, parent): fsync_directory(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = snapshot(args.output)
        path = Path(result["code_directory"]) / RECEIPT
        print(continuation().canonical({"status": result["status"], "code_directory": result["code_directory"],
              "canonical_code_inventory_sha256": result["canonical_code_inventory_sha256"],
              "receipt_sha256": hashlib.sha256(stable_bytes(path)[0]).hexdigest(), "copied_python_files": result["copied_python_files"],
              "fit_or_score_calls": 0, "execution_approved": False}))
    except Exception as failure:
        raise SystemExit("HYBRID code snapshot refused/failed: " + type(failure).__name__ + "; originals and any private partial checkpoint retained") from None


if __name__ == "__main__": main()
