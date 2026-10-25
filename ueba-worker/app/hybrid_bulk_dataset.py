"""Private BULK_PILOT training data, additive to the frozen small pilot contract."""

import hashlib
import os
from pathlib import Path
import re
import stat

from app.catalog import MAX_SHARD_BYTES, parse_json, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.hybrid_dataset import CLASS_TARGETS, CLASS_TARGET_NAMES, training_targets
from app.policy import canonical

NORMAL_ROWS = 50000
SUPERVISED_ROWS = 81500
MAX_SUPERVISED_ROWS = 100000
SUPPLEMENT_NAMESPACE = "hybrid-bulk-supplement-20261004-a01"
NORMAL_NAMESPACE = "schema4-pilot-20261003-a01"


def value_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def checksum(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def private_read(root, relative, maximum):
    if relative not in ("manifest.private.json", "predeclared.private.json") and not re.fullmatch(
            r"shards/bulk-(?:normal-ready|supplement)-(?:ready|unseen|cold|normal)-b[0-9]{6}-[0-9]{3}\.json", relative):
        raise ValueError("bulk reader accepts only its protected training artifacts")
    path = root / relative
    if (not path.parent.resolve(strict=True).is_relative_to(root)
            or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents)):
        raise ValueError("local protected bulk training file required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("local protected bulk training file required") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077 or before.st_size > maximum):
            raise ValueError("bounded owner-controlled regular bulk training file required")
        data = stream.read(maximum + 1)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_uid, item.st_mode)
        if (signature(before) != signature(os.fstat(stream.fileno())) or signature(before) != signature(path.lstat())
                or len(data) != before.st_size):
            raise ValueError("bulk training file changed while reading")
    return data


def load_hybrid_bulk_fit(root, expected_sha256):
    """Return (normal_READY_50000_rows, supervised_81500_rows, manifest).

    Supervised labels are obtained with training_targets(rows) outside X. No
    calibration/validation/holdout row is opened or accepted by this loader.
    """
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("immutable bulk training manifest checksum required")
    root = Path(root).absolute()
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise ValueError("regular private bulk training directory required")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("private owner-controlled bulk training directory required")
    raw = private_read(root, "manifest.private.json", 2 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("bulk training manifest checksum mismatch")
    manifest = parse_json(raw)
    if not isinstance(manifest, dict):
        raise ValueError("bulk training manifest must be an object")
    for key in ("hybrid_bulk_training_schema_version", "feature_schema_version", "telemetry_contract_version",
                "fit_or_score_calls", "holdout_numeric_records_read"):
        if type(manifest.get(key)) is not int:
            raise ValueError("bulk schema and counters require exact integers")
    if (manifest["hybrid_bulk_training_schema_version"] != 1 or manifest["feature_schema_version"] != 4
            or manifest["telemetry_contract_version"] != 3 or manifest.get("feature_names") != list(FEATURE_NAMES_V4)
            or manifest.get("stage") != "BULK_PILOT" or manifest.get("data_provenance") != "DEMO_ONLY"
            or not isinstance(manifest.get("dataset_id"), str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", manifest["dataset_id"])
            or manifest.get("artifact_id") != manifest["dataset_id"]
            or manifest.get("quality_gate") != "NOT_APPLICABLE" or manifest["fit_or_score_calls"] != 0
            or manifest["holdout_numeric_records_read"] != 0 or manifest.get("class_targets") != CLASS_TARGETS
            or manifest.get("class_target_names") != CLASS_TARGET_NAMES or manifest.get("confirmed_attack_target_available") is not False):
        raise ValueError("unqualified bulk planned-context training contract required")
    source = manifest.get("source_identity_before")
    if not isinstance(source, dict) or source != manifest.get("source_identity_after"):
        raise ValueError("frozen bulk producer/source identity changed")
    declaration_raw = private_read(root, "predeclared.private.json", 2 * 1024 * 1024)
    if hashlib.sha256(declaration_raw).hexdigest() != manifest.get("predeclared_identity_sha256"):
        raise ValueError("bulk pre-generation declaration changed")
    declaration = parse_json(declaration_raw)
    if (not isinstance(declaration, dict) or declaration.get("source_identity") != source
            or type(declaration.get("new_frames_generated_before_declaration")) is not int
            or declaration.get("new_frames_generated_before_declaration") != 0):
        raise ValueError("bulk source/count recipe must precede all new worlds")
    proof = manifest.get("isolation_proofs")
    if (not isinstance(proof, dict) or proof.get("unseen_validation_accounts_disjoint") is not True
            or proof.get("all_training_before_calibration_by_more_than14days") is not True
            or any(type(proof.get(key)) is not int or proof[key] != 0 for key in
                   ("calibration_frame_overlap", "calibration_account_hour_overlap", "validation_frame_overlap", "validation_account_hour_overlap"))):
        raise ValueError("verified frozen calibration/validation isolation proof required")
    sections = manifest.get("training_sections")
    if not isinstance(sections, dict) or set(sections) != {"NORMAL_COMPONENT", "SUPPLEMENT"}:
        raise ValueError("separate normal-only and labeled-supplement sections required")
    normal, supplement, seen_frames, seen_hours, paths = [], [], set(), set(), set()
    for name, split in sections.items():
        if (not isinstance(split, dict) or not isinstance(split.get("shards"), list) or not 1 <= len(split["shards"]) <= 700
                or any(type(split.get(key)) is not int for key in ("records", "normal", "positive"))
                or value_sha({key: value for key, value in split.items() if key != "sha256"}) != split.get("sha256")):
            raise ValueError("bounded checksum-bound bulk training section required")
        target = normal if name == "NORMAL_COMPONENT" else supplement
        for shard in split["shards"]:
            if (not isinstance(shard, dict) or not isinstance(shard.get("path"), str) or shard["path"] in paths
                    or any(type(shard.get(key)) is not int for key in ("records", "normal", "positive"))):
                raise ValueError("unique exact-integer bulk training shard descriptor required")
            paths.add(shard["path"])
            data = private_read(root, shard["path"], MAX_SHARD_BYTES)
            if hashlib.sha256(data).hexdigest() != shard.get("sha256"):
                raise ValueError("bulk numeric training shard checksum mismatch")
            rows = parse_json(data)
            stats = validate_rows(rows, 4)
            if any(shard.get(key) != value for key, value in stats.items()):
                raise ValueError("actual bulk training shard counters changed")
            for row in rows:
                hour = (row["account_id"], utc(row["window_start"]).strftime("%Y-%m-%dT%H"))
                if row["frame_id"] in seen_frames or hour in seen_hours:
                    raise ValueError("bulk duplicate evaluated frame/account-hour refused")
                if not utc("2026-04-15T00:00:00Z") <= utc(row["window_start"]) <= utc("2026-04-15T12:00:00Z"):
                    raise ValueError("bulk training must retain original pre-calibration FIT time")
                if name == "NORMAL_COMPONENT" and (row["label"] or row["cohort"] != "READY" or row["family"] != "normal"):
                    raise ValueError("normal component must contain normal READY only")
                seen_frames.add(row["frame_id"])
                seen_hours.add(hour)
            target.extend(rows)
            if len(normal) + len(supplement) > MAX_SUPERVISED_ROWS:
                raise ValueError("bulk supervised training bound exceeded")
        if len(target) != split["records"]:
            raise ValueError("bulk section is incomplete")
    if len(normal) != NORMAL_ROWS or len(supplement) != SUPERVISED_ROWS - NORMAL_ROWS:
        raise ValueError("exact 50000 normal component and31500 supplement required")
    rows = [*normal, *supplement]
    from collections import Counter
    if (Counter(row["cohort"] for row in rows if not row["label"]) != Counter({"READY": 50050, "UNSEEN_READY": 14300, "COLD": 7150})
            or Counter(row["cohort"] for row in rows if row["label"]) != Counter({"READY": 7000, "UNSEEN_READY": 2000, "COLD": 1000})):
        raise ValueError("exact 71500-normal/10000-positive 70/20/10 population required")
    for family in CLASS_TARGETS:
        if family != "normal" and Counter(row["cohort"] for row in rows if row["family"] == family) != Counter({"READY": 1400, "UNSEEN_READY": 400, "COLD": 200}):
            raise ValueError("each bulk incident family requires predeclared 2000 rows")
    if value_sha(normal[:2000]) != manifest.get("original_normal_2000_prefix_sha256"):
        raise ValueError("original normal2000 feature/identity prefix changed")
    return normal, rows, manifest
