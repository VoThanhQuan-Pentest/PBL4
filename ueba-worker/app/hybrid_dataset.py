"""Protected, labeled hybrid training artifact; separate from normal-only FIT.

This additive research contract never relaxes catalog.ShardedDataset's ban on
positive FIT labels. Planned synthetic behavioral/operational causes are not
confirmed attacks. Labels and identity remain outside every feature vector.
"""

from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import stat

from app.catalog import MAX_SHARD_BYTES, parse_json, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.policy import canonical
from app.strict_metrics import FAMILIES

SCHEMA_VERSION = 1
TRAINING_SPLIT = "incident-training"
CLASS_TARGETS = {"normal": 0, "request_burst": 1, "endpoint_scan": 1, "auth_failure_burst": 1,
                 "sensitive_action_burst": 1, "http_error_burst": 2}
CLASS_TARGET_NAMES = {"0": "NORMAL", "1": "SIMULATED_SECURITY_BEHAVIOR_CONTEXT",
                      "2": "SIMULATED_OPERATIONAL_FAILURE_CONTEXT"}
PILOT_SHA = "3c127c1e57a4a436ecabef1c9fe9d40465fc9191313259560a85554b6d7b9f12"
CALIBRATION_START = "2026-05-03T00:00:00Z"
VALIDATION_START = "2026-05-21T00:00:00Z"
MAX_TRAINING_ROWS = 4000


def value_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def checksum(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular non-symlink bound file required")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def private_read(root, relative, maximum):
    if relative != "manifest.private.json" and relative != "predeclared.private.json" and not re.fullmatch(
            r"shards/incident-training-(?:shared|new)-[0-9]{6}\.json", relative):
        raise ValueError("hybrid reader may only open its local training artifacts")
    path = root / relative
    if (not path.parent.resolve(strict=True).is_relative_to(root)
            or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents)):
        raise ValueError("protected regular hybrid training artifact required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("protected regular hybrid training artifact required") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077 or before.st_size > maximum):
            raise ValueError("protected bounded owner-controlled regular hybrid file required")
        result = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        final = path.lstat()
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                   value.st_uid, value.st_mode)
        if signature(before) != signature(after) or signature(before) != signature(final):
            raise ValueError("hybrid file changed while reading")
    if len(result) != before.st_size or len(result) > maximum:
        raise ValueError("hybrid artifact exceeds bounded input size")
    return result


def training_targets(rows):
    """Explicit family-to-class mapping, never inferred from feature values."""
    targets = []
    for row in rows:
        family, label = row.get("family"), row.get("label")
        if (family not in CLASS_TARGETS or type(label) is not int or label not in (0, 1)
                or (family == "normal") != (label == 0)):
            raise ValueError("separate frozen planned family/label mapping required")
        targets.append(CLASS_TARGETS[family])
    return targets


def validate_training_rows(rows):
    if not isinstance(rows, list) or len(rows) != MAX_TRAINING_ROWS:
        raise ValueError("complete 4000-row supervised training population required")
    stats = validate_rows(rows, 4)
    expected_families = {"normal": 3000, **{family: 200 for family in FAMILIES}}
    if (stats["normal"] != 3000 or stats["positive"] != 1000
            or stats["families"] != expected_families
            or stats["cohorts"] != {"READY": 2800, "UNSEEN_READY": 800, "COLD": 400}):
        raise ValueError("exact class/family/cohort hybrid populations required")
    for label, expected in ((0, {"READY": 2100, "UNSEEN_READY": 600, "COLD": 300}),
                            (1, {"READY": 700, "UNSEEN_READY": 200, "COLD": 100})):
        if Counter(row["cohort"] for row in rows if row["label"] == label) != Counter(expected):
            raise ValueError("normal and positive populations must each conserve 70/20/10 cohorts")
    for family in FAMILIES:
        if Counter(row["cohort"] for row in rows if row["family"] == family) != Counter({"READY": 140, "UNSEEN_READY": 40, "COLD": 20}):
            raise ValueError("each incident family must conserve predeclared 70/20/10 cohorts")
    if (utc(stats["from"]) < utc("2026-04-15T00:00:00Z") or utc(stats["to"]) > utc("2026-04-15T12:00:00Z")
            or (utc(CALIBRATION_START) - utc(stats["to"])).total_seconds() <= 14 * 86400
            or utc(stats["to"]) >= utc(VALIDATION_START)):
        raise ValueError("training must stay at original FIT time before all frozen calibration/validation")
    targets = training_targets(rows)
    if Counter(targets) != Counter({0: 3000, 1: 800, 2: 200}):
        raise ValueError("explicit normal/security-context/operational class counts changed")
    return stats


def load_hybrid_fit(root, expected_sha256=None):
    """Return (numeric_rows, manifest); no calibration/validation/holdout I/O.

    ``numeric_rows`` use the existing catalog row fields. Supervised target
    values are obtained separately with training_targets(rows); model callers
    pass only row['features'] as X. No original score-only row is copied here.
    """
    original = Path(root).absolute()
    if original.is_symlink() or original.resolve(strict=True) != original or not original.is_dir():
        raise ValueError("regular protected training directory required")
    root = original
    root_stat = root.stat()
    if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid() or stat.S_IMODE(root_stat.st_mode) & 0o077:
        raise ValueError("hybrid training directory must be private")
    raw = private_read(root, "manifest.private.json", 2 * 1024 * 1024)
    actual_sha = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and actual_sha != expected_sha256:
        raise ValueError("frozen hybrid training manifest checksum mismatch")
    manifest = parse_json(raw)
    if not isinstance(manifest, dict):
        raise ValueError("hybrid training manifest must be an object")
    integer_fields = ("hybrid_training_schema_version", "feature_schema_version", "telemetry_contract_version",
                      "fit_or_score_calls", "holdout_numeric_records_read")
    if any(type(manifest.get(field)) is not int for field in integer_fields):
        raise ValueError("hybrid schema versions and counts require exact integers, not booleans")
    if (manifest.get("hybrid_training_schema_version") != SCHEMA_VERSION or manifest.get("stage") != "PILOT"
            or manifest.get("data_provenance") != "DEMO_ONLY" or manifest.get("feature_schema_version") != 4
            or manifest.get("telemetry_contract_version") != 3 or manifest.get("feature_names") != list(FEATURE_NAMES_V4)
            or manifest.get("class_targets") != CLASS_TARGETS or manifest.get("class_target_names") != CLASS_TARGET_NAMES
            or manifest.get("confirmed_attack_target_available") is not False
            or manifest.get("quality_gate") != "NOT_APPLICABLE" or manifest.get("fit_or_score_calls") != 0
            or not re.fullmatch(r"[a-z0-9_-]{8,32}", str(manifest.get("dataset_id", "")))):
        raise ValueError("bounded unqualified hybrid simulation training contract required")
    source = manifest.get("shared_normal_component_source", {})
    score_only = manifest.get("frozen_score_only_dataset", {})
    if not isinstance(source, dict) or not isinstance(score_only, dict):
        raise ValueError("hybrid source descriptors must be objects")
    if (source.get("manifest_sha256") != PILOT_SHA or source.get("split") != "fold1-fit"
            or type(source.get("rows")) is not int or source.get("rows") != 2000 or source.get("normal_ready_only") is not True
            or source.get("reuse_across_training_components_permitted") is not True
            or score_only.get("manifest_sha256") != PILOT_SHA
            or score_only.get("calibration_start") != CALIBRATION_START or score_only.get("validation_start") != VALIDATION_START
            or score_only.get("fit_use") is not False or manifest.get("holdout_numeric_records_read") != 0):
        raise ValueError("training-only normal sharing and untouched score-only temporal contract required")
    declaration_raw = private_read(root, "predeclared.private.json", 2 * 1024 * 1024)
    if hashlib.sha256(declaration_raw).hexdigest() != manifest.get("predeclared_identity_sha256"):
        raise ValueError("pre-generation recipe/source identity changed")
    declaration = parse_json(declaration_raw)
    if not isinstance(declaration, dict):
        raise ValueError("hybrid predeclaration must be an object")
    if (declaration.get("events_generated_before_declaration") != 0 or declaration.get("new_labels_generated_before_declaration") != 0
            or declaration.get("source_identity") != manifest.get("source_identity_before")
            or manifest.get("source_identity_before") != manifest.get("source_identity_after")):
        raise ValueError("source identity must be frozen before labels/events and unchanged afterwards")
    temporal = manifest.get("temporal_isolation", {})
    if (not isinstance(temporal, dict) or manifest.get("unseen_validation_accounts_disjoint_from_all_training") is not True
            or temporal.get("strictly_exceeds_14_day_history_gap") is not True):
        raise ValueError("temporal history gap and unseen-account isolation proof required")
    split = manifest.get("split", {})
    if not isinstance(split, dict) or split.get("name") != TRAINING_SPLIT or not isinstance(split.get("shards"), list) or not 1 <= len(split["shards"]) <= 64:
        raise ValueError("bounded separate incident-training shards required")
    if any(type(split.get(key)) is not int or split[key] < 0 for key in ("records", "normal", "positive")):
        raise ValueError("hybrid split counts require exact nonnegative integers")
    if value_sha({key: value for key, value in split.items() if key != "sha256"}) != split.get("sha256"):
        raise ValueError("hybrid training split checksum mismatch")
    rows, paths, shared = [], set(), []
    for descriptor in split["shards"]:
        if not isinstance(descriptor, dict):
            raise ValueError("hybrid shard descriptors must be objects")
        if any(type(descriptor.get(key)) is not int or descriptor[key] < 0 for key in ("records", "normal", "positive")):
            raise ValueError("hybrid shard counts require exact nonnegative integers")
        path = descriptor.get("path")
        if (not isinstance(path, str) or path in paths or descriptor.get("id") != Path(path).stem
                or descriptor.get("population") not in ("SHARED_NORMAL_READY_FIT", "INDEPENDENT_NEW_TRAINING")):
            raise ValueError("unique explicitly sourced hybrid shard descriptor required")
        paths.add(path)
        shard_raw = private_read(root, path, MAX_SHARD_BYTES)
        if hashlib.sha256(shard_raw).hexdigest() != descriptor.get("sha256"):
            raise ValueError("hybrid numeric training shard checksum mismatch")
        shard = parse_json(shard_raw)
        stats = validate_rows(shard, 4)
        if any(descriptor.get(key) != value for key, value in stats.items()):
            raise ValueError("actual training shard counts differ from manifest")
        if descriptor["population"] == "SHARED_NORMAL_READY_FIT":
            if stats["positive"] or stats["cohorts"] != {"READY": stats["records"]}:
                raise ValueError("shared training component source must be normal READY only")
            shared.extend(shard)
        rows.extend(shard)
        if len(rows) > MAX_TRAINING_ROWS:
            raise ValueError("hybrid training row budget exceeded")
    stats = validate_training_rows(rows)
    if (len(shared) != 2000 or any(split.get(key) != value for key, value in stats.items())
            or value_sha(shared) != source.get("rows_sha256")
            or value_sha(shared) != declaration.get("shared_original_normal_rows_sha256")):
        raise ValueError("complete sourced training counts changed")
    return rows, manifest
