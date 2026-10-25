"""Bounded protected replacement calibration, not training or qualification.

Both buckets are normal-only original-schema-4 causal worlds. Consumers replace
the old small buckets; they must never append them or double-count overlapping
frames. This research artifact is separate from all existing dataset loaders.
"""

import hashlib
import os
from pathlib import Path
import re
import stat

from app.catalog import MAX_SHARD_BYTES, parse_json, utc, validate_rows
from app.contract import FEATURE_NAMES_V4
from app.policy import canonical

NAMESPACE = "schema4-pilot-20261003-a01"
PILOT_SHA = "3c127c1e57a4a436ecabef1c9fe9d40465fc9191313259560a85554b6d7b9f12"
TRAINING_SHA = "b080e99633e6dfe364d83fd67656baf71989b900682f4b7296369f168d9ae5de"
ROWS_PER_COHORT = 60000


def value_sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def checksum(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def private_read(root, relative, maximum):
    if relative not in ("manifest.private.json", "predeclared.private.json") and not re.fullmatch(
            r"shards/expanded-calibration-(?:ready|cold)-[0-9]{6}\.json", relative):
        raise ValueError("expanded reader is calibration-only; training/validation/holdout refused")
    path = root / relative
    if (not path.parent.resolve(strict=True).is_relative_to(root)
            or any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents)):
        raise ValueError("protected local expanded calibration file required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("protected local expanded calibration file required") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077 or before.st_size > maximum):
            raise ValueError("bounded owner-controlled regular expanded calibration file required")
        data = stream.read(maximum + 1)
        after, final = os.fstat(stream.fileno()), path.lstat()
        signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_uid, item.st_mode)
        if signature(before) != signature(after) or signature(before) != signature(final) or len(data) != before.st_size:
            raise ValueError("expanded calibration file changed while reading")
    return data


def load_expanded_calibration(root, expected_sha256):
    """Return ({'READY': numeric_rows, 'COLD': numeric_rows}, manifest).

    No model fit or other split is read. Only row['features'] may enter the
    scorer; labels, cohort and identifiers are correspondence/audit metadata.
    """
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("immutable expanded calibration manifest checksum required")
    root = Path(root).absolute()
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise ValueError("regular private expanded calibration directory required")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("private owner-controlled expanded calibration directory required")
    raw = private_read(root, "manifest.private.json", 2 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("expanded calibration manifest checksum mismatch")
    manifest = parse_json(raw)
    if not isinstance(manifest, dict):
        raise ValueError("expanded calibration manifest must be an object")
    counts = ("expanded_calibration_schema_version", "feature_schema_version", "telemetry_contract_version",
              "fit_or_score_calls", "holdout_numeric_records_read", "rows_per_cohort")
    if any(type(manifest.get(key)) is not int for key in counts):
        raise ValueError("expanded calibration schema/counts require exact integers")
    if (manifest["expanded_calibration_schema_version"] != 1 or manifest["feature_schema_version"] != 4
            or manifest["telemetry_contract_version"] != 3 or manifest["feature_names"] != list(FEATURE_NAMES_V4)
            or manifest.get("stage") != "PILOT" or manifest.get("data_provenance") != "DEMO_ONLY"
            or manifest.get("diagnostic_scope") != "PILOT_DEMO_ONLY" or manifest.get("quality_gate") != "NOT_APPLICABLE"
            or manifest["fit_or_score_calls"] != 0 or manifest["holdout_numeric_records_read"] != 0
            or manifest["rows_per_cohort"] != ROWS_PER_COHORT or manifest.get("dataset_namespace") != NAMESPACE
            or manifest.get("replacement_calibration_only") is not True or manifest.get("merge_old_calibration") is not False):
        raise ValueError("normal-only bounded replacement PILOT calibration contract required")
    source = manifest.get("source_identity_before")
    if not isinstance(source, dict) or source != manifest.get("source_identity_after"):
        raise ValueError("expanded immutable source identity changed")
    original_source, training_source = source.get("original_pilot"), source.get("hybrid_training")
    if (not isinstance(original_source, dict) or not isinstance(training_source, dict)
            or original_source.get("manifest_sha256") != PILOT_SHA
            or training_source.get("manifest_sha256") != TRAINING_SHA):
        raise ValueError("fixed original score-only and training source bindings required")
    declared = private_read(root, "predeclared.private.json", 2 * 1024 * 1024)
    if hashlib.sha256(declared).hexdigest() != manifest.get("predeclared_identity_sha256"):
        raise ValueError("expanded pre-generation recipe checksum mismatch")
    declaration = parse_json(declared)
    if (not isinstance(declaration, dict) or declaration.get("source_identity") != source
            or type(declaration.get("new_frames_generated_before_declaration")) is not int
            or declaration.get("new_frames_generated_before_declaration") != 0):
        raise ValueError("recipe/source must precede all new calibration events")
    proofs = manifest.get("isolation_proofs")
    if (not isinstance(proofs, dict) or proofs.get("ready_accounts_covered_by_original_fit") is not True
            or proofs.get("training_evaluated_frame_overlap") != 0 or type(proofs.get("training_evaluated_frame_overlap")) is not int
            or proofs.get("validation_evaluated_frame_overlap") != 0 or type(proofs.get("validation_evaluated_frame_overlap")) is not int
            or proofs.get("training_account_hour_overlap") != 0 or type(proofs.get("training_account_hour_overlap")) is not int
            or proofs.get("validation_account_hour_overlap") != 0 or type(proofs.get("validation_account_hour_overlap")) is not int):
        raise ValueError("actual training/validation and READY coverage isolation proof required")
    splits = manifest.get("splits")
    if not isinstance(splits, dict) or set(splits) != {"READY", "COLD"}:
        raise ValueError("exactly independent READY and COLD buckets required")
    buckets, frame_ids, account_hours, paths = {}, set(), set(), set()
    for cohort, split in splits.items():
        if (not isinstance(split, dict) or not isinstance(split.get("shards"), list) or not 1 <= len(split["shards"]) <= 64
                or any(type(split.get(key)) is not int for key in ("records", "normal", "positive"))
                or (split["records"], split["normal"], split["positive"]) != (ROWS_PER_COHORT, ROWS_PER_COHORT, 0)
                or split.get("cohorts") != {cohort: ROWS_PER_COHORT} or split.get("families") != {"normal": ROWS_PER_COHORT}
                or value_sha({key: value for key, value in split.items() if key != "sha256"}) != split.get("sha256")):
            raise ValueError("bounded exact 60000-normal calibration split required")
        rows = []
        for shard in split["shards"]:
            if (not isinstance(shard, dict) or not isinstance(shard.get("path"), str) or shard["path"] in paths
                    or not shard["path"].startswith("shards/expanded-calibration-" + cohort.lower() + "-")
                    or any(type(shard.get(key)) is not int for key in ("records", "normal", "positive"))):
                raise ValueError("unique exact-integer calibration shard descriptor required")
            paths.add(shard["path"])
            data = private_read(root, shard["path"], MAX_SHARD_BYTES)
            if hashlib.sha256(data).hexdigest() != shard.get("sha256"):
                raise ValueError("expanded numeric calibration shard checksum mismatch")
            selected = parse_json(data)
            stats = validate_rows(selected, 4)
            if (any(shard.get(key) != value for key, value in stats.items()) or stats["positive"]
                    or stats["cohorts"] != {cohort: stats["records"]}):
                raise ValueError("actual expanded calibration rows differ from normal/cohort contract")
            for row in selected:
                at = utc(row["window_start"])
                key = (row["account_id"], at.strftime("%Y-%m-%dT%H"))
                if row["frame_id"] in frame_ids or key in account_hours:
                    raise ValueError("duplicate calibration frame/account-hour refused")
                if (not utc("2026-05-03T00:00:00Z") <= at <= utc("2026-05-05T23:00:00Z")
                        or (at - utc("2026-04-15T12:00:00Z")).total_seconds() <= 14 * 86400
                        or (utc("2026-05-21T00:00:00Z") - at).total_seconds() <= 14 * 86400
                        or cohort == "COLD" and not 3 <= row["trusted_window_count"] <= 22):
                    raise ValueError("frozen calibration chronology/history applicability required")
                frame_ids.add(row["frame_id"])
                account_hours.add(key)
            rows.extend(selected)
            if len(rows) > ROWS_PER_COHORT:
                raise ValueError("expanded calibration row bound exceeded")
        if (len(rows) != ROWS_PER_COHORT or min(row["window_start"] for row in rows) != split["from"]
                or max(row["window_start"] for row in rows) != split["to"]):
            raise ValueError("complete expanded calibration count/date conservation required")
        buckets[cohort] = rows
    return buckets, manifest
