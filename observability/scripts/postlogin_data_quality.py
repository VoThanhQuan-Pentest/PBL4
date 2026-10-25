"""Audit committed before-action pilot data without fitting or opening holdout.

Labels remain planned simulation contexts. Exact numeric collisions bound only
this empirical population; they do not establish real-world identifiability.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
import math
from pathlib import Path

from ueba_research_artifacts import commit, digest, private_directory

COUNTS = {"fit": 4000, "calibration": 10000, "validation": 21000}
WIDTH = 57


def read(path, maximum=1024 * 1024):
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > maximum
            or path.stat().st_mode & 0o077):
        raise ValueError("bounded owner-private source file required")
    return json.loads(path.read_text(), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def features(row, width=WIDTH):
    a, b = row["baseline_features"], row["postlogin_features"]
    if len(a) != 37 or len(b) != 20:
        raise ValueError("exact existing baseline37/postlogin20 required")
    values = a + b
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
        raise ValueError("finite numeric features required")
    if row["training_context"] not in (0, 1, 2) or row["label"] != int(row["training_context"] != 0):
        raise ValueError("planned context/label inconsistency")
    return tuple(float(v) for v in values[:width])


def load_split(source, split, protocol_sha256, expected_count=None):
    if split not in COUNTS:
        raise ValueError("only FIT/calibration/validation are admitted; no holdout access")
    expected_count = COUNTS[split] if expected_count is None else expected_count
    rows, hashes = [], []
    for offset in range(0, expected_count, 32):
        phase = f"source-f1-{split}-{offset // 32:04d}"
        marker = read(source / (phase + ".commit.private.json"))
        if marker["receipt"] != phase + ".receipt.private.json":
            raise ValueError("source receipt reference changed")
        receipt = source / marker["receipt"]
        if digest(receipt) != marker["receipt_sha256"]:
            raise ValueError("source receipt checksum changed")
        data = read(receipt)
        binding = {"protocol_sha256": protocol_sha256, "fold": 1, "split": split,
                   "offset": offset, "count": min(32, expected_count - offset)}
        if data["binding"] != binding or len(data["rows"]) != binding["count"]:
            raise ValueError("source split/count/protocol binding changed")
        for row in data["rows"]:
            features(row)
        rows.extend(data["rows"])
        hashes.append(digest(source / (phase + ".commit.private.json")))
    return rows, hashes


def collision_report(rows, width):
    groups = defaultdict(lambda: Counter())
    for row in rows:
        # READY and UNSEEN_READY use the same established-baseline policy.
        key = (row["baseline_established"], features(row, width))
        groups[key][row["label"]] += 1
    mixed = [c for c in groups.values() if c[0] and c[1]]
    normal = sum(r["label"] == 0 for r in rows)
    positive = len(rows) - normal
    fp_budget = max(0, math.ceil(normal * .001) - 1)  # strict FPR < 0.1%
    best = [0] * (fp_budget + 1)
    pure_positive = sum(c[1] for c in groups.values() if not c[0])
    for counts in mixed:
        cost, reward = counts[0], counts[1]
        if cost <= fp_budget:
            for allowance in range(fp_budget, cost - 1, -1):
                best[allowance] = max(best[allowance], best[allowance - cost] + reward)
    maximum_tp = pure_positive + max(best)
    return {"feature_width": width, "distinct_vectors_with_policy_cohort": len(groups),
            "opposite_binary_label_groups": len(mixed),
            "rows_in_opposite_label_groups": sum(sum(c.values()) for c in mixed),
            "unavoidable_errors_if_one_decision_per_vector": sum(min(c[0], c[1]) for c in mixed),
            "normal_rows": normal, "positive_rows": positive, "strict_fp_budget_for_this_sample": fp_budget,
            "empirical_oracle_maximum_tp_at_fpr_budget": maximum_tp,
            "empirical_oracle_recall_upper_bound": maximum_tp / positive if positive else None,
            "scope": "Exact empirical vector groups only; ignores generalization and precision constraints."}


def audit(splits):
    sets = {kind: [] for kind in ("frame", "session", "context", "account_hour")}
    report = {"splits": {}, "warnings": []}
    for split in COUNTS:
        rows = splits[split]
        frames = {r["frame_id"] for r in rows}
        hours = {(r["account_id"], r["as_of"][:13]) for r in rows}
        if len(frames) != len(rows) or len(hours) != len(rows):
            raise ValueError("duplicate frame or account-hour")
        for kind, values in (("frame", frames), ("session", {v for r in rows for v in r["session_fingerprints"]}),
                             ("context", {v for r in rows for v in r["context_frame_ids"]}), ("account_hour", hours)):
            if any(values & previous for previous in sets[kind]):
                raise ValueError(f"cross-split {kind} leakage")
            sets[kind].append(values)
        numeric = [features(r) for r in rows]
        columns = list(zip(*numeric))
        report["splits"][split] = {"rows": len(rows), "labels": dict(Counter(r["training_context"] for r in rows)),
            "cohorts": dict(Counter(r["cohort"] for r in rows)),
            "families": dict(Counter(r["family"] for r in rows if r["label"])),
            "time_min": min(r["as_of"] for r in rows), "time_max": max(r["as_of"] for r in rows),
            "constant_feature_indices": [i for i, c in enumerate(columns) if min(c) == max(c)],
            "column_stats": [{"index": i, "min": min(c), "max": max(c), "distinct": len(set(c))}
                             for i, c in enumerate(columns)],
            "baseline37": collision_report(rows, 37), "candidate57": collision_report(rows, 57)}
    dt = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))
    for before, after in (("fit", "calibration"), ("calibration", "validation")):
        if (dt(report["splits"][after]["time_min"]) - dt(report["splits"][before]["time_max"])).total_seconds() <= 14 * 86400:
            raise ValueError("chronological gap is not greater than fourteen days")
    fitted = {r["account_id"] for r in splits["fit"]}
    if fitted & {r["account_id"] for r in splits["validation"] if r["cohort"] == "UNSEEN_READY"}:
        raise ValueError("UNSEEN account entered FIT")
    report["status"] = "DATA_AUDIT_COMPLETE_NOT_TRAINING_OR_QUALITY_ADMISSION"
    report.update(new_fits=0, holdout_scored=False, auto_containment=False, aws_changed=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = private_directory(args.source), private_directory(args.output)
    protocol_sha = digest(source / "pilot.protocol.private.json")
    source_binding_sha = read(source / "pilot.protocol.private.json")["source_binding_sha256"]
    if digest(source / "pilot.source.identity.private.json") != source_binding_sha:
        raise ValueError("source identity differs from the frozen training protocol")
    splits, hashes = {}, {}
    for split in COUNTS:
        splits[split], hashes[split] = load_split(source, split, source_binding_sha)
    report = audit(splits)
    report.update(source_protocol_sha256=protocol_sha, source_identity_sha256=source_binding_sha, source_commit_hashes=hashes,
                  script_sha256=digest(Path(__file__)))
    marker = commit(output, report, phase="pilot-data-quality")
    print(json.dumps({"status": report["status"], "receipt": marker,
                      "validation": report["splits"]["validation"]["candidate57"]}, sort_keys=True))


if __name__ == "__main__":
    main()
