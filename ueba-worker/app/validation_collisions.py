"""Bounded, aggregate-only necessary conditions from validation input collisions.

No forest, cached scores, fitting/calibration rows or numeric holdout rows are
loaded. The label-aware oracle can distinguish every unequal input perfectly;
it is deliberately more powerful than a trained forest, not a quality result.
"""

import argparse
from collections import Counter, defaultdict
from importlib.metadata import distribution, version
import hashlib
from pathlib import Path
import platform
import re

import numpy as np

from app.catalog import ShardedDataset
from app.contract import FEATURE_NAMES_V2
from app.policy import canonical

MAX_POSITIVES = 1000
MAX_RECORDS = 1_001_000
VALIDATION_SPLITS = tuple(f"fold{fold}-validation" for fold in (1, 2, 3))
REPRESENTATIONS = ("float64", "float32")
PRECISION_NUMERATOR = 998
PRECISION_DENOMINATOR = 1000
FP_TP_RATIO = 499
SOURCE_FILES = ("validation_collisions.py", "catalog.py", "contract.py", "policy.py", "strict_metrics.py", "model.py")


def _matrices(rows):
    """Normalize signed zero: a tree cannot distinguish +0 from -0."""
    f64 = np.asarray([row["features"] for row in rows], dtype="<f8")
    f64[f64 == 0] = 0
    f32 = f64.astype("<f4")
    f32[f32 == 0] = 0
    return {"float64": f64, "float32": f32}


def _key(row, vector):
    # The actual calibrated model uses one READY bucket for READY/UNSEEN_READY.
    return ("COLD" if row["cohort"] == "COLD" else "READY", vector.tobytes())


def oracle_bound(groups, positives):
    """Exact 0/1 knapsack on positive-bearing keys, never on individual rows.

    Each group is (TP gain, unavoidable FP cost). Precision >= 998/1000 is
    exactly TP >= 499*FP. P//499 is only a relaxed necessary FP budget; the
    actual feasible bound also checks the selected subset's own TP count.
    """
    if type(positives) is not int or not 1 <= positives <= MAX_POSITIVES:
        raise ValueError("positive population must be 1..1000")
    groups = list(groups)
    if (not groups or len(groups) > positives
            or any(type(p) is not int or p < 1 or type(n) is not int or n < 0 for p, n in groups)
            or sum(p for p, _ in groups) != positives):
        raise ValueError("positive-bearing groups must conserve the positive population")
    budget = positives // FP_TP_RATIO
    dp = [-1] * (budget + 1)
    dp[0] = 0
    for gain, cost in groups:
        if cost > budget:
            continue
        for spent in range(budget, cost - 1, -1):
            if dp[spent - cost] >= 0:
                dp[spent] = max(dp[spent], dp[spent - cost] + gain)
    optimistic_tp = max(dp)
    optimistic_fp = next(cost for cost, tp in enumerate(dp) if tp == optimistic_tp)
    feasible = [(tp, cost) for cost, tp in enumerate(dp) if tp > 0 and tp >= FP_TP_RATIO * cost]
    feasible_tp, feasible_fp = max(feasible, key=lambda item: (item[0], -item[1])) if feasible else (0, 0)
    return {
        "precision_requirement": {"numerator": PRECISION_NUMERATOR, "denominator": PRECISION_DENOMINATOR},
        "necessary_fp_budget_from_total_positives": budget,
        "optimistic_relaxed_max_tp": optimistic_tp,
        "optimistic_relaxed_max_recall": optimistic_tp / positives,
        "optimistic_relaxed_min_fp_at_max_tp": optimistic_fp,
        "relaxed_max_satisfies_its_own_precision": optimistic_tp > 0 and optimistic_tp >= FP_TP_RATIO * optimistic_fp,
        "precision_feasible_max_tp": feasible_tp,
        "precision_feasible_max_recall": feasible_tp / positives,
        "precision_feasible_min_fp_at_max_tp": feasible_fp,
        "precision_at_feasible_max": feasible_tp / (feasible_tp + feasible_fp) if feasible_tp else None,
        "any_nonempty_precision_feasible_subset": bool(feasible),
        "global_recall_strictly_above_99_percent_necessary_condition": feasible_tp * 100 > positives * 99,
        "exact_cost_frontier": [{"fp": cost, "max_tp": tp if tp >= 0 else None,
                                 "satisfies_precision": tp > 0 and tp >= FP_TP_RATIO * cost}
                                for cost, tp in enumerate(dp)],
    }


def _summary(groups, positive_details, normals, positives):
    mixed = [key for key in groups if normals[key] > 0]
    collision_families = Counter()
    collision_cohorts = Counter()
    positive_families = Counter()
    positive_cohorts = Counter()
    forced_missed_families = Counter()
    forced_missed_cohorts = Counter()
    necessary_fp_budget = positives // FP_TP_RATIO
    histogram = Counter()
    for key, count in groups.items():
        local = positive_details[key]
        if sum(local["families"].values()) != count or sum(local["cohorts"].values()) != count:
            raise ValueError("positive key slice details do not conserve positives")
        positive_families.update(local["families"])
        positive_cohorts.update(local["cohorts"])
        histogram[(count, normals[key])] += 1
        if normals[key]:
            collision_families.update(local["families"])
            collision_cohorts.update(local["cohorts"])
        if normals[key] > necessary_fp_budget:
            # One such key alone exceeds the necessary GLOBAL precision FP
            # budget. Every positive in the key is therefore forced missed.
            forced_missed_families.update(local["families"])
            forced_missed_cohorts.update(local["cohorts"])
    forced_missed = sum(groups[key] for key in groups if normals[key] > necessary_fp_budget)
    if (sum(positive_families.values()) != positives or sum(positive_cohorts.values()) != positives
            or sum(forced_missed_families.values()) != forced_missed
            or sum(forced_missed_cohorts.values()) != forced_missed):
        raise ValueError("positive slice totals do not conserve the observed population")

    def slice_bounds(populations, misses):
        return {name: {"positive_samples": population, "forced_missed_positives": misses[name],
                       "max_recalled_positives": population - misses[name],
                       "recall_upper_bound": (population - misses[name]) / population,
                       "strict_recall_above_99_percent_necessary_condition":
                           (population - misses[name]) * 100 > population * 99}
                for name, population in sorted(populations.items())}

    family_bounds = slice_bounds(positive_families, forced_missed_families)
    cohort_bounds = slice_bounds(positive_cohorts, forced_missed_cohorts)
    collided_positive = sum(groups[key] for key in mixed)
    return {
        "positive_input_keys": len(groups),
        "mixed_label_input_keys": len(mixed),
        "positive_rows_in_mixed_keys": collided_positive,
        "normal_rows_in_mixed_keys": sum(normals[key] for key in mixed),
        "positive_rows_without_normal_match": positives - collided_positive,
        "collision_positive_rows_by_family": dict(sorted(collision_families.items())),
        "collision_positive_rows_by_actual_cohort": dict(sorted(collision_cohorts.items())),
        "positive_population_by_family": dict(sorted(positive_families.items())),
        "positive_population_by_actual_cohort": dict(sorted(positive_cohorts.items())),
        "slice_necessary_conditions": {
            "conclusion_scope": "NECESSARY_CONDITION_ONLY",
            "necessary_global_fp_budget": necessary_fp_budget,
            "slice_recall_requirement": {"numerator": 99, "denominator": 100, "strict": True},
            "forced_excluded_input_keys": sum(normals[key] > necessary_fp_budget for key in groups),
            "forced_missed_positive_rows": forced_missed,
            "by_family": family_bounds, "by_actual_cohort": cohort_bounds,
            "any_observed_slice_provably_fails_strict_recall_requirement": any(
                not row["strict_recall_above_99_percent_necessary_condition"]
                for row in (*family_bounds.values(), *cohort_bounds.values())),
            "limitation": "Conservative upper bounds ignore further precision, score ordering and joint-slice constraints; not trained-model recall."},
        "positive_key_population_histogram": [
            {"positive_rows_per_key": p, "normal_rows_per_key": n, "input_keys": count}
            for (p, n), count in sorted(histogram.items())],
        "oracle": oracle_bound([(p, normals[key]) for key, p in groups.items()], positives),
    }


def collision_split(dataset, name, *, progress=None):
    """Only positive descriptors in pass 1; all validation shards in pass 2."""
    if name not in VALIDATION_SPLITS:
        raise ValueError("only fold1..3-validation numeric records may be read")
    split = dataset.split(name)
    if not 1 <= split["positive"] <= MAX_POSITIVES or not 1 <= split["records"] <= MAX_RECORDS:
        raise ValueError("validation population exceeds diagnostic bound")
    positive_keys = {representation: Counter() for representation in REPRESENTATIONS}
    details = {representation: defaultdict(lambda: {"families": Counter(), "cohorts": Counter()})
               for representation in REPRESENTATIONS}
    pass1_records = pass1_shards = pass1_positives = 0
    for number, descriptor in enumerate(split["shards"]):
        if not descriptor["positive"]:
            continue
        _, rows = dataset.load_shard(name, number)
        matrices = _matrices(rows)
        for index, row in enumerate(rows):
            if row["label"] != 1:
                continue
            pass1_positives += 1
            if pass1_positives > MAX_POSITIVES:
                raise ValueError("actual positive population exceeds diagnostic bound")
            for representation in REPRESENTATIONS:
                key = _key(row, matrices[representation][index])
                positive_keys[representation][key] += 1
                details[representation][key]["families"][row["family"]] += 1
                details[representation][key]["cohorts"][row["cohort"]] += 1
        pass1_records += len(rows)
        pass1_shards += 1
    if pass1_positives != split["positive"]:
        raise ValueError("positive-descriptor pass does not conserve positives")
    normal_matches = {representation: Counter() for representation in REPRESENTATIONS}
    verified_positive_keys = {representation: Counter() for representation in REPRESENTATIONS}
    totals = Counter()
    families = Counter()
    cohorts = Counter()
    positive_families = Counter()
    positive_cohorts = Counter()
    verified_paths = []
    for descriptor, rows in dataset.iter_shards(name):
        matrices = _matrices(rows)
        totals["records"] += len(rows)
        for index, row in enumerate(rows):
            totals["normal" if row["label"] == 0 else "positive"] += 1
            families[row["family"]] += 1
            cohorts[row["cohort"]] += 1
            if row["label"] == 1:
                positive_families[row["family"]] += 1
                positive_cohorts[row["cohort"]] += 1
            for representation in REPRESENTATIONS:
                key = _key(row, matrices[representation][index])
                if key in positive_keys[representation]:
                    if row["label"] == 0:
                        normal_matches[representation][key] += 1
                    else:
                        verified_positive_keys[representation][key] += 1
                elif row["label"] == 1:
                    raise ValueError("positive input changed between validation passes")
        verified_paths.append({key: descriptor[key] for key in ("path", "sha256", "records", "normal", "positive")})
        if progress:
            progress({"split": name, "phase": "VERIFY_ALL_VALIDATION_SHARDS", "records_verified": totals["records"],
                      "shards_verified": len(verified_paths)})
    actual = {key: totals[key] for key in ("records", "normal", "positive")}
    actual.update(families=dict(sorted(families.items())), cohorts=dict(sorted(cohorts.items())))
    if any(split[key] != value for key, value in actual.items()):
        raise ValueError("actual validation totals differ from manifest")
    if any(verified_positive_keys[representation] != positive_keys[representation] for representation in REPRESENTATIONS):
        raise ValueError("positive inputs differ between validation passes")
    representations = {representation: _summary(positive_keys[representation], details[representation],
                                                 normal_matches[representation], totals["positive"])
                       for representation in REPRESENTATIONS}
    for summary in representations.values():
        if (summary["positive_population_by_family"] != dict(positive_families)
                or summary["positive_population_by_actual_cohort"] != dict(positive_cohorts)):
            raise ValueError("positive slice populations differ between validation passes")
    actual.update(positive_by_family=dict(sorted(positive_families.items())),
                  positive_by_actual_cohort=dict(sorted(positive_cohorts.items())))
    return {
        "split": name, "split_sha256": split["sha256"], "actual_population_verified": actual,
        "pass1": {"numeric_shards_read": pass1_shards, "numeric_records_read": pass1_records,
                  "positives_collected": pass1_positives, "normal_only_descriptors_skipped": len(split["shards"]) - pass1_shards},
        "pass2": {"numeric_shards_read": len(verified_paths), "numeric_records_read": totals["records"],
                  "checksum_and_row_contract_verified_paths": verified_paths},
        "representations": representations,
    }


def _bounded_source_hash(path, maximum=512 * 1024):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular diagnostic source file required")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("diagnostic source file exceeds bound")
    return hashlib.sha256(data).hexdigest()


def source_binding():
    directory = Path(__file__).resolve().parent
    files = {"app/" + name: _bounded_source_hash(directory / name) for name in SOURCE_FILES}
    sklearn_path = Path(distribution("scikit-learn").locate_file("sklearn/ensemble/_iforest.py"))
    return {"source_files_sha256": files,
            "source_binding_sha256": hashlib.sha256(canonical(files).encode()).hexdigest(),
            "runtime": {"python": platform.python_version(), "numpy": np.__version__,
                        "scikit_learn": version("scikit-learn"),
                        "sklearn_iforest_source_sha256": _bounded_source_hash(sklearn_path)}}


def diagnose(dataset, names=VALIDATION_SPLITS, *, progress=None):
    names = tuple(names)
    if not names or len(names) > 3 or len(set(names)) != len(names) or any(name not in VALIDATION_SPLITS for name in names):
        raise ValueError("one to three distinct validation splits required")
    initial_binding = source_binding()
    results = [collision_split(dataset, name, progress=progress) for name in names]
    ShardedDataset(dataset.root, expected_sha256=dataset.sha256)
    if source_binding() != initial_binding:
        raise ValueError("diagnostic source changed during evidence collection")
    return {
        "diagnostic_schema_version": 2, "diagnostic": "VALIDATION_EXACT_INPUT_COLLISIONS",
        "data_provenance": "DEMO_ONLY", "quality_gate": "NOT_APPLICABLE",
        "conclusion_scope": "NECESSARY_CONDITION_ONLY", "prediction_scope": "MODEL_ONLY",
        "dataset_id": dataset.manifest["dataset_id"], "dataset_manifest_sha256": dataset.sha256,
        "dataset_stage": dataset.manifest["stage"], "feature_schema_version": 2,
        "feature_count": len(FEATURE_NAMES_V2), **initial_binding,
        "boundaries": {"allowed_numeric_splits": list(names), "max_positives_per_split": MAX_POSITIVES,
                       "max_records_per_split": MAX_RECORDS, "max_knapsack_fp_budget": MAX_POSITIVES // FP_TP_RATIO,
                       "numeric_holdout_records_read": 0, "fit_or_calibration_records_read": 0,
                       "fit_calls": 0, "model_artifacts_loaded": 0, "model_activations": 0,
                       "account_ids_or_input_vectors_emitted": False},
        "key_semantics": {"float64": "all 15 validated float64 features plus actual calibration cohort",
                          "float32": "all 15 features after sklearn IsolationForest float32 conversion plus actual calibration cohort",
                          "calibration_cohort": {"COLD": "COLD", "READY": "READY", "UNSEEN_READY": "READY"},
                          "signed_zero": "canonicalized because trees cannot distinguish signed zero"},
        "limitations": ["Label-aware oracle, not a fitted or deployable model; it may reject every unequal normal input perfectly.",
                        "Identical keys force identical MODEL_ONLY decisions; unequal keys may still receive identical forest scores.",
                        "The oracle is not the ordered score/percentile threshold policy and does not evaluate SIEM_FINAL rules.",
                        "Global oracle feasibility does not establish slice recall; conservative forced-exclusion slice bounds can only disprove necessary recall conditions.",
                        "Passing any necessary condition does not establish uncertainty bounds or quality qualification.",
                        "Validation populations only; no numeric holdout evaluation or production/shadow evidence.",
                        "Checksums, per-shard row contract and observed totals are verified; cross-shard identity uniqueness is not independently re-proved."],
        "splits": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="fresh evidence directory outside the dataset")
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--splits", nargs="+", choices=VALIDATION_SPLITS, default=VALIDATION_SPLITS)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{64}", args.expected_manifest_sha256):
        parser.error("expected manifest SHA256 must be 64 lowercase hexadecimal characters")
    dataset = ShardedDataset(args.dataset, expected_sha256=args.expected_manifest_sha256)
    output = args.output
    if output.is_symlink() or output.exists() or output.resolve().is_relative_to(dataset.root):
        parser.error("a fresh non-symlink evidence directory outside the dataset is required")
    if any(parent.is_symlink() for parent in output.parents):
        parser.error("evidence directory parents must not be symlinks")
    output.mkdir(mode=0o700)
    def progress(value):
        if value["shards_verified"] % 20 == 0:
            print(canonical(value), flush=True)
    evidence = diagnose(dataset, args.splits, progress=progress)
    target = output / "validation-collisions.json"
    with target.open("x") as stream:
        target.chmod(0o600)
        stream.write(canonical(evidence) + "\n")
    print(canonical({"status": "COMPLETE", "artifact": str(target), "artifact_sha256": _bounded_source_hash(target, 2 * 1024 * 1024),
                     "quality_gate": "NOT_APPLICABLE", "conclusion_scope": "NECESSARY_CONDITION_ONLY"}), flush=True)


if __name__ == "__main__":
    main()
