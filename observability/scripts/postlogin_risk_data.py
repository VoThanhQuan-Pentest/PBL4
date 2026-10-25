"""Deterministic, quota-stratified source for the declared observable context task.

Sampling is explicitly synthetic and stratified, not real-world prevalence.
Accepted labels are computed from actual raw pre-attempt observations, never
from the original simulator's planned cause. Legitimate burst counterparts are
included in review-context strata and keep their original planned labels.
"""
from collections import Counter
from datetime import timedelta

from postlogin_risk_contract import FAMILIES, reference
from postlogin_risk_rolling import expected_rolling

DATASET_ID = "postlogin-observable-context-20261020-v2"
NORMAL_CAUSES = ("normal", "benign_missing_metadata", "benign_operational_errors", "benign_login_only_retries")
COUNTERPARTS = {"request_burst": "benign_heavy_burst", "endpoint_scan": "benign_endpoint_traversal",
                "auth_failure_burst": "benign_retries", "sensitive_action_burst": "benign_password_maintenance",
                "http_error_burst": "benign_expected_degradation"}
COUNTS = {"fit": 4000, "calibration": 10000, "validation": 21000}
MAXIMUM_ATTEMPTS_PER_ROW = 1024


def protocol():
    return {"dataset_id": DATASET_ID, "split_counts": COUNTS,
            "fit_context_counts": {"0": 3000, "1": 800, "2": 200}, "shared_normal_fit": 2000,
            "calibration_normal": {"READY": 5000, "COLD": 5000},
            "validation": {"normal": 20000, "positive": 1000, "each_family": 200},
            "normal_generation_causes": list(NORMAL_CAUSES), "positive_counterparts": COUNTERPARTS,
            "positive_cause_selection": "alternate planned family and its legitimate counterpart by row parity",
            "sampling": "PREDECLARED_REFERENCE_CONTEXT_STRATIFICATION_NOT_REAL_PREVALENCE",
            "maximum_attempts_per_row": MAXIMUM_ATTEMPTS_PER_ROW,
            "ready_account_sampling": "SKIP_RESERVED_ACCOUNT_HOURS_BEFORE_BOUNDED_WORLD_VARIANTS_V2",
            "old_data_modified": False, "uncovered_worlds": "COUNT_AND_RETAIN_DIAGNOSTIC_DIGEST_NOT_FIT",
            "current_outcome": "UNOBSERVED_NOT_USED"}


class Sampler:
    def __init__(self, data, fold, split, fit_accounts=()):
        data.DATASET_ID = DATASET_ID  # New namespace; frozen generator bytes remain untouched.
        self.data, self.fold, self.split = data, fold, split
        self.specifications = list(data.specifications(fold, split))
        self.fit_accounts = list(fit_accounts)
        self.used = set()
        self.rejected = Counter()

    def remember(self, row):
        key = (row["source_account_ordinal"], row["source_window_start"])
        if key in self.used:
            raise ValueError("duplicate account-hour in committed split")
        self.used.add(key)

    def desired(self, index):
        if self.split == "calibration" or index < (3000 if self.split == "fit" else 20000):
            return "normal"
        return FAMILIES[(index - (3000 if self.split == "fit" else 20000)) // 200]

    def select(self, index):
        template = self.specifications[index]
        wanted = self.desired(index)
        cause = NORMAL_CAUSES[index % len(NORMAL_CAUSES)] if wanted == "normal" else (
            wanted if index % 2 == 0 else COUNTERPARTS[wanted])
        available_ready = []
        if self.split != "fit" and template["cohort"] == "READY":
            if len(self.fit_accounts) != 4000:
                raise ValueError("READY source requires the actual 4000 accepted FIT account ordinals")
            for step in range(4000):
                account = self.fit_accounts[(index + step * 997) % 4000]
                if (account, template["window_start"]) not in self.used:
                    available_ready.append(account)
                    if len(available_ready) == 64:
                        break
            if not available_ready:
                raise ValueError("READY_ACCOUNT_HOUR_CAPACITY_EXHAUSTED")
        for trial in range(MAXIMUM_ATTEMPTS_PER_ROW):
            if self.split == "fit":
                account = index * 16 + trial % 16
            elif template["cohort"] == "READY":
                account = available_ready[(trial // 16) % len(available_ready)]
            else:
                bank = 200000 if self.split == "calibration" else 400000 if template["cohort"] == "UNSEEN_READY" else 800000
                account = bank + self.data.original.stable_seed(DATASET_ID, self.fold, self.split, index, trial) % 100000
            episode = index // 4000 + trial // 16
            spec = {**template, "account": account, "episode": episode, "cause": cause}
            if (account, spec["window_start"]) in self.used:
                self.rejected["ACCOUNT_HOUR_ALREADY_ACCEPTED"] += 1
                continue
            raw, old = self.data.build(spec)
            target = reference(raw)
            if target["coverage"] != "COVERED" or target["family"] != wanted:
                self.rejected["UNDETERMINED" if target["coverage"] != "COVERED" else target["family"]] += 1
                continue
            metadata = {**old, "legacy_planned_label": old["label"],
                        "legacy_planned_family": old["family"], "legacy_planned_training_context": old["training_context"],
                        "label": target["label"], "training_context": target["training_context"], "family": target["family"],
                        "task_id": "postlogin-observable-risk-context-v1", "feature_schema_version": 6, "recipe_version": 5,
                        "source_account_ordinal": account, "source_episode_ordinal": episode,
                        "selection_attempts": trial + 1, "reference": target,
                        "expected_rolling": expected_rolling(raw)}
            self.used.add((account, spec["window_start"]))
            return spec, raw, metadata
        raise ValueError("bounded source stratum cannot be satisfied; do not change rubric or fill missing rows")


def stratum_population():
    result = {"READY/normal": 22000, "COLD/normal": 7000, "UNSEEN_READY/normal": 4000}
    for family in FAMILIES:
        result.update({"READY/" + family: 340, "UNSEEN_READY/" + family: 40, "COLD/" + family: 20})
    return result


def benchmark_indices(data):
    specs = list(data.specifications(1, "validation"))
    result = {}
    for cohort in ("READY", "UNSEEN_READY", "COLD"):
        for family in ("normal", *FAMILIES):
            matches = [s["index"] for s in specs if s["cohort"] == cohort
                       and (s["index"] < 20000 if family == "normal" else
                            s["index"] >= 20000 and FAMILIES[(s["index"] - 20000) // 200] == family)]
            result[cohort + "/" + family] = matches[:20]
    if any(len(v) != 20 for v in result.values()):
        raise ValueError("all 18 representative source strata require twenty accepted rows")
    return result
