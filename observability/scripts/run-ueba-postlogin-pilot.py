#!/usr/bin/env python3
"""Serial PILOT_ONLY research with fixed data, one candidate and durable units.

Strict campaign/selection/adoption are deliberately separate. Launch inside the
pinned network-disabled image and an independent whole-job OS timeout.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import hashlib
import io
import json
import math
import os
import resource
from pathlib import Path
import shutil
import signal
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish
from postlogin_pilot_artifacts import publish_bundle, read_bundle, writer
from postlogin_pilot_source import classpath, load_split, read_committed
import postlogin_pilot_data as data


class BudgetStop(Exception): pass


def result_phase(status):
    if status in ("STOP_AT_COMMITTED_FIT_BOUNDARY", "STOP_QUOTA_RESERVE"):
        return "pilot-checkpoint-" + str(time.time_ns())
    return "pilot-result"


class Budget:
    def __init__(self, output):
        self.output = output; self.path = output / "pilot-budget.private.json"
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            if self.state.get("active_unit"):
                # The writer lock is already acquired. The previous writer is
                # gone; conservatively charge its complete declared unit cap.
                self.state["elapsed_seconds"] += self.state["active_unit"]["cap_seconds"]
                self.state["recovered_interrupted_units"] += 1
                self.state["active_unit"] = None
        else:
            benchmark = json.loads((output / "p3-source-benchmark.receipt.private.json").read_text())
            self.state = {"elapsed_seconds": benchmark["elapsed_seconds"], "cap_seconds": 7200,
                          "composite_invocations": 0, "component_invocations_recorded_before_call": 0,
                          "recovered_interrupted_units": 0, "active_unit": None}
        self.state.setdefault("phase_elapsed_seconds", {})
        self.started = None; self.last_accounted = time.monotonic(); self.save()

    def account(self):
        now = time.monotonic()
        self.state["elapsed_seconds"] += now - self.last_accounted
        self.last_accounted = now

    def save(self):
        self.account()
        publish(self.path, self.state)
        state = json.loads((self.output / "operator-state.private.json").read_text())
        state.update(phase="P3_P4_PILOT_ONLY", pilot_budget=self.state,
                     active_handle={"kind": "docker", "name": "flare-ueba-postlogin-pilot-r2"})
        publish(self.output / "operator-state.private.json", state)

    def check(self):
        self.account()
        used = self.state["elapsed_seconds"]
        if used >= self.state["cap_seconds"]: raise BudgetStop("STOP_BUDGET")
        if shutil.disk_usage(self.output).free < 5_000_000_000: raise BudgetStop("STOP_DISK_RESERVE")
        allocated = sum(p.stat().st_size for p in self.output.rglob("*") if p.is_file())
        if allocated > 2 * 1024**3: raise BudgetStop("STOP_OUTPUT_BYTE_CAP")
        hold = self.output / "operator-hold.private.json"
        if hold.exists() and json.loads(hold.read_text()).get("hold_new_units"): raise BudgetStop("STOP_QUOTA_RESERVE")

    def begin(self, unit, *, seconds=900, composite=False):
        self.check()
        if composite:
            if self.state["composite_invocations"] >= 7: raise BudgetStop("STOP_FIT_CAP")
            self.state["composite_invocations"] += 1
        self.state["active_unit"] = {"id": unit, "cap_seconds": seconds, "started_at_utc": datetime.now(timezone.utc).isoformat()}
        self.started = time.monotonic(); self.save()
        # Kernel termination also works while Python is inside a native fit.
        # Completed bundles remain durable; no handler is required for recovery.
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(max(1, min(seconds, math.floor(self.state["cap_seconds"] - self.state["elapsed_seconds"])) ))

    def component(self):
        if self.state["component_invocations_recorded_before_call"] >= 14: raise BudgetStop("STOP_COMPONENT_FIT_CAP")
        self.state["component_invocations_recorded_before_call"] += 1; self.save()

    def finish(self, unit, proof):
        signal.alarm(0)
        elapsed = time.monotonic() - self.started
        phase = unit.split("-", 1)[0]
        self.state["phase_elapsed_seconds"][phase] = self.state["phase_elapsed_seconds"].get(phase, 0) + elapsed
        self.state["last_unit_resources"] = {"unit": unit, "elapsed_seconds": round(elapsed, 6),
            "worker_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "child_peak_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
        self.started = None; self.state["active_unit"] = None
        self.state["last_verified_commit"] = {"unit": unit, **proof}; self.save()


def check_isolation(fitting, calibration, validation):
    frame_sets = []; context_sets = []; session_sets = []; episode_sets = []
    for rows in (fitting, calibration, validation):
        frames = {r["frame_id"] for r in rows}
        episodes = {(r["account_id"], r["as_of"][:13]) for r in rows}
        if len(frames) != len(rows) or len(episodes) != len(rows): raise ValueError("duplicate primary frame/account-hour")
        frame_sets.append(frames); episode_sets.append(episodes)
        context_sets.append({identity for r in rows for identity in r["context_frame_ids"]})
        session_sets.append({identity for r in rows for identity in r["session_fingerprints"]})
    for sets in (frame_sets, context_sets, session_sets, episode_sets):
        if any(sets[a] & sets[b] for a, b in ((0, 1), (0, 2), (1, 2))): raise ValueError("split isolation failed")
    fitted_accounts = {r["account_id"] for r in fitting}
    if fitted_accounts & {r["account_id"] for r in validation if r["cohort"] == "UNSEEN_READY"}: raise ValueError("unseen account entered FIT")
    if Counter(r["training_context"] for r in fitting) != {0: 3000, 1: 800, 2: 200}: raise ValueError("labeled FIT counts changed")
    if sum(r["normal_fit"] for r in fitting) != 2000: raise ValueError("normal shared FIT counts changed")


def matrix(rows, kind):
    import numpy as np
    return np.asarray([r["baseline_features"] + (r["postlogin_features"] if kind == "candidate" else []) for r in rows], dtype=np.float64)


def raw_scores(model, values):
    import numpy as np
    result = np.concatenate([model.anomaly_scores(values[i:i + 1000]) for i in range(0, len(values), 1000)])
    if not np.isfinite(result).all(): raise ValueError("invalid finite pilot scores")
    return result


def fitted_unit(output, fold, kind, fitting, calibration, binding, budget):
    import joblib
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from app.normal_support import NormalSupportScorer
    from postlogin_pilot_model import new_model
    unit = f"fit-fold{fold}-{kind}"
    retained = read_bundle(output, unit, binding, allow_unmarked=True)
    if retained is not None:
        publish_bundle(output, unit, binding, {})
        return retained
    budget.begin(unit, composite=True)
    component_count = 0
    original = {NormalSupportScorer: NormalSupportScorer.fit, HistGradientBoostingClassifier: HistGradientBoostingClassifier.fit}
    def wrap(cls):
        def invoke(self, *args, **kwargs):
            nonlocal component_count
            budget.component(); result = original[cls](self, *args, **kwargs); component_count += 1
            return result
        return invoke
    try:
        for cls in original: cls.fit = wrap(cls)
        model = new_model(kind)
        x = matrix(fitting, kind)
        labels = np.asarray([r["training_context"] for r in fitting], dtype=np.int64)
        fit_started = time.monotonic()
        model.fit(x[[i for i, r in enumerate(fitting) if r["normal_fit"]]], x, labels)
        fit_seconds = time.monotonic() - fit_started
    finally:
        for cls, method in original.items(): cls.fit = method
    if component_count != 2: raise ValueError("one composite must contain exactly two component fits")
    buckets = {}; calibration_started = time.monotonic()
    for cohort in ("READY", "COLD"):
        rows = [r for r in calibration if r["cohort"] == cohort]
        if len(rows) != 5000 or any(r["label"] for r in rows): raise ValueError("separate normal calibration required")
        buckets[cohort] = np.sort(raw_scores(model, matrix(rows, kind)))
    calibration_seconds = time.monotonic() - calibration_started
    blob = io.BytesIO(); joblib.dump({"model": model, "calibration": buckets}, blob, compress=3)
    # Own fresh bytes only: verify estimator/calibration readback before publishing.
    restored = joblib.load(io.BytesIO(blob.getvalue()))
    if not np.array_equal(raw_scores(model, x[:8]), raw_scores(restored["model"], x[:8])): raise ValueError("pilot model readback changed scores")
    metadata = {"applicability": "PILOT_ONLY_UNQUALIFIED", "model_kind": "normal_plus_incident_research",
        "recipe_version": 1 if kind == "baseline" else 2, "actual_composite_fits": 1, "actual_component_fit_calls": 2,
        "normal_fit": 2000, "labeled_fit": 4000, "shared_normal_fit": 2000, "calibration": {"READY": 5000, "COLD": 5000},
        "feature_columns": 37 if kind == "baseline" else 57, "holdout_scored": False, "auto_containment": False}
    metadata.update(fit_seconds=fit_seconds, calibration_seconds=calibration_seconds,
                    elapsed_seconds_before_publication=time.monotonic() - budget.started,
                    worker_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    contents = {"model.joblib": blob.getvalue(), "metadata.json": canonical(metadata).encode()}
    proof = publish_bundle(output, unit, binding, contents); budget.finish(unit, proof)
    del model, restored; gc.collect()
    return contents


def rule_decisions(output, fold, validation, source_sha, budget):
    import numpy as np
    from app.policy import ScorePolicy
    from app.risk_replay import JavaRiskReplay
    policy = ScorePolicy.strict(99_990_000, 99_999_500, 70, schema=4)
    unit = f"rules-fold{fold}-validation"
    binding = {"source_sha256": source_sha, "policy_sha256": policy.sha256,
               "workspace_identity_sha256": digest(output / "pilot-replay-java/identity.private.json")}
    retained = read_bundle(output, unit, binding, allow_unmarked=True)
    if retained is not None:
        publish_bundle(output, unit, binding, {})
        values = np.frombuffer(retained["rules.bin"], dtype=np.uint8)
        if values.shape != (len(validation),) or not np.isin(values, (0, 1)).all(): raise ValueError("rule cache shape changed")
        return values.astype(bool)
    budget.begin(unit)
    values = []
    with JavaRiskReplay(output / "pilot-replay-java", policy) as replay:
        for index in range(0, len(validation), 1000):
            rows = [{**r, "features": r["baseline_features"]} for r in validation[index:index + 1000]]
            scores = [{"raw_anomaly_score": 0.0, "normal_percentile": 0.0, "level": "NORMAL_RANGE"} for _ in rows]
            actual = replay.score(rows, scores)
            if any(r["predictions"]["MODEL_ONLY"] for r in actual): raise ValueError("rule-only replay contained ML")
            values.extend(r["predictions"]["SIEM_FINAL"] for r in actual)
    values = np.asarray(values, dtype=np.uint8)
    proof = publish_bundle(output, unit, binding, {"rules.bin": values.tobytes()}); budget.finish(unit, proof)
    return values.astype(bool)


def group_names(row):
    groups = ["global", "cohort/" + row["cohort"], "operation/" + row["current_operation"],
              "postlogin/OBSERVED" if row["postlogin_features"][3] else "postlogin/UNOBSERVED_LOGIN"]
    if row["label"]: groups.append("family/" + row["family"])
    if row["cohort"] == "COLD": groups.append("control/sparse_history")
    if not row["label"] and row["planned_cause"] == "benign_password_maintenance": groups.append("control/legitimate_sensitive_sequence")
    if not row["label"] and (row["baseline_features"][8] or row["baseline_features"][9]): groups.append("control/legitimate_new_client")
    if row["source_window_start"] != row["window_start"]: groups.append("context/window_boundary")
    return groups


def validation_counts(rows, model_predictions, rule_predictions):
    counts = {scope: {} for scope in ("MODEL_ONLY", "SIEM_FINAL")}
    for index, row in enumerate(rows):
        predictions = {"MODEL_ONLY": bool(model_predictions[index]), "SIEM_FINAL": bool(model_predictions[index] or rule_predictions[index])}
        for scope, predicted in predictions.items():
            category = ("tp" if predicted else "fn") if row["label"] else ("fp" if predicted else "tn")
            for group in group_names(row):
                counts[scope].setdefault(group, {key: 0 for key in ("tp", "fn", "fp", "tn")})[category] += 1
    return counts


def evaluated_unit(output, fold, kind, contents, validation, rules, binding, budget):
    import joblib
    import numpy as np
    unit = f"validation-fold{fold}-{kind}"
    retained = read_committed(output, unit)
    if retained is not None:
        if retained["binding"] != binding: raise ValueError("retained evaluation binding changed")
        return retained
    budget.begin(unit)
    payload = joblib.load(io.BytesIO(contents["model.joblib"]))
    values = raw_scores(payload["model"], matrix(validation, kind)); predicted = np.zeros(len(values), dtype=bool)
    for cohort, threshold in (("READY", 99.99), ("COLD", 99.9995)):
        mask = np.asarray([(r["cohort"] == "COLD") == (cohort == "COLD") for r in validation])
        calibration = payload["calibration"][cohort]
        selected = values[mask]
        percentiles = (np.searchsorted(calibration, selected, side="left") + np.searchsorted(calibration, selected, side="right")) / (2 * len(calibration)) * 100
        predicted[mask] = percentiles >= threshold
    receipt = {"binding": binding, "counts": validation_counts(validation, predicted, rules), "validation_rows": len(validation),
               "quality_gate": "NOT_APPLICABLE_PILOT_ONLY", "holdout_scored": False, "auto_containment": False}
    proof = commit(output, receipt, phase=unit); budget.finish(unit, proof)
    return receipt


def compare(baseline, candidate):
    reasons = []
    for scope in ("MODEL_ONLY", "SIEM_FINAL"):
        before, after = baseline["counts"][scope], candidate["counts"][scope]
        primary = before["postlogin/OBSERVED"]["fn"]
        reduction = primary - after["postlogin/OBSERVED"]["fn"]
        if primary < 3 or reduction < max(3, math.ceil(primary * 0.25)): reasons.append(scope + "/primary_delta")
        for group in before:
            if group not in after or after[group]["fp"] > before[group]["fp"] or after[group]["fn"] > before[group]["fn"]:
                reasons.append(scope + "/non_regression/" + group)
    return {"status": "GO" if not reasons else "STOP_NO_IMPROVEMENT", "reasons": reasons}


def run(output, maximum_new_fits):
    output = private_directory(output)
    protocol_path = output / "pilot.protocol.private.json"; protocol = json.loads(protocol_path.read_text())
    for name, expected in protocol["code_sha256"].items():
        if digest(Path(__file__).parent / name) != expected: raise ValueError("pilot code snapshot changed")
    if protocol["model_kind"] != "normal_plus_incident_research" or protocol["primary_goal"] != "REDUCE_FN_OBSERVED_POSTLOGIN":
        raise ValueError("predeclared model kind/primary goal required")
    protocol_sha = digest(protocol_path)
    with writer(output):
        budget = Budget(output); cp = classpath(output); new_fits = 0; outcomes = []
        try:
            for fold in (1, 2, 3):
                source_binding = protocol["source_binding_sha256"]
                fitting, fit_sha = load_split(output, fold, "fit", source_binding, budget, cp)
                calibration, cal_sha = load_split(output, fold, "calibration", source_binding, budget, cp)
                validation, val_sha = load_split(output, fold, "validation", source_binding, budget, cp)
                check_isolation(fitting, calibration, validation)
                rules = rule_decisions(output, fold, validation, val_sha, budget)
                results = {}
                for kind in ("baseline", "candidate"):
                    binding = {"protocol_sha256": protocol_sha, "fold": fold, "kind": kind, "fit_sha256": fit_sha,
                               "calibration_sha256": cal_sha, "validation_sha256": val_sha}
                    exists = (output / f"fit-fold{fold}-{kind}.bundle.zip").exists()
                    if not exists and new_fits >= maximum_new_fits: raise BudgetStop("STOP_AT_COMMITTED_FIT_BOUNDARY")
                    contents = fitted_unit(output, fold, kind, fitting, calibration, binding, budget)
                    if not exists: new_fits += 1
                    evaluation_binding = {**binding, "model_bundle_sha256": digest(output / f"fit-fold{fold}-{kind}.bundle.zip")}
                    results[kind] = evaluated_unit(output, fold, kind, contents, validation, rules, evaluation_binding, budget)
                    if kind == "baseline" and any(results[kind]["counts"][scope].get("postlogin/OBSERVED", {"fn": 0})["fn"] < 3
                                                  for scope in ("MODEL_ONLY", "SIEM_FINAL")):
                        raise BudgetStop("INCONCLUSIVE_BASELINE_PRIMARY_FN_BELOW_3")
                decision = compare(results["baseline"], results["candidate"])
                proof = commit(output, {"fold": fold, "protocol_sha256": protocol_sha, **decision}, phase=f"decision-fold{fold}")
                outcomes.append({"fold": fold, **decision})
                if decision["status"] != "GO": raise BudgetStop(decision["status"])
                if fold == 1:
                    projected = json.loads((output / "p3-source-benchmark.receipt.private.json").read_text())["projected_one_fold_generation_seconds_with_50_percent_margin"]
                    if budget.state["cap_seconds"] - budget.state["elapsed_seconds"] < 2 * projected:
                        raise BudgetStop("STOP_BUDGET_BEFORE_P4")
            # Every fold passes the fixed delta and non-regression: this implies
            # the pooled >=25% primary reduction and >=2/3 direction screen.
            status = "GO_RESEARCH_SCREEN_ONLY_NOT_QUALIFIED"
        except BudgetStop as stop:
            status = str(stop)
        finally:
            signal.alarm(0)
        budget.save()
        receipt = {"phase": "P3_P4", "status": status, "protocol_sha256": protocol_sha, "fold_decisions": outcomes,
            "budget": budget.state, "quality_gate": "NOT_RUN", "holdout_scored": False, "auto_containment": False,
            "aws_changed": False, "adoption": False, "shadow_started": False,
            "next_action": "Review the fixed research screen and remaining gates; do not extend caps, tune validation thresholds or start strict automatically."}
        proof = commit(output, receipt, phase=result_phase(status))
        state = json.loads((output / "operator-state.private.json").read_text())
        state.update(phase="P3_P4", status=status, last_verified_commit=proof, active_handle=None, next_action=receipt["next_action"])
        publish(output / "operator-state.private.json", state)
        print(canonical({"status": status, "budget": budget.state, "fold_decisions": outcomes}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model-kind", required=True, choices=["normal_plus_incident_research"])
    parser.add_argument("--maximum-new-fits", type=int, choices=range(1, 8), default=7)
    args = parser.parse_args(); run(args.output.absolute(), args.maximum_new_fits)
