#!/usr/bin/env python3
"""One authorized, predeclared second unseen fold of the frozen factorial recipe."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
import tempfile

from postlogin_risk_probe import frozen_generator
import postlogin_risk_source as source
from postlogin_risk_rolling import java_classpath
from postlogin_risk_audit import load_source, audit_source
from postlogin_risk_factorial_data import export
from postlogin_risk_boundary_pilot import validate_controls
from postlogin_risk_factorial_pilot import point_gate
from postlogin_risk_replication import fit_sufficient
from postlogin_risk_ratio_pilot import fit as fit_baseline
from postlogin_risk_pilot import evaluate, compare
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import writer
from ueba_research_artifacts import commit, digest, canonical, publish


def quota(root):
    value = json.loads((root / "operator-state.private.json").read_text())["quota"]
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(value["observed_at_utc"])).total_seconds()
    if value["used_percent_5h"] >= 97 or not 0 <= age <= 300:
        raise RuntimeError("STOP_FRESH_QUOTA_REQUIRED_BELOW_97")


class AmendedLedger:
    def __init__(self, root):
        self.root = root
        approval = checked(root, "next-unseen-fold-budget-authorization-v1")
        assert approval["status"] == "USER_AUTHORIZED"
        assert approval["current_context_fit_cap"] == [13, 26]
        self.path = root / "risk-fit-ledger.private.json"
        self.state = json.loads(self.path.read_text())
        assert self.state["protocol_sha256"] == digest(root / "ratio-protocol-v1.receipt.private.json")

    def reserve(self, unit, kind):
        quota(self.root)
        assert unit in ("ratio-fit-fold5-baseline", "projection-fit-fold5-candidate")
        assert kind in ("composite", "normal", "classifier")
        field, inherited, cap = (("composite_invocations_reserved", 2, 13) if kind == "composite"
                                 else ("component_invocations_reserved", 4, 26))
        if self.state[field] + inherited >= cap:
            raise RuntimeError("STOP_APPROVED_CUMULATIVE_FIT_CAP")
        self.state[field] += 1
        self.state["invocations"].append({"unit": "second-unseen-" + unit, "kind": kind})
        publish(self.path, self.state)


def prior_rows(root):
    paths = [*root.glob("risk-source-f2-*-*.receipt.private.json"),
             *root.glob("risk-source-f3-*-*.receipt.private.json"),
             *(root.parent / "postlogin-risk-context-20261020-r1").glob("risk-source-f1-*-*.receipt.private.json"),
             *(root / "factorial-v1").glob("factorial-control-rows-f*-*.receipt.private.json"),
             *(root / "forward-validation-v1").glob("forward-source-f4-validation-*.receipt.private.json")]
    for path in paths:
        value = checked(path.parent, path.name.removesuffix(".receipt.private.json"))
        yield from value["rows"]


def cross_fold_isolation(root, splits, controls):
    current = [r for rows in splits.values() for r in rows] + controls
    for field in ("frame_id", "session_fingerprints", "context_frame_ids"):
        def values(row):
            return row[field] if isinstance(row[field], list) else [row[field]]
        identities = {v for row in current for v in values(row)}
        for row in prior_rows(root):
            if any(v in identities for v in values(row)):
                raise ValueError("SECOND_UNSEEN_CROSS_FOLD_IDENTITY_OVERLAP_" + field)


def selfcheck(root, data):
    with tempfile.TemporaryDirectory(prefix="second-unseen-no-fit-", dir=root) as scratch:
        test = Path(scratch)
        publish(test / "operator-state.private.json", {"quota": {"used_percent_5h": 64,
                "observed_at_utc": datetime.now(timezone.utc).isoformat()}})
        publish(test / "ratio-protocol-v1.receipt.private.json", {"test": True})
        commit(test, {"status": "USER_AUTHORIZED", "current_context_fit_cap": [13, 26]},
               phase="next-unseen-fold-budget-authorization-v1")
        publish(test / "risk-fit-ledger.private.json", {
            "protocol_sha256": digest(test / "ratio-protocol-v1.receipt.private.json"),
            "composite_invocations_reserved": 10, "component_invocations_reserved": 20, "invocations": []})
        ledger = AmendedLedger(test)
        for kind in ("composite", "normal", "classifier"):
            ledger.reserve("ratio-fit-fold5-baseline", kind)
        for kind in ("composite", "normal"):
            try:
                ledger.reserve("projection-fit-fold5-candidate", kind)
            except RuntimeError as error:
                assert "FIT_CAP" in str(error)
            else:
                raise AssertionError("CAP_BYPASS")
        for percent, age in ((97, 0), (64, 301)):
            publish(test / "operator-state.private.json", {"quota": {"used_percent_5h": percent,
                    "observed_at_utc": (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat()}})
            try:
                quota(test)
            except RuntimeError:
                pass
            else:
                raise AssertionError("QUOTA_BYPASS")
    for split, count in {"fit": 4000, "calibration": 10000, "validation": 21000}.items():
        assert len(list(data.specifications(5, split))) == count
    return {"status": "SECOND_UNSEEN_ZERO_FIT_CHECK_PASS", "new_fits": 0,
            "checks": ["actual_ledger_inherited_caps", "quota97_and_stale_refused", "fold5_template_cardinalities"]}


def run(a):
    root = a.output
    assert source.resource_limits()["verified"]
    protocol = checked(root, "second-unseen-fold5-protocol-v1")
    for name, sha in protocol["code_sha256"].items():
        assert digest(Path(__file__).with_name(name)) == sha, "FROZEN_SECOND_UNSEEN_CODE_CHANGED"
    approval = checked(root, "next-unseen-fold-budget-authorization-v1")
    assert approval["status"] == "USER_AUTHORIZED"
    assert checked(root, "factorial-future-fold3-result")["status"] == "SINGLE_UNSEEN_FUTURE_SCREEN_PASS_NEEDS_MORE_PROOF"
    start = time.monotonic()
    original_guard = source.guard

    def bounded_guard(output, started, maximum_seconds):
        quota(output)
        return original_guard(output, started, maximum_seconds)

    source.guard = bounded_guard
    quota(root)
    data = frozen_generator(a.source, a.frozen_code)
    data.ANCHORS = {**data.ANCHORS, 5: data.ANCHORS[3] + timedelta(days=14)}
    assert data.ANCHORS[5].isoformat() == protocol["fold5_fit_anchor"]
    if a.mode == "check":
        before = digest(root / "risk-fit-ledger.private.json")
        report = selfcheck(root, data)
        assert digest(root / "risk-fit-ledger.private.json") == before
        commit(root, report, phase="second-unseen-zero-fit-check-v1")
        print(canonical(report), flush=True)
        return
    if not (root / "second-unseen-zero-fit-check-v1.commit.private.json").exists():
        before = digest(root / "risk-fit-ledger.private.json")
        report = selfcheck(root, data)
        assert digest(root / "risk-fit-ledger.private.json") == before
        commit(root, report, phase="second-unseen-zero-fit-check-v1")
        print(canonical(report), flush=True)
    assert checked(root, "second-unseen-zero-fit-check-v1")["status"] == "SECOND_UNSEEN_ZERO_FIT_CHECK_PASS"
    source_sha = source.source_protocol(a.source, root)
    cp = java_classpath(a.source, root)
    commit(root, {"status": "FOLD5_ANCHOR_BOUND_BEFORE_SOURCE", "protocol_sha256": digest(root / "second-unseen-fold5-protocol-v1.receipt.private.json"),
                  "fit_anchor": data.ANCHORS[5].isoformat(), "new_fits": 0}, phase="second-unseen-fold5-anchor-v1")
    source.generate(data, a.source, root, cp, source_sha, 5, a.maximum_seconds - 120)
    splits, bindings = load_source(root, 5, source_sha)
    audit = audit_source(splits)
    assert min(r["window_start"] for r in splits["validation"]) > protocol["prior_validation_latest_window"]
    data = frozen_generator(a.source, a.frozen_code)
    data.ANCHORS = {**data.ANCHORS, 5: data.ANCHORS[3] + timedelta(days=14)}
    child = root / "factorial-second-unseen-v1"
    child.mkdir(mode=0o700, exist_ok=True)
    controls = export(data, 5, child, cp)
    validate_controls(controls, splits)
    cross_fold_isolation(root, splits, controls)
    commit(root, {**audit, "split_bindings": bindings, "cross_fold_frame_session_history_disjoint": True,
                  "validation_after_previous": True}, phase="second-unseen-fold5-source-audit-v1")
    commit(child, {"rows_count": len(controls), "batches_sha256": {
        f"factorial-control-rows-f5-b{i:03d}": digest(child / f"factorial-control-rows-f5-b{i:03d}.receipt.private.json") for i in range(8)},
        "normal_rows": 162, "review_rows": 78, "training_only": True}, phase="replication-controls-fold5")
    if time.monotonic() - start > a.maximum_seconds - 100:
        raise RuntimeError("STOP_BUDGET_BEFORE_TWO_FITS")
    protocol_sha = digest(root / "second-unseen-fold5-protocol-v1.receipt.private.json")
    with writer(root):
        ledger = AmendedLedger(root)
        quota(root)
        model, proof = fit_baseline(root, 5, "baseline", splits, bindings, protocol_sha, ledger)
        baseline = evaluate(child, 5, "baseline65", model, proof, splits["validation"], protocol_sha, bindings["validation"])
        quota(root)
        model, proof = fit_sufficient(child, 5, splits, controls, bindings, protocol_sha, ledger)
        candidate = evaluate(child, 5, "factorial11", model, proof, splits["validation"], protocol_sha, bindings["validation"])
        comparison = compare(baseline, candidate)
        regressions = [name for name, value in baseline["counts"].items()
                       if candidate["counts"][name]["fp"] > value["fp"] or candidate["counts"][name]["fn"] > value["fn"]]
        first = checked(root, "factorial-future-fold3-result")
        pooled_base_fn = first["baseline_counts"]["fn"] + baseline["counts"]["global"]["fn"]
        pooled_candidate_fn = first["candidate_counts"]["fn"] + candidate["counts"]["global"]["fn"]
        pooled_reduction = (pooled_base_fn - pooled_candidate_fn) / pooled_base_fn if pooled_base_fn else None
        passed = (not regressions and point_gate(candidate) and comparison["status"] == "GO_RESEARCH_SCREEN_ONLY"
                  and not first["regressions"] and first["absolute_point_gate"] and pooled_reduction is not None and pooled_reduction >= .25)
        report = {"status": "TWO_UNSEEN_FIT_FOLDS_SCREEN_PASS_DEMO_ONLY" if passed else "STOP_NO_IMPROVEMENT",
                  "fold": 5, "candidate_counts": candidate["counts"]["global"], "baseline_counts": baseline["counts"]["global"],
                  "candidate_points": candidate["points"], "absolute_point_gate": point_gate(candidate), "comparison": comparison,
                  "regressions": regressions, "unseen_fit_folds": [3, 5], "forward4_excluded_from_fit_fold_count": True,
                  "pooled_unseen_baseline_fn": pooled_base_fn, "pooled_unseen_candidate_fn": pooled_candidate_fn,
                  "pooled_unseen_fn_reduction": pooled_reduction, "new_round_fit_state": ledger.state,
                  "source_class": "DEMO_ONLY_RULE_DISTILLATION", "strict_admission": "INDEPENDENT_OUTCOME_SOURCE_AND_STRICT_PROTOCOL_STILL_REQUIRED",
                  "quality_gate": "NOT_RUN", "SIEM_FINAL": "NOT_EVALUATED_SCHEMA6_SERVING_NOT_ADMITTED",
                  "holdout_scored": False, "auto_containment": False, "aws_changed": False}
        commit(root, report, phase="second-unseen-fold5-result-v1")
        print(canonical(report), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "frozen-code", "output", "comparison-source"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--mode", choices=("check", "campaign"), required=True)
    p.add_argument("--fold", choices=(5,), type=int, required=True)
    p.add_argument("--maximum-seconds", type=int, required=True)
    run(p.parse_args())
