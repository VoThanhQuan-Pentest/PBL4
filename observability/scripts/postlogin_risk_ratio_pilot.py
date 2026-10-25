#!/usr/bin/env python3
"""One frozen ratio hypothesis; diagnostic fold1 and unseen chronological replication."""
import argparse
import io
import json
from pathlib import Path
import signal
import time

import joblib
import numpy as np
from postlogin_risk_ratio_model import RelativeVolumeScorer, relative_volume
from postlogin_risk_pilot import FitLedger, PARAMETERS, THRESHOLDS, scores, evaluate, compare
from postlogin_risk_audit import load_source, audit_source
from postlogin_risk_source import resource_limits
from postlogin_risk_result_diagnosis import checked
from postlogin_risk_rolling import model_features
from postlogin_pilot_artifacts import writer, read_bundle, publish_bundle
from ueba_research_artifacts import canonical, commit, digest, private_directory


class RoundLedger(FitLedger):
    def reserve(self, unit, kind):
        field, limit, inherited = ("composite_invocations_reserved", 7, 2) if kind == "composite" else ("component_invocations_reserved", 14, 4)
        if self.state[field] + inherited >= limit:
            raise RuntimeError("STOP_CUMULATIVE_FIT_CAP_INCLUDING_PRIOR_ROUND")
        super().reserve(unit, kind)


def controls(output):
    raw = np.zeros((5, 65)); raw[:, 57] = [30, 300, 120, 10, 0]
    raw[:, 63] = [10, 100, 0, 1, 20]; raw[:, 64] = [1, 1, 1, 0, 1]
    assert np.array_equal(relative_volume(raw), [3, 3, 0, 0, 0])
    assert RelativeVolumeScorer("candidate").values(raw).shape == (5, 66)
    assert RelativeVolumeScorer("baseline").values(raw).shape == (5, 65)
    for bad in (np.zeros((2, 64)), np.full((1, 65), np.nan)):
        try: relative_volume(bad)
        except ValueError: pass
        else: raise AssertionError("invalid feature shape/value accepted")
    assert compare({"counts":{"global":dict(tp=985,fn=15,fp=2,tn=19998)}},
                   {"counts":{"global":dict(tp=989,fn=11,fp=2,tn=19998)}})["status"] == "GO_RESEARCH_SCREEN_ONLY"
    commit(output, {"status":"RATIO_NO_FIT_CONTROLS_PASS", "new_fits":0,
        "checks":["continuous_ratio_no_cutoff", "missing_or_zero_history_explicit", "raw65_model66", "invalid_input_rejected", "primary_reduction_boundary"],
        "publication":"REUSES_PREVIOUSLY_SIGKILL_TESTED_BUNDLE_WRITER"}, phase="ratio-control-check-v1")


def fit(output, fold, kind, splits, bindings, protocol_sha, ledger):
    unit = f"ratio-fit-fold{fold}-{kind}"
    binding = {"protocol_sha256":protocol_sha, "source_splits_sha256":bindings, "representation":kind}
    existing = read_bundle(output, unit, binding, allow_unmarked=True)
    if existing is not None:
        proof = publish_bundle(output, unit, binding, {})
        return joblib.load(io.BytesIO(existing["model.joblib"])), proof
    ledger.reserve(unit, "composite")
    signal.signal(signal.SIGALRM, signal.SIG_DFL); signal.alarm(900)
    start = time.monotonic()
    x = np.asarray([model_features(r) for r in splits["fit"]], dtype=np.float64)
    normal = x[[i for i,r in enumerate(splits["fit"]) if r["normal_fit"]]]
    labels = np.asarray([r["training_context"] for r in splits["fit"]], dtype=np.int64)
    model = RelativeVolumeScorer(kind).fit(normal, x, labels, lambda component: ledger.reserve(unit, component))
    calibration = {}
    for cohort in ("READY", "COLD"):
        rows = [r for r in splits["calibration"] if r["cohort"] == cohort]
        assert len(rows)==5000 and not any(r["label"] for r in rows)
        calibration[cohort] = np.sort(scores(model, np.asarray([model_features(r) for r in rows])))
    artifact = {"model":model,"calibration":calibration}
    encoded = io.BytesIO(); joblib.dump(artifact, encoded, compress=3)
    restored = joblib.load(io.BytesIO(encoded.getvalue()))
    probes = x[[0,1999,2999,3000,3199,3399,3599,3799,3999]]
    assert np.array_equal(scores(model, probes), scores(restored["model"], probes))
    assert all(np.array_equal(calibration[c], restored["calibration"][c]) for c in calibration)
    metadata = {"recipe_version":6,"feature_schema_version":7,"raw_java_schema":6,"raw_width":65,
        "classifier_width":66 if kind=="candidate" else 65,"normal_component_width":37,
        "parameters":PARAMETERS,"normal_fit_rows":2000,"labeled_fit_rows":4000,"calibration_rows":10000,
        "readback_probe_rows":9,"actual_component_fits":2,"elapsed_seconds":time.monotonic()-start,
        "applicability":"PILOT_ONLY_RULE_DISTILLATION"}
    proof=publish_bundle(output,unit,binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical(metadata).encode()})
    signal.alarm(0)
    return restored,proof


def run(args):
    output=private_directory(args.output); old=private_directory(args.comparison_source)
    if not resource_limits()["verified"]: raise RuntimeError("CAPPED_OFFLINE_WORKER_REQUIRED")
    protocol=checked(output,"ratio-protocol-v1")
    for name,expected in protocol["code_sha256"].items():
        if digest(Path(__file__).with_name(name))!=expected: raise ValueError("FROZEN_RATIO_CODE_CHANGED")
    if args.mode=="ratio-check":
        controls(output); print("RATIO_NO_FIT_CONTROLS_PASS",flush=True); return
    assert checked(output,"ratio-control-check-v1")["status"]=="RATIO_NO_FIT_CONTROLS_PASS"
    if args.fold>1 and checked(output,"ratio-fold1-result")["status"]!="GO_FOR_UNSEEN_REPLICATION_NOT_PASS":
        raise RuntimeError("DEVELOPMENT_SCREEN_DID_NOT_ADMIT_REPLICATION")
    protocol_sha=digest(output/"ratio-protocol-v1.receipt.private.json")
    phase=f"ratio-fold{args.fold}-result"
    if (output/(phase+".commit.private.json")).exists():
        prior=checked(output,phase);assert prior["protocol_sha256"]==protocol_sha
        print(canonical({"status":prior["status"],"reused":True}),flush=True);return
    source=old if args.fold==1 else output
    source_sha=digest(source/"risk-source-protocol-v4.receipt.private.json")
    splits,bindings=load_source(source,args.fold,source_sha)
    audit=audit_source(splits)
    commit(output,{**audit,"split_bindings":bindings},phase=f"ratio-source-audit-fold{args.fold}")
    with writer(output):
        ledger=RoundLedger(output,protocol_sha)
        if args.fold==1:
            prior_protocol=digest(old/"risk-pilot-protocol-v2.receipt.private.json")
            bound={"protocol_sha256":prior_protocol,"source_splits_sha256":bindings,"projection":"candidate"}
            contents=read_bundle(old,"risk-fit-fold1-candidate",bound)
            assert contents is not None
            artifact=joblib.load(io.BytesIO(contents["model.joblib"]))
            proof={"bundle_sha256":digest(old/"risk-fit-fold1-candidate.bundle.zip"),"reused":True}
        else:
            artifact,proof=fit(output,args.fold,"baseline",splits,bindings,protocol_sha,ledger)
        baseline=evaluate(output,args.fold,"baseline",artifact,proof,splits["validation"],protocol_sha,bindings["validation"])
        if args.fold==1:
            old_validation=checked(old,"risk-validation-fold1-candidate")
            assert baseline["counts"]==old_validation["counts"],"REUSED_BASELINE_SCORE_COUNTS_CHANGED"
        artifact,proof=fit(output,args.fold,"candidate",splits,bindings,protocol_sha,ledger)
        candidate=evaluate(output,args.fold,"candidate",artifact,proof,splits["validation"],protocol_sha,bindings["validation"])
        decision=compare(baseline,candidate)
        original_regressions=[]
        if args.fold==1:
            original=checked(old,"risk-validation-fold1-baseline")["counts"]
            original_regressions=[k for k,v in original.items() if candidate["counts"][k]["fp"]>v["fp"] or candidate["counts"][k]["fn"]>v["fn"]]
        go=decision["status"]=="GO_RESEARCH_SCREEN_ONLY" and not original_regressions
        status=("GO_FOR_UNSEEN_REPLICATION_NOT_PASS" if args.fold==1 else "REPLICATION_FOLD_IMPROVEMENT_NOT_QUALIFICATION") if go else "STOP_NO_IMPROVEMENT"
        result={"status":status,"protocol_sha256":protocol_sha,"fold":args.fold,"comparison":decision,
            "original37_regressions":original_regressions,"baseline_counts":baseline["counts"]["global"],
            "candidate_counts":candidate["counts"]["global"],"candidate_points":candidate["points"],
            "validation_scope":"PREVIOUSLY_INSPECTED_DEVELOPMENT" if args.fold==1 else "FROZEN_HYPOTHESIS_FUTURE_CHRONOLOGICAL_VALIDATION",
            "new_round_reserved_fits":ledger.state,"inherited_reserved_fits":{"composite":2,"component":4},
            "strict_admission":"NOT_FROM_RULE_DISTILLATION_ALONE","holdout_scored":False,"auto_containment":False,"aws_changed":False}
        commit(output,result,phase=phase);print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"): p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--fold",type=int,choices=(1,2,3),required=True)
    p.add_argument("--maximum-seconds",type=int,required=True)
    p.add_argument("--mode",choices=("ratio-check","ratio-pilot"),required=True)
    run(p.parse_args())
