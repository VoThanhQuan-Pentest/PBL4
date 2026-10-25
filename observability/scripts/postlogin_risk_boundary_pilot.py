#!/usr/bin/env python3
"""Data-support hypothesis: fixed ratio model with raw-only FIT boundary controls."""
import argparse
import io
from pathlib import Path
import time
import signal

import joblib
import numpy as np
from postlogin_risk_ratio_model import RelativeVolumeScorer
from postlogin_risk_boundary_data import export_controls
from postlogin_risk_probe import frozen_generator
from postlogin_risk_rolling import java_classpath, model_features
from postlogin_risk_source import resource_limits
from postlogin_risk_audit import load_source, audit_source
from postlogin_risk_pilot import FitLedger, PARAMETERS, THRESHOLDS, scores, evaluate, compare
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import writer, read_bundle, publish_bundle
from ueba_research_artifacts import canonical, commit, digest


class CampaignLedger(FitLedger):
    def reserve(self,unit,kind):
        cap=8 if (self.path.parent/"ratio-budget-amendment-v1.commit.private.json").exists() else 7
        if cap==8:
            approval=checked(self.path.parent,"ratio-budget-amendment-v1")
            assert approval["status"]=="USER_AUTHORIZED" and approval["cumulative_composite_cap"]==8
        field,inherited,limit=("composite_invocations_reserved",2,cap) if kind=="composite" else ("component_invocations_reserved",4,cap*2)
        if self.state[field]+inherited>=limit: raise RuntimeError("STOP_CUMULATIVE_FIT_CAP")
        super().reserve(unit,kind)


def validate_controls(rows,splits):
    heldout=[r for split in ("calibration","validation") for r in splits[split]]
    for field in ("frame_id","session_fingerprints","context_frame_ids"):
        def identities(items):
            return {v for r in items for v in (r[field] if isinstance(r[field],list) else [r[field]])}
        if identities(rows)&identities(heldout): raise ValueError("AUGMENTATION_HELDOUT_OVERLAP")
    if min(r["window_start"] for r in heldout)<=max(r["window_start"] for r in rows):
        raise ValueError("AUGMENTATION_NOT_PAST_ONLY")
    assert all(r["trusted_window_count"]==48 and r["baseline_established"] for r in rows)


def fit(output,fold,splits,rows,bindings,protocol_sha,ledger):
    unit=f"boundary-fit-fold{fold}-candidate"
    binding={"protocol_sha256":protocol_sha,"source_splits_sha256":bindings,
             "augmentation_sha256":digest(output/f"boundary-controls-fold{fold}.receipt.private.json")}
    existing=read_bundle(output,unit,binding,allow_unmarked=True)
    if existing is not None: return joblib.load(io.BytesIO(existing["model.joblib"])),publish_bundle(output,unit,binding,{})
    ledger.reserve(unit,"composite");signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(900)
    start=time.monotonic();fitting=splits["fit"]+rows
    x=np.asarray([model_features(r) for r in fitting]);y=np.asarray([r["training_context"] for r in fitting])
    normal=x[[i for i,r in enumerate(fitting) if r["normal_fit"]]]
    assert len(fitting)==4240 and len(normal)==2000
    model=RelativeVolumeScorer("candidate").fit(normal,x,y,lambda component:ledger.reserve(unit,component))
    calibration={c:np.sort(scores(model,np.asarray([model_features(r) for r in splits["calibration"] if r["cohort"]==c]))) for c in ("READY","COLD")}
    assert all(len(v)==5000 for v in calibration.values())
    artifact={"model":model,"calibration":calibration};encoded=io.BytesIO();joblib.dump(artifact,encoded,compress=3)
    restored=joblib.load(io.BytesIO(encoded.getvalue()));probes=x[[0,1999,2999,3999,4000,4119,4239]]
    assert np.array_equal(scores(model,probes),scores(restored["model"],probes))
    assert all(np.array_equal(calibration[c],restored["calibration"][c]) for c in calibration)
    metadata={"model_recipe":6,"training_recipe":7,"classifier_width":66,"raw_java_width":65,"parameters":PARAMETERS,
        "normal_fit_rows":2000,"labeled_fit_rows":4240,"additional_raw_java_controls":240,"calibration_rows":10000,
        "readback_probe_rows":7,"elapsed_seconds":time.monotonic()-start,"source_class":"DEMO_ONLY_RULE_DISTILLATION"}
    proof=publish_bundle(output,unit,binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical(metadata).encode()})
    signal.alarm(0);return restored,proof


def run(a):
    output=a.output;old=a.comparison_source
    assert resource_limits()["verified"]
    protocol=checked(output,"boundary-protocol-v4")
    for name,expected in protocol["code_sha256"].items():
        assert digest(Path(__file__).with_name(name))==expected,"FROZEN_BOUNDARY_CODE_CHANGED"
    data=frozen_generator(a.source,a.frozen_code);cp=java_classpath(a.source,output)
    if a.mode=="boundary-check":
        rows=export_controls(data,a.fold,output,cp,24)
        assert sum(r["label"]==0 for r in rows)==sum(r["label"]==1 for r in rows)==12
        commit(output,{"status":"RAW_JAVA_BOUNDARY_CONTROLS_PASS","rows":rows,"new_fits":0,
            "scope":"12_SYNTHETIC_119_VS_120_PAIRS_NOT_QUALITY_PROOF"},phase="boundary-control-check-v1")
        print("RAW_JAVA_BOUNDARY_CONTROLS_PASS",flush=True);return
    assert checked(output,"boundary-control-check-v1")["status"]=="RAW_JAVA_BOUNDARY_CONTROLS_PASS"
    protocol_sha=digest(output/"boundary-protocol-v4.receipt.private.json")
    phase=f"boundary-fold{a.fold}-result"
    if (output/(phase+".commit.private.json")).exists():
        print(canonical(checked(output,phase)),flush=True);return
    source=old if a.fold==1 else output
    splits,bindings=load_source(source,a.fold,digest(source/"risk-source-protocol-v4.receipt.private.json"));audit_source(splits)
    with writer(output):
        control_phase=f"boundary-controls-fold{a.fold}"
        if (output/(control_phase+".commit.private.json")).exists():
            manifest=checked(output,control_phase)
            rows=[r for phase in manifest["batches"] for r in checked(output,phase)["rows"]]
        else:
            rows=export_controls(data,a.fold,output,cp)
            batches=[f"boundary-control-rows-f{a.fold}-n240-b{i:03d}" for i in range(8)]
            commit(output,{"rows_count":len(rows),"batches":batches,
                "batches_sha256":{name:digest(output/(name+".receipt.private.json")) for name in batches},
                "status":"FIT_ONLY_RAW_JAVA_CONTROLS_READY","new_fits":0},phase=control_phase)
        validate_controls(rows,splits)
        ledger=CampaignLedger(output,digest(output/"ratio-protocol-v1.receipt.private.json"))
        if a.fold!=1: raise RuntimeError("FUTURE_FOLD_PAIRED_BASELINE_REQUIRES_PREDECLARED_ADMISSION")
        artifact,proof=fit(output,a.fold,splits,rows,bindings,protocol_sha,ledger)
        candidate=evaluate(output,a.fold,"boundary",artifact,proof,splits["validation"],protocol_sha,bindings["validation"])
        comparisons={name:checked(old,phase) for name,phase in [("original37","risk-validation-fold1-baseline"),("previous65","risk-validation-fold1-candidate")]}
        comparisons["ratio66"]=checked(output,"risk-validation-fold1-candidate")
        decision=compare(comparisons["previous65"],candidate)
        regressions={name:[k for k,v in report["counts"].items() if candidate["counts"][k]["fp"]>v["fp"] or candidate["counts"][k]["fn"]>v["fn"]] for name,report in comparisons.items()}
        go=decision["status"]=="GO_RESEARCH_SCREEN_ONLY" and not any(regressions.values())
        result={"status":"GO_FOR_UNSEEN_REPLICATION_NOT_PASS" if go else "STOP_NO_IMPROVEMENT",
            "protocol_sha256":protocol_sha,"candidate_counts":candidate["counts"]["global"],"candidate_points":candidate["points"],
            "comparisons":regressions,"primary":decision,"validation_scope":"PREVIOUSLY_INSPECTED_DEVELOPMENT",
            "source_class":"DEMO_ONLY_RULE_DISTILLATION","strict_admission":"INDEPENDENT_OUTCOME_EVIDENCE_REQUIRED",
            "holdout_scored":False,"auto_containment":False,"new_round_reserved_fits":ledger.state}
        commit(output,result,phase=phase);print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mode",choices=("boundary-check","boundary-pilot"),required=True)
    p.add_argument("--fold",type=int,choices=(1,2,3),required=True);p.add_argument("--maximum-seconds",type=int,required=True)
    run(p.parse_args())
