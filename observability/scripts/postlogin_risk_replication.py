#!/usr/bin/env python3
"""Frozen future-fold confirmation: independent baseline and both learned views.

Never uses a final holdout or exports a serving model. The same synthetic
generator is temporal confirmation, not independent real-incident evidence.
"""
import argparse
import io
import json
from pathlib import Path
import signal
import time
import zipfile
import tempfile
import joblib
import numpy as np

from postlogin_risk_ratio_model import RelativeVolumeScorer
from postlogin_risk_projection_model import SufficientContextScorer
from postlogin_risk_consensus_model import ConsensusContextScorer
from postlogin_risk_ratio_pilot import fit as fit_ratio
from postlogin_risk_boundary_data import export_controls
from postlogin_risk_boundary_pilot import validate_controls
from postlogin_risk_probe import frozen_generator
from postlogin_risk_rolling import java_classpath,model_features
from postlogin_risk_source import resource_limits
from postlogin_risk_audit import load_source,audit_source
from postlogin_risk_pilot import scores,evaluate,PARAMETERS
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import writer,read_bundle,publish_bundle
from ueba_research_artifacts import canonical,commit,digest,publish


class ReplicationLedger:
    def __init__(self,output):
        self.path=output/"risk-fit-ledger.private.json"
        self.state=json.loads(self.path.read_text())
        assert self.state["protocol_sha256"]==digest(output/"ratio-protocol-v1.receipt.private.json")
        self.approval=checked(output,"ratio-budget-amendment-v1")
        assert self.approval["status"]=="USER_AUTHORIZED"
        assert self.approval["cumulative_composite_cap"]==11 and self.approval["cumulative_component_cap"]==22

    def reserve(self,unit,kind):
        field,inherited,limit=("composite_invocations_reserved",2,11) if kind=="composite" else ("component_invocations_reserved",4,22)
        if self.state[field]+inherited>=limit:raise RuntimeError("STOP_APPROVED_CUMULATIVE_FIT_CAP")
        self.state[field]+=1;self.state["invocations"].append({"unit":unit,"kind":kind});publish(self.path,self.state)


def artifact(root,unit):
    path=root/(unit+".bundle.zip")
    with zipfile.ZipFile(path) as z:binding=json.loads(z.read("manifest.json"))["binding"]
    contents=read_bundle(root,unit,binding)
    return joblib.load(io.BytesIO(contents["model.joblib"])),{"bundle_sha256":digest(path),"reused":True}


def controls(a):
    old=a.comparison_source;root=a.output
    source_sha=digest(old/"risk-source-protocol-v4.receipt.private.json")
    splits,_=load_source(old,1,source_sha)
    x=np.asarray([model_features(r) for r in splits["fit"][:10]])
    original,_=artifact(old,"risk-fit-fold1-candidate")
    wrapper=RelativeVolumeScorer("baseline");wrapper.normal=original["model"].normal;wrapper.classifier=original["model"].classifier
    assert np.array_equal(scores(wrapper,x),scores(original["model"],x))
    assert np.array_equal(wrapper.contexts(x),original["model"].contexts(x))
    full,_=artifact(root,"ratio-fit-fold1-candidate");sufficient,_=artifact(root,"projection-fit-fold1-candidate")
    current,_=artifact(root,"consensus-model-fold1")
    reconstructed=ConsensusContextScorer(full["model"],sufficient["model"])
    assert np.array_equal(scores(reconstructed,x),scores(current["model"],x))
    assert np.array_equal(reconstructed.contexts(x),current["model"].contexts(x))
    class NoFit:
        def reserve(self,*args):raise AssertionError("CONTROL_ATTEMPTED_NEW_FIT")
    # Exercise the actual future-fit helpers' committed-bundle resume paths.
    with tempfile.TemporaryDirectory(prefix="replication-resume-",dir=root) as scratch:
        test=Path(scratch)
        encoded=io.BytesIO();joblib.dump(original,encoded)
        binding={"protocol_sha256":"NO_FIT_CONTROL","source_splits_sha256":{},"representation":"baseline"}
        publish_bundle(test,"ratio-fit-fold2-baseline",binding,{"model.joblib":encoded.getvalue()})
        restored,_=fit_ratio(test,2,"baseline",{},{},"NO_FIT_CONTROL",NoFit())
        assert np.array_equal(scores(restored["model"],x),scores(original["model"],x))
        publish(test/"replication-controls-fold2.receipt.private.json",{"scope":"NO_DATA_NO_FIT_CONTROL"})
        binding={"protocol_sha256":"NO_FIT_CONTROL","source_splits_sha256":{},
            "augmentation_sha256":digest(test/"replication-controls-fold2.receipt.private.json")}
        encoded=io.BytesIO();joblib.dump(sufficient,encoded)
        publish_bundle(test,"projection-fit-fold2-candidate",binding,{"model.joblib":encoded.getvalue()})
        restored,_=fit_sufficient(test,2,{},[],{},"NO_FIT_CONTROL",NoFit())
        assert np.array_equal(scores(restored["model"],x),scores(sufficient["model"],x))
    commit(root,{"status":"REPLICATION_ZERO_FIT_CONTROLS_PASS","new_fits":0,"probes":10,
        "checks":["baseline65_wrapper_exact_score_context_parity","consensus_parent_reconstruction_exact_parity",
                  "actual_future_fit_helpers_resume_committed_models_without_fit","same_capped_writer_and_publication_pipeline"],
        "actual_fits_not_started":"USER_BUDGET_AMENDMENT_REQUIRED"},phase="replication-control-check-v1")
    print("REPLICATION_ZERO_FIT_CONTROLS_PASS",flush=True)


def fit_sufficient(root,fold,splits,rows,bindings,protocol_sha,ledger):
    unit=f"projection-fit-fold{fold}-candidate"
    binding={"protocol_sha256":protocol_sha,"source_splits_sha256":bindings,
        "augmentation_sha256":digest(root/f"replication-controls-fold{fold}.receipt.private.json")}
    existing=read_bundle(root,unit,binding,allow_unmarked=True)
    if existing is not None:return joblib.load(io.BytesIO(existing["model.joblib"])),publish_bundle(root,unit,binding,{})
    ledger.reserve(unit,"composite");signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(900);start=time.monotonic()
    fitting=splits["fit"]+rows;x=np.asarray([model_features(r) for r in fitting]);y=np.asarray([r["training_context"] for r in fitting])
    normal=x[[i for i,r in enumerate(fitting) if r["normal_fit"]]];assert len(normal)==2000 and len(x)==4240
    model=SufficientContextScorer().fit(normal,x,y,lambda component:ledger.reserve(unit,component))
    calibration={c:np.sort(scores(model,np.asarray([model_features(r) for r in splits["calibration"] if r["cohort"]==c]))) for c in ("READY","COLD")}
    assert all(len(v)==5000 for v in calibration.values())
    value={"model":model,"calibration":calibration};encoded=io.BytesIO();joblib.dump(value,encoded,compress=3)
    restored=joblib.load(io.BytesIO(encoded.getvalue()));probes=x[[0,1999,3999,4000,4119,4239]]
    assert np.array_equal(scores(model,probes),scores(restored["model"],probes))
    assert all(np.array_equal(calibration[c],restored["calibration"][c]) for c in calibration)
    metadata={"recipe_version":8,"raw_width":65,"classifier_width":11,"normal_component_width":37,"parameters":PARAMETERS,
        "labeled_fit_rows":4240,"normal_fit_rows":2000,"calibration_rows":10000,"readback_probes":6,
        "fit_seconds":time.monotonic()-start,"source_class":"DEMO_ONLY_RULE_DISTILLATION"}
    proof=publish_bundle(root,unit,binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical(metadata).encode()})
    signal.alarm(0);return restored,proof


def run(a):
    root=a.output;assert resource_limits()["verified"]
    protocol=checked(root,"replication-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected,"FROZEN_REPLICATION_CODE_CHANGED"
    assert checked(root,"consensus-fold1-result")["status"]=="GO_FOR_UNSEEN_REPLICATION_NOT_PASS"
    if a.mode=="replication-check":controls(a);return
    assert a.fold in (2,3)
    assert checked(root,"replication-control-check-v1")["status"]=="REPLICATION_ZERO_FIT_CONTROLS_PASS"
    ledger=ReplicationLedger(root)
    phase=f"replication-fold{a.fold}-result"
    if (root/(phase+".commit.private.json")).exists():print(canonical(checked(root,phase)),flush=True);return
    if a.fold==3:assert checked(root,"replication-fold2-result")["status"]=="REPLICATION_FOLD_NONREGRESSION_PASS"
    splits,bindings=load_source(root,a.fold,digest(root/"risk-source-protocol-v4.receipt.private.json"));audit=audit_source(splits)
    if a.fold==2:old_splits,_=load_source(a.comparison_source,1,digest(a.comparison_source/"risk-source-protocol-v4.receipt.private.json"))
    else:old_splits,_=load_source(root,2,digest(root/"risk-source-protocol-v4.receipt.private.json"))
    assert min(r["window_start"] for r in splits["validation"])>max(r["window_start"] for r in old_splits["validation"])
    commit(root,{**audit,"split_bindings":bindings,"validation_after_previous_fold":True},phase=f"replication-source-audit-fold{a.fold}")
    protocol_sha=digest(root/"replication-protocol-v1.receipt.private.json")
    with writer(root):
        data=frozen_generator(a.source,a.frozen_code);cp=java_classpath(a.source,root)
        rows=export_controls(data,a.fold,root,cp);validate_controls(rows,splits)
        batches=[f"boundary-control-rows-f{a.fold}-n240-b{i:03d}" for i in range(8)]
        commit(root,{"rows_count":len(rows),"batches_sha256":{n:digest(root/(n+".receipt.private.json")) for n in batches},
            "training_only":True},phase=f"replication-controls-fold{a.fold}")
        baseline,baseline_proof=fit_ratio(root,a.fold,"baseline",splits,bindings,protocol_sha,ledger)
        full,full_proof=fit_ratio(root,a.fold,"candidate",splits,bindings,protocol_sha,ledger)
        sufficient,sufficient_proof=fit_sufficient(root,a.fold,splits,rows,bindings,protocol_sha,ledger)
        model=ConsensusContextScorer(full["model"],sufficient["model"])
        calibration={c:np.sort(scores(model,np.asarray([model_features(r) for r in splits["calibration"] if r["cohort"]==c]))) for c in ("READY","COLD")}
        value={"model":model,"calibration":calibration};encoded=io.BytesIO();joblib.dump(value,encoded,compress=3)
        restored=joblib.load(io.BytesIO(encoded.getvalue()));probes=np.asarray([model_features(r) for r in splits["fit"][:10]])
        assert np.array_equal(scores(model,probes),scores(restored["model"],probes))
        assert all(np.array_equal(calibration[c],restored["calibration"][c]) for c in calibration)
        binding={"protocol_sha256":protocol_sha,"source_splits_sha256":bindings,
            "parent_bundles_sha256":{"full":full_proof["bundle_sha256"],"sufficient":sufficient_proof["bundle_sha256"]}}
        proof=publish_bundle(root,f"consensus-model-fold{a.fold}",binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical({"new_fits":0,"parent_models_reused":2,"calibration_rows":10000,"readback_probes":10}).encode()})
        base=evaluate(root,a.fold,"replication-baseline65",baseline,baseline_proof,splits["validation"],protocol_sha,bindings["validation"])
        candidate=evaluate(root,a.fold,"replication-consensus",restored,proof,splits["validation"],protocol_sha,bindings["validation"])
        regressions=[k for k,v in base["counts"].items() if candidate["counts"][k]["fp"]>v["fp"] or candidate["counts"][k]["fn"]>v["fn"]]
        result={"status":"REPLICATION_FOLD_NONREGRESSION_PASS" if not regressions else "STOP_NO_IMPROVEMENT",
            "fold":a.fold,"protocol_sha256":protocol_sha,"baseline_counts":base["counts"]["global"],
            "candidate_counts":candidate["counts"]["global"],"candidate_points":candidate["points"],"regressions":regressions,
            "strict_admission":"INDEPENDENT_OUTCOME_EVIDENCE_REQUIRED","validation_scope":"FROZEN_RECIPE_FUTURE_SYNTHETIC_TIME_FOLD",
            "new_round_reserved_fits":ledger.state,"holdout_scored":False,"auto_containment":False,"aws_changed":False}
        commit(root,result,phase=phase);print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mode",choices=("replication-check","replication-pilot"),required=True)
    p.add_argument("--fold",type=int,required=True);p.add_argument("--maximum-seconds",type=int,required=True);run(p.parse_args())
