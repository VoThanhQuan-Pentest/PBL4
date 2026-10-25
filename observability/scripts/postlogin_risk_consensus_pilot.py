#!/usr/bin/env python3
"""Frozen consensus study: existing fitted bytes, new normal calibration, zero fits."""
import argparse
import io
import json
from pathlib import Path
import zipfile
import joblib
import numpy as np
from postlogin_risk_consensus_model import ConsensusContextScorer
from postlogin_risk_source import resource_limits
from postlogin_risk_audit import load_source,audit_source
from postlogin_risk_rolling import model_features
from postlogin_risk_pilot import scores,evaluate,compare
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import read_bundle,publish_bundle,writer
from ueba_research_artifacts import commit,digest,canonical


def run(a):
    assert resource_limits()["verified"]
    root=a.output;protocol=checked(root,"consensus-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected
    splits,bindings=load_source(a.comparison_source,1,digest(a.comparison_source/"risk-source-protocol-v4.receipt.private.json"));audit_source(splits)
    models={};parent_hashes={}
    for role,unit in [("full","ratio-fit-fold1-candidate"),("sufficient","projection-fit-fold1-candidate")]:
        path=root/(unit+".bundle.zip");assert digest(path)==protocol["parent_bundles_sha256"][role]
        with zipfile.ZipFile(path) as z:binding=json.loads(z.read("manifest.json"))["binding"]
        assert binding["source_splits_sha256"]==bindings
        contents=read_bundle(root,unit,binding);models[role]=joblib.load(io.BytesIO(contents["model.joblib"]))["model"]
        parent_hashes[role]=digest(path)
    model=ConsensusContextScorer(models["full"],models["sufficient"])
    calibration={};normal_report={}
    for cohort in ("READY","COLD"):
        rows=[r for r in splits["calibration"] if r["cohort"]==cohort];assert len(rows)==5000 and not any(r["label"] for r in rows)
        x=np.asarray([model_features(r) for r in rows]);calibration[cohort]=np.sort(scores(model,x))
        normal_report[cohort]={"rows":len(rows),"full_context_nonroutine":int(np.sum(models["full"].contexts(x)!=0)),
            "sufficient_context_nonroutine":int(np.sum(models["sufficient"].contexts(x)!=0)),"consensus_nonroutine":int(np.sum(model.contexts(x)!=0))}
    protocol_sha=digest(root/"consensus-protocol-v1.receipt.private.json")
    with writer(root):
        artifact={"model":model,"calibration":calibration};encoded=io.BytesIO();joblib.dump(artifact,encoded,compress=3)
        restored=joblib.load(io.BytesIO(encoded.getvalue()));probes=np.asarray([model_features(r) for r in splits["fit"][:10]])
        assert np.array_equal(scores(model,probes),scores(restored["model"],probes))
        assert all(np.array_equal(calibration[c],restored["calibration"][c]) for c in calibration)
        binding={"protocol_sha256":protocol_sha,"parent_bundles_sha256":parent_hashes,"source_splits_sha256":bindings}
        proof=publish_bundle(root,"consensus-model-fold1",binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical({"new_fits":0,"parent_models_reused":2,"calibration_rows":10000,"recipe_version":9,"readback_probes":10}).encode()})
        candidate=evaluate(root,1,"consensus",restored,proof,splits["validation"],protocol_sha,bindings["validation"])
        refs={"original37":checked(a.comparison_source,"risk-validation-fold1-baseline"),"previous65":checked(a.comparison_source,"risk-validation-fold1-candidate"),
            "ratio66":checked(root,"risk-validation-fold1-candidate"),"projection11":checked(root,"risk-validation-fold1-projection")}
        regressions={n:[k for k,v in r["counts"].items() if candidate["counts"][k]["fp"]>v["fp"] or candidate["counts"][k]["fn"]>v["fn"]] for n,r in refs.items()}
        primary=compare(refs["previous65"],candidate);go=primary["status"]=="GO_RESEARCH_SCREEN_ONLY" and not any(regressions.values())
        result={"status":"GO_FOR_UNSEEN_REPLICATION_NOT_PASS" if go else "STOP_NO_IMPROVEMENT","protocol_sha256":protocol_sha,
            "primary":primary,"candidate_counts":candidate["counts"]["global"],"candidate_points":candidate["points"],
            "regressions":regressions,"normal_calibration_agreement":normal_report,"new_fits":0,
            "validation_scope":"PREVIOUSLY_INSPECTED_DEVELOPMENT_NOT_INDEPENDENT_CONFIRMATION","source_class":"DEMO_ONLY_RULE_DISTILLATION",
            "strict_admission":"INDEPENDENT_OUTCOME_EVIDENCE_REQUIRED","holdout_scored":False,"auto_containment":False}
        commit(root,result,phase="consensus-fold1-result");print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mode",required=True);p.add_argument("--fold",type=int,required=True);p.add_argument("--maximum-seconds",type=int,required=True);run(p.parse_args())
