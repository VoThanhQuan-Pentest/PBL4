#!/usr/bin/env python3
"""One declared classifier-sufficiency ablation, not a parameter search."""
import argparse
import io
from pathlib import Path
import signal
import time
import joblib
import numpy as np
from postlogin_risk_projection_model import SufficientContextScorer,projection
from postlogin_risk_boundary_pilot import CampaignLedger,validate_controls
from postlogin_risk_audit import load_source,audit_source
from postlogin_risk_rolling import model_features
from postlogin_risk_source import resource_limits
from postlogin_risk_pilot import scores,evaluate,compare,PARAMETERS
from postlogin_risk_result_diagnosis import checked
from postlogin_pilot_artifacts import writer,read_bundle,publish_bundle
from ueba_research_artifacts import canonical,commit,digest


def run(a):
    assert resource_limits()["verified"]
    output=a.output;protocol=checked(output,"projection-protocol-v1")
    for name,expected in protocol["code_sha256"].items():assert digest(Path(__file__).with_name(name))==expected
    raw=np.zeros((3,65));raw[:,57]=[100,120,0];raw[:,63]=[20,20,0];raw[:,64]=[1,1,0]
    raw[:,59]=[25,12,0];raw[:,60]=[10,24,0]
    projected=projection(raw);assert projected.shape==(3,11)
    assert np.array_equal(projected[:,8],[5,6,0])
    assert np.allclose(projected[:,9],[.25,.1,0]) and np.allclose(projected[:,10],[.1,.2,0])
    if a.mode=="projection-check":
        commit(output,{"status":"PROJECTION_NO_FIT_CONTROLS_PASS","new_fits":0,
            "checks":["raw65_classifier11","continuous_ratios_no_cutoffs","zero_denominator_explicit","normal_component_remains_real37"]},phase="projection-control-check-v1")
        print("PROJECTION_NO_FIT_CONTROLS_PASS",flush=True);return
    assert checked(output,"projection-control-check-v1")["status"]=="PROJECTION_NO_FIT_CONTROLS_PASS"
    source=a.comparison_source;splits,bindings=load_source(source,1,digest(source/"risk-source-protocol-v4.receipt.private.json"));audit_source(splits)
    manifest=checked(output,"boundary-controls-fold1");rows=[]
    for name in manifest["batches"]:
        assert digest(output/(name+".receipt.private.json"))==manifest["batches_sha256"][name]
        rows.extend(checked(output,name)["rows"])
    validate_controls(rows,splits);assert len(rows)==240
    protocol_sha=digest(output/"projection-protocol-v1.receipt.private.json")
    binding={"protocol_sha256":protocol_sha,"source_splits_sha256":bindings,"augmentation_sha256":digest(output/"boundary-controls-fold1.receipt.private.json")}
    unit="projection-fit-fold1-candidate"
    with writer(output):
        ledger=CampaignLedger(output,digest(output/"ratio-protocol-v1.receipt.private.json"))
        contents=read_bundle(output,unit,binding,allow_unmarked=True)
        if contents is not None:artifact=joblib.load(io.BytesIO(contents["model.joblib"]));proof=publish_bundle(output,unit,binding,{})
        else:
            ledger.reserve(unit,"composite");signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(900);start=time.monotonic()
            fitting=splits["fit"]+rows;x=np.asarray([model_features(r) for r in fitting]);y=np.asarray([r["training_context"] for r in fitting])
            normal=x[[i for i,r in enumerate(fitting) if r["normal_fit"]]];assert len(normal)==2000 and len(x)==4240
            model=SufficientContextScorer().fit(normal,x,y,lambda component:ledger.reserve(unit,component))
            calibration={c:np.sort(scores(model,np.asarray([model_features(r) for r in splits["calibration"] if r["cohort"]==c]))) for c in ("READY","COLD")}
            assert all(len(v)==5000 for v in calibration.values());artifact={"model":model,"calibration":calibration}
            encoded=io.BytesIO();joblib.dump(artifact,encoded,compress=3);restored=joblib.load(io.BytesIO(encoded.getvalue()))
            probes=x[[0,1999,3999,4000,4119,4239]];assert np.array_equal(scores(model,probes),scores(restored["model"],probes))
            assert all(np.array_equal(calibration[c],restored["calibration"][c]) for c in calibration)
            metadata={"recipe_version":8,"raw_java_schema":6,"raw_width":65,"classifier_width":11,"normal_component_width":37,
                "parameters":PARAMETERS,"normal_fit_rows":2000,"labeled_fit_rows":4240,"calibration_rows":10000,
                "fit_seconds":time.monotonic()-start,"readback_probes":6,"source_class":"DEMO_ONLY_RULE_DISTILLATION"}
            proof=publish_bundle(output,unit,binding,{"model.joblib":encoded.getvalue(),"metadata.json":canonical(metadata).encode()});artifact=restored;signal.alarm(0)
        candidate=evaluate(output,1,"projection",artifact,proof,splits["validation"],protocol_sha,bindings["validation"])
        references={"original37":checked(source,"risk-validation-fold1-baseline"),"previous65":checked(source,"risk-validation-fold1-candidate"),
            "ratio66":checked(output,"risk-validation-fold1-candidate"),"boundary66":checked(output,"risk-validation-fold1-boundary")}
        regressions={name:[k for k,v in report["counts"].items() if candidate["counts"][k]["fp"]>v["fp"] or candidate["counts"][k]["fn"]>v["fn"]] for name,report in references.items()}
        primary=compare(references["previous65"],candidate);go=primary["status"]=="GO_RESEARCH_SCREEN_ONLY" and not any(regressions.values())
        result={"status":"GO_FOR_UNSEEN_REPLICATION_NOT_PASS" if go else "STOP_NO_IMPROVEMENT","protocol_sha256":protocol_sha,
            "primary":primary,"candidate_counts":candidate["counts"]["global"],"candidate_points":candidate["points"],
            "regressions":regressions,"new_round_reserved_fits":ledger.state,"validation_scope":"PREVIOUSLY_INSPECTED_DEVELOPMENT",
            "source_class":"DEMO_ONLY_RULE_DISTILLATION","holdout_scored":False,"auto_containment":False,
            "strict_admission":"INDEPENDENT_OUTCOME_EVIDENCE_REQUIRED"}
        commit(output,result,phase="projection-fold1-result");print(canonical(result),flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mode",choices=("projection-check","projection-pilot"),required=True)
    p.add_argument("--fold",type=int,required=True);p.add_argument("--maximum-seconds",type=int,required=True);run(p.parse_args())
