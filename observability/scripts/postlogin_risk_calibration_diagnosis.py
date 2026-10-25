#!/usr/bin/env python3
"""No-fit decomposition on independent normal CALIBRATION, never holdout."""
import argparse
import io
import json
import zipfile

import joblib
import numpy as np
from scipy.special import logsumexp
from app.normal_support import _signed_log
from postlogin_risk_audit import load_source
from postlogin_risk_rolling import model_features
from postlogin_risk_source import resource_limits
from postlogin_pilot_artifacts import read_bundle
from ueba_research_artifacts import digest,commit,canonical


def run(a):
    assert resource_limits()["verified"]
    splits,bindings=load_source(a.comparison_source,1,digest(a.comparison_source/"risk-source-protocol-v4.receipt.private.json"))
    report={}
    for kind,unit in [("ratio66","ratio-fit-fold1-candidate"),("boundary66","boundary-fit-fold1-candidate")]:
        with zipfile.ZipFile(a.output/(unit+".bundle.zip")) as z: binding=json.loads(z.read("manifest.json"))["binding"]
        assert binding["source_splits_sha256"]==bindings
        content=read_bundle(a.output,unit,binding);artifact=joblib.load(io.BytesIO(content["model.joblib"]))
        model=artifact["model"];report[kind]={}
        for cohort in ("READY","COLD"):
            rows=[r for r in splits["calibration"] if r["cohort"]==cohort]
            assert len(rows)==5000 and not any(r["label"] for r in rows)
            x=np.asarray([model_features(r) for r in rows]);logits=model.classifier._raw_predict(_signed_log(model.values(x)))
            margin=logsumexp(logits[:,1:],axis=1)-logits[:,0]
            novelty=np.log(model.normal.anomaly_scores(x[:,:37])+1e-12)
            fused=np.maximum(margin,novelty)
            assert np.array_equal(np.sort(fused),artifact["calibration"][cohort])
            top=np.argsort(fused)[-50:]
            report[kind][cohort]={"normal_calibration_rows":5000,
                "normal_classifier_context_errors":int(np.sum(np.argmax(logits,axis=1)!=0)),
                "top50_fused_dominated_by_novelty":int(np.sum(novelty[top]>margin[top])),
                "margin_percentiles_50_95_99_100":np.percentile(margin,[50,95,99,100]).tolist(),
                "novelty_percentiles_50_95_99_100":np.percentile(novelty,[50,95,99,100]).tolist()}
    result={"status":"NORMAL_CALIBRATION_COMPONENT_DIAGNOSIS_COMPLETE","reports":report,
        "new_fits":0,"validation_used_for_this_analysis":False,"holdout_scored":False,
        "scope":"MECHANISM_DIAGNOSIS_NOT_THRESHOLD_TUNING_OR_MODEL_SELECTION"}
    commit(a.output,result,phase="ratio-calibration-component-diagnosis-v1");print(canonical(result),flush=True)


if __name__=="__main__":
    from pathlib import Path
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","frozen-code","output","comparison-source"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--fold",type=int,required=True);p.add_argument("--maximum-seconds",type=int,required=True)
    p.add_argument("--mode",required=True);run(p.parse_args())
