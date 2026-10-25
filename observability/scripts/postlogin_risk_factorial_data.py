"""Orthogonal synthetic FIT controls; all numeric features come from real Java.

The previous controls fixed history at20 and endpoint count at0, correlating
absolute and relative volume. This fixed Cartesian design breaks that shortcut.
"""
import copy
from itertools import product
from datetime import timedelta
import hashlib
from postlogin_risk_contract import instant,reference
from postlogin_risk_rolling import expected_rolling,model_features
from postlogin_risk_source import export_selected
from postlogin_risk_result_diagnosis import checked
from ueba_research_artifacts import canonical,commit

REQUESTS=(60,80,100,119,120,121,140,179)
HISTORY=(5,10,20,40,80)
ENDPOINTS=(0,4,8)
VERSION="postlogin-factorial-fit-controls-20261021-v1"
FIELDS={"event_id","actor_user_id","target_user_id","event_type","action","outcome","event_timestamp",
        "telemetry_contract_version","session_pseudonym","session_issued_at","http_status","endpoint_category",
        "http_method","route_group","source_ip","user_agent_family"}


def export(data,fold,output,classpath):
    data.DATASET_ID=VERSION;templates=list(data.specifications(fold,"fit"))
    lattice=list(product(REQUESTS,HISTORY,ENDPOINTS,("PASSWORD_CHANGE","EMAIL_CHANGE")))
    assert len(lattice)==240
    rows=[]
    for offset in range(0,240,32):
        phase=f"factorial-control-rows-f{fold}-b{offset//32:03d}"
        binding={"version":VERSION,"fold":fold,"offset":offset,"design_sha256":hashlib.sha256(canonical(lattice).encode()).hexdigest()}
        if (output/(phase+".commit.private.json")).exists():
            retained=checked(output,phase);assert retained["binding"]==binding;rows.extend(retained["rows"]);continue
        selected=[]
        for i in range(offset,min(offset+32,240)):
            count,median,categories,operation=lattice[i]
            spec={**templates[2000+i],"account":64000+fold*1024+i,"episode":0,"cause":"normal","current_operation":operation}
            raw,old=data.build(spec);attempt=raw["attempt"];at=instant(attempt["event_timestamp"])
            prototype=next(e for h in raw["baseline_frames"] for e in h["events"] if e.get("event_type")=="HTTP_REQUEST")
            for h in raw["baseline_frames"]:
                start=instant(h["window_start"]);session=hashlib.sha256(canonical([h["frame_id"],VERSION]).encode()).hexdigest();h["events"]=[]
                for k in range(median):
                    e=copy.deepcopy(prototype);e.update(event_timestamp=(start+timedelta(seconds=100+k)).isoformat(),http_status=200)
                    if "session_pseudonym" in e:e.update(session_pseudonym=session,session_issued_at=(start-timedelta(seconds=1)).isoformat())
                    h["events"].append(e)
            begin=max(at-timedelta(seconds=10),instant(attempt["session_issued_at"])+timedelta(microseconds=1));assert begin<at
            raw["context"]=[e for e in raw["context"] if e.get("event_type")=="AUTH" and e.get("outcome")=="SUCCESS"]
            for k in range(count):
                e={key:copy.deepcopy(value) for key,value in prototype.items() if key in FIELDS}
                e.update(event_id=raw["frame_id"]+f":factorial-http-{k}",actor_user_id=attempt["actor_user_id"],
                    event_timestamp=(begin+(at-begin)*(k+1)/(count+1)).isoformat(),session_pseudonym=attempt["session_pseudonym"],
                    session_issued_at=attempt["session_issued_at"],telemetry_contract_version=4,http_status=200)
                if categories:e["endpoint_category"]="FACTORIAL_ROUTE_"+str(k%categories)
                else:e.pop("endpoint_category",None)
                raw["context"].append(e)
            target=reference(raw);rolling=expected_rolling(raw)
            assert rolling[0]==count and rolling[1]==categories and rolling[6]==median and target["coverage"]=="COVERED"
            metadata={**old,"legacy_planned_label":old["label"],"legacy_planned_family":old["family"],"legacy_planned_training_context":old["training_context"],
                "label":target["label"],"training_context":target["training_context"],"family":target["family"],"task_id":"postlogin-observable-risk-context-v1",
                "feature_schema_version":6,"recipe_version":5,"source_account_ordinal":spec["account"],"source_episode_ordinal":0,
                "selection_attempts":1,"reference":target,"expected_rolling":rolling,"normal_fit":False,"split":"fit",
                "source_intervention":VERSION,"raw_frame_sha256":hashlib.sha256(canonical(raw).encode()).hexdigest()}
            selected.append((spec,raw,metadata))
        retained={"binding":binding,"rows":export_selected(output,selected,classpath)};commit(output,retained,phase=phase);rows.extend(retained["rows"])
    assert len(rows)==240 and len({r["frame_id"] for r in rows})==240
    assert all(r["cohort"]=="READY" and not r["normal_fit"] and r["split"]=="fit" for r in rows)
    assert sum(r["label"]==0 for r in rows)==162 and sum(r["label"]==1 for r in rows)==78
    for row in rows:model_features(row)
    return rows
