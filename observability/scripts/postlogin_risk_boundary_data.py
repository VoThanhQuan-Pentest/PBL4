"""Explicit synthetic FIT-only boundary controls, exported again by real Java.

No validation episodes, hidden actor labels, proof outcomes or numeric feature
edits are used. This remains rule-distillation, not incident ground truth.
"""
import copy
from datetime import timedelta
import hashlib

from postlogin_risk_contract import instant, reference
from postlogin_risk_rolling import expected_rolling, model_features
from postlogin_risk_source import export_selected
from ueba_research_artifacts import canonical, commit
from postlogin_risk_result_diagnosis import checked


def controls(data, fold, number=240):
    data.DATASET_ID = "postlogin-fit-boundary-controls-20261021-v1"
    templates = list(data.specifications(fold, "fit"))
    selected=[]
    for i in range(number):
        count = 60 + i // 2
        if number==24: count=119+i%2
        spec={**templates[2000+i],"account":64000+fold*1024+i,"episode":0,"cause":"normal"}
        raw,old=data.build(spec)
        attempt=raw["attempt"]; at=instant(attempt["event_timestamp"])
        http=[e for frame in raw["baseline_frames"] for e in frame["events"] if e.get("event_type")=="HTTP_REQUEST"]
        http += [e for e in raw["context"] if e.get("event_type")=="HTTP_REQUEST"]
        if not http: raise ValueError("frozen world lacks a valid HTTP event template")
        prototype=http[0]
        for history in raw["baseline_frames"]:
            start=instant(history["window_start"])
            session=hashlib.sha256(canonical([history["frame_id"],"boundary-history-session"]).encode()).hexdigest()
            history["events"]=[]
            for k in range(20):
                event=copy.deepcopy(prototype)
                event.update(event_timestamp=(start+timedelta(seconds=100+k)).isoformat(),http_status=200)
                # Historical windows bind the account at frame level and use
                # their frozen schema3 event vocabulary, not schema4's prefix.
                if "session_pseudonym" in event:
                    event.update(session_pseudonym=session,session_issued_at=(start-timedelta(seconds=1)).isoformat())
                history["events"].append(event)
        issued=instant(attempt["session_issued_at"])
        begin=max(at-timedelta(seconds=10),issued+timedelta(microseconds=1))
        if begin>=at: raise ValueError("current session has no observable past interval")
        raw["context"]=[e for e in raw["context"] if e.get("event_type")=="AUTH" and e.get("outcome")=="SUCCESS"]
        for k in range(count):
            fields={"event_id","actor_user_id","target_user_id","event_type","action","outcome",
                    "event_timestamp","telemetry_contract_version","session_pseudonym","session_issued_at",
                    "http_status","endpoint_category","http_method","route_group","source_ip","user_agent_family"}
            event={key:copy.deepcopy(value) for key,value in prototype.items() if key in fields}
            event.update(event_id=raw["frame_id"]+f":boundary-http-{k}",actor_user_id=attempt["actor_user_id"],
                event_timestamp=(begin+(at-begin)*(k+1)/(count+1)).isoformat(),
                session_pseudonym=attempt["session_pseudonym"],session_issued_at=attempt["session_issued_at"],
                telemetry_contract_version=4,http_status=200)
            raw["context"].append(event)
        target=reference(raw)
        expected=0 if count<120 else 1
        if target["training_context"]!=expected or target["reference_observations"]["requests"]!=count:
            raise ValueError("declared raw-only boundary intervention changed another context")
        metadata={**old,"legacy_planned_label":old["label"],"legacy_planned_family":old["family"],
            "legacy_planned_training_context":old["training_context"],"label":target["label"],
            "training_context":target["training_context"],"family":target["family"],
            "task_id":"postlogin-observable-risk-context-v1","feature_schema_version":6,"recipe_version":5,
            "source_account_ordinal":spec["account"],"source_episode_ordinal":0,"selection_attempts":1,
            "reference":target,"expected_rolling":expected_rolling(raw),"normal_fit":False,
            "split":"fit","source_intervention":"FIT_ONLY_RAW_HTTP_COUNTS_60_TO_179_HISTORY20",
            "raw_frame_sha256":hashlib.sha256(canonical(raw).encode()).hexdigest()}
        selected.append((spec,raw,metadata))
    return selected


def export_controls(data, fold, output, classpath, number=240):
    selected=controls(data,fold,number)
    rows=[]
    for offset in range(0,number,32):
        chunk=selected[offset:offset+32]
        phase=f"boundary-control-rows-f{fold}-n{number}-b{offset//32:03d}"
        binding={"fold":fold,"number":number,"offset":offset,
                 "raw_frames_sha256":hashlib.sha256(canonical([item[1] for item in chunk]).encode()).hexdigest()}
        if (output/(phase+".commit.private.json")).exists():
            retained=checked(output,phase)
            if retained["binding"]!=binding: raise ValueError("boundary raw batch binding changed")
        else:
            retained={"binding":binding,"rows":export_selected(output,chunk,classpath)}
            commit(output,retained,phase=phase)
        rows.extend(retained["rows"])
    if len(rows)!=number or len({r["frame_id"] for r in rows})!=number:
        raise ValueError("boundary controls lost identities")
    for row in rows:
        model_features(row)
        if row["cohort"]!="READY" or row["split"]!="fit" or row["normal_fit"]:
            raise ValueError("boundary controls must not enter calibration, validation, UNSEEN or the normal component")
    return rows
