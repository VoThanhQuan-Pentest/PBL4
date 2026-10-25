#!/usr/bin/env python3
"""Bounded, reproducible DEMO_ONLY events, Java feature export and frozen temporal splits."""

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "observability/runtime/ueba-experiments"
FAMILIES = ("request_burst", "endpoint_scan", "auth_failure_burst", "sensitive_action_burst", "http_error_burst")
FOLDS = {1: ((15, 28), (29, 31), (32, 35)),
         2: ((15, 35), (36, 38), (39, 42)),
         3: ((16, 42), (43, 45), (46, 49))}
ROUTES = ("products", "search", "cart", "orders", "profile", "support", "payments")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def stable_seed(*parts):
    return int.from_bytes(hashlib.sha256("/".join(map(str, parts)).encode()).digest()[:8], "big")


def assignments(seed, accounts, days, count=1000):
    choices = [(account, day, slot) for account in accounts for day in days for slot in range(12)]
    rng = random.Random(seed)
    selected = rng.sample(choices, count)
    return {key: FAMILIES[index % 5] for index, key in enumerate(selected)}


def account_profile(account):
    rng = random.Random(stable_seed("profile", account))
    return {"requests": (4, 8, 15, 25, 40, 65)[account % 6],
            "routes": 1 + account % 5, "utc_start": rng.choice((1, 2, 6, 9, 13, 17)),
            "ua": ("CHROMIUM", "FIREFOX", "WEBKIT")[account % 3],
            "ip": f"198.51.100.{1 + account % 200}"}


def event(at, kind, action, outcome, ip, ua, status=None, route=None):
    value = {"event_timestamp": at.isoformat().replace("+00:00", "Z"),
             "event_type": kind, "action": action, "outcome": outcome,
             "source_ip": ip, "user_agent_family": ua}
    if status is not None: value["http_status"] = status
    if route is not None: value["route_group"] = route
    return value


def frame(dataset, account, day, slot, anchor, family="normal", cohort="DEVELOPMENT"):
    profile = account_profile(account)
    seed_kind = "holdout" if day >= 50 else "development"
    rng = random.Random(stable_seed(seed_kind, dataset, account, day, slot))
    start = anchor + timedelta(days=day - 1, hours=profile["utc_start"], minutes=slot * 30)
    # Shifts never wrap beyond the metadata UTC day, preserving temporal folds.
    assert start.date() == (anchor + timedelta(days=day - 1)).date()
    requests = max(2, round(profile["requests"] * rng.lognormvariate(0, 0.30)))
    route_count = min(requests, max(1, profile["routes"] + rng.choice((-1, 0, 0, 0, 1))))
    ip, ua = profile["ip"], profile["ua"]
    client_errors = server_errors = failed = sensitive = 0
    successful = rng.choice((0, 0, 1, 1, 2))
    variant = rng.random()
    if variant < 0.04: client_errors = min(requests, rng.choice((1, 2, 3)))
    elif variant < 0.07: failed = rng.choice((1, 2))
    elif variant < 0.09: sensitive = 1
    elif variant < 0.105:
        ip, ua = f"203.0.113.{1 + account % 200}", "FIREFOX" if ua != "FIREFOX" else "CHROMIUM"
    elif variant < 0.12: server_errors = min(requests, rng.choice((1, 2)))
    elif variant < 0.135: requests = min(180, requests * 2)
    if family != "normal":
        ip, ua = f"203.0.113.{1 + (account + 37) % 200}", "SCANNER"
        if family == "request_burst":
            requests = min(1200, max(150, requests * rng.randint(6, 14)))
            client_errors = min(requests, rng.randint(5, 15))
            route_count = min(requests, 8 + rng.randrange(12))
        elif family == "endpoint_scan":
            requests = rng.randint(70, 200)
            client_errors = rng.randint(30, requests)
            route_count = min(requests, rng.randint(20, 45))
        elif family == "auth_failure_burst":
            requests, client_errors, server_errors = rng.randint(2, 8), 0, 0
            route_count = 1
            failed, successful = rng.randint(12, 45), rng.choice((0, 1))
        elif family == "sensitive_action_burst":
            requests, client_errors, server_errors = rng.randint(3, 12), 0, 0
            route_count = 2
            sensitive, successful = rng.randint(8, 25), rng.randint(1, 3)
        elif family == "http_error_burst":
            requests = rng.randint(70, 220)
            client_errors = rng.randint(5, 15)
            server_errors = rng.randint(25, requests - client_errors)
            route_count = min(requests, 7 + rng.randrange(8))
    events = []
    for index in range(requests):
        status = 404 if index < client_errors else 503 if index < client_errors + server_errors else 200
        route = ROUTES[index % min(route_count, len(ROUTES))] if route_count <= len(ROUTES) else f"group_{index % route_count}"
        events.append(event(start + timedelta(seconds=index % 840 + 1), "HTTP_REQUEST", "API_REQUEST",
                            "FAILURE" if status >= 400 else "SUCCESS", ip, ua, status, route))
    for index in range(failed): events.append(event(start + timedelta(seconds=841 + index), "AUTH", "LOGIN", "FAILURE", ip, ua))
    for index in range(successful): events.append(event(start + timedelta(seconds=886 + index), "AUTH", "LOGIN", "SUCCESS", ip, ua))
    for index in range(sensitive): events.append(event(start + timedelta(seconds=860 + index), "DOMAIN_ACTION",
                                                     ("PASSWORD_CHANGE", "EMAIL_CHANGE", "PASSWORD_RESET")[index % 3], "SUCCESS", ip, ua))
    if max((item["event_timestamp"] for item in events), default="") >= (start + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"):
        raise ValueError("Event generation exceeded its window")
    return {"frame_id": f"{dataset}-a{account:03d}-d{day:02d}-s{slot:02d}",
            "account_id": f"{dataset}-account-{account:03d}", "day": day, "cohort": cohort,
            "window_start": start.isoformat().replace("+00:00", "Z"),
            "demo_label": "NORMAL" if family == "normal" else "ABNORMAL", "family": family, "events": events}


def frames(dataset, anchor):
    abnormal = {}
    for number, (_, _, validation) in FOLDS.items():
        abnormal.update(assignments(stable_seed("validation", number), range(1, 151), range(validation[0], validation[1] + 1)))
    abnormal.update(assignments(stable_seed("holdout-seen"), range(1, 151), range(50, 57), 600))
    abnormal.update(assignments(stable_seed("holdout-unseen"), range(151, 201), range(50, 57), 400))
    for account in range(1, 201):
        cohort = "DEVELOPMENT" if account <= 150 else "UNSEEN"
        days = range(1, 57) if account <= 150 else range(36, 57)
        for day in days:
            for slot in range(12):
                yield frame(dataset, account, day, slot, anchor, abnormal.get((account, day, slot), "normal"), cohort)


def choose(rows, count, seed):
    if len(rows) < count: raise ValueError(f"Insufficient independent windows: {len(rows)} < {count}")
    selected = random.Random(seed).sample(rows, count)
    return sorted(selected, key=lambda row: (row["window_start"], row["account_id"], row["frame_id"]))


def write_split(destination, name, rows):
    selected = [{key: row[key] for key in ("frame_id", "account_id", "window_start", "label", "family",
                                           "baseline_established", "features", "rule_only_risk", "rule_only_incident")}
                for row in rows]
    path = destination / f"{name}.json"
    with path.open("x", encoding="utf-8") as output:
        json.dump({"split_name": name, "data_provenance": "DEMO_ONLY", "feature_schema_version": 2,
                   "records": selected}, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
    path.chmod(0o600)
    return {"path": path.name, "sha256": digest(path), "windows": len(rows),
            "normal_windows": sum(row["label"] == 0 for row in rows),
            "abnormal_windows": sum(row["label"] == 1 for row in rows),
            "accounts": len({row["account_id"] for row in rows}),
            "from": min(row["window_start"] for row in rows), "to": max(row["window_start"] for row in rows),
            "families": dict(Counter(row["family"] for row in rows))}


def prepare(dataset, anchor):
    if not re.fullmatch(r"[a-z0-9_-]{8,32}", dataset): raise ValueError("Invalid dataset ID")
    RUNTIME.mkdir(parents=True, mode=0o700, exist_ok=True)
    destination = RUNTIME / dataset
    destination.mkdir(mode=0o700)  # No overwriting or resetting an existing experiment.
    event_file, feature_file = destination / "events.ndjson", destination / "features.ndjson"
    with event_file.open("x", encoding="utf-8") as output:
        for index, value in enumerate(frames(dataset, anchor), 1):
            output.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")
            if index % 5000 == 0: print(f"DEMO_ONLY raw windows generated: {index}", flush=True)
    event_file.chmod(0o600)
    classpath = ROOT / "backend/target/ueba-experiment.classpath"
    if not classpath.is_file(): raise ValueError("Build backend and target/ueba-experiment.classpath first")
    with event_file.open("rb") as source, feature_file.open("xb") as target, (destination / "java-export.log").open("xb") as log:
        command = ["java", "-Xmx1024m", "-cp", str(ROOT / "backend/target/classes") + ":" + classpath.read_text().strip(),
                   "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only"]
        process = subprocess.Popen(command, stdin=source, stdout=target, stderr=log)
        print(f"Java feature exporter PID={process.pid}; log={destination / 'java-export.log'}", flush=True)
        try:
            code = process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise RuntimeError("Java exporter exceeded its bound; managed child was terminated") from None
        if code: raise RuntimeError("Java feature export failed; no campaign manifest published")
    feature_file.chmod(0o600)
    rows = [json.loads(line) for line in feature_file.read_text().splitlines()]
    if len({row["frame_id"] for row in rows}) != len(rows): raise ValueError("Duplicate frame identity")
    splits = {}
    for number, (fit, calibration, validation) in FOLDS.items():
        for kind, days in (("fit", fit), ("calibration", calibration)):
            subset = [row for row in rows if row["cohort"] == "DEVELOPMENT" and row["baseline_established"]
                      and row["label"] == 0 and days[0] <= row["day"] <= days[1]]
            minimum, maximum = (10000, 50000) if kind == "fit" else (2000, 10000)
            if not minimum <= len(subset) <= maximum: raise ValueError("Training/calibration window bound violated")
            splits[f"fold{number}-{kind}"] = write_split(destination, f"fold{number}-{kind}", subset)
        validation_rows = [row for row in rows if row["cohort"] == "DEVELOPMENT" and row["baseline_established"]
                           and validation[0] <= row["day"] <= validation[1]]
        selected = choose([row for row in validation_rows if row["label"] == 0], 5000, stable_seed("validation-normal", number))
        selected += choose([row for row in validation_rows if row["label"] == 1], 1000, stable_seed("validation-abnormal", number))
        splits[f"fold{number}-validation"] = write_split(destination, f"fold{number}-validation", selected)
    final = [row for row in rows if row["baseline_established"] and 50 <= row["day"] <= 56]
    selected = choose([row for row in final if row["label"] == 0 and row["cohort"] == "DEVELOPMENT"], 7500, stable_seed("holdout-normal-seen"))
    selected += choose([row for row in final if row["label"] == 0 and row["cohort"] == "UNSEEN"], 2500, stable_seed("holdout-normal-unseen"))
    selected += choose([row for row in final if row["label"] == 1], 1000, stable_seed("holdout-abnormal"))
    splits["holdout"] = write_split(destination, "holdout", selected)
    source_files = [Path(__file__), ROOT / "backend/src/main/java/com/flarefitness/backend/ops/UebaFeatureExport.java",
                    ROOT / "backend/src/main/java/com/flarefitness/backend/service/siem/AccountBehaviorFeatures.java",
                    ROOT / "backend/src/main/java/com/flarefitness/backend/service/siem/AccountBaselinePolicy.java"]
    manifest = {"dataset_id": dataset, "data_provenance": "DEMO_ONLY", "feature_schema_version": 2,
                "development_accounts": 150, "unseen_accounts": 50, "warmup_days": 14,
                "anchor_utc": anchor.isoformat(), "raw_event_frames": len(rows),
                "event_file_sha256": digest(event_file), "feature_file_sha256": digest(feature_file),
                "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in source_files},
                "compiled_feature_sha256": {name: digest(ROOT / "backend/target/classes" / name)
                    for name in ("com/flarefitness/backend/ops/UebaFeatureExport.class",
                                 "com/flarefitness/backend/service/siem/AccountBehaviorFeatures.class",
                                 "com/flarefitness/backend/service/siem/AccountBaselinePolicy.class")},
                "split_strategy": "past_only_temporal_with_unseen_accounts_and_label_independent_baselines",
                "fold_days": {str(key): value for key, value in FOLDS.items()}, "splits": splits}
    with (destination / "manifest.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, sort_keys=True, indent=2)
    (destination / "manifest.json").chmod(0o600)
    print(f"Frozen dataset ready: {destination}; windows={len(rows)}; holdout=11000", flush=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--anchor", help="UTC midnight ISO date, default 64 days before today")
    args = parser.parse_args()
    if args.anchor:
        anchor = datetime.fromisoformat(args.anchor.replace("Z", "+00:00"))
        if anchor.tzinfo is not None and anchor.utcoffset() != timedelta(0): parser.error("Anchor must use UTC")
        anchor = anchor.replace(tzinfo=timezone.utc)
    else:
        anchor = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=64)
    if anchor.hour or anchor.minute or anchor.second or anchor.microsecond:
        parser.error("Anchor must be UTC midnight")
    if anchor + timedelta(days=56) > datetime.now(timezone.utc) - timedelta(minutes=15):
        parser.error("All windows must be historical")
    prepare(args.dataset_id, anchor)


if __name__ == "__main__": main()
