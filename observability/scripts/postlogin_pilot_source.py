"""Bounded, resumable source batches through the measured real Java producer."""
import importlib.util
import json
from pathlib import Path
import subprocess

import postlogin_pilot_data as data
from ueba_research_artifacts import canonical, commit, digest

BATCH_ROWS = 32


def classpath(output):
    overlay = output / "java-overlay-stream"
    identity = json.loads((overlay / "identity.private.json").read_text())
    for name, expected in identity["overlay_classes_sha256"].items():
        if digest(overlay / "classes" / name) != expected: raise ValueError("Java overlay changed")
    checker = Path(__file__).with_name("audit-ueba-postlogin-representation.py")
    spec = importlib.util.spec_from_file_location("pilot_workspace", checker)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    base, _ = module.pinned_workspace(identity["base_workspace"], identity["base_workspace_snapshot_sha256"])
    return str(overlay / "classes") + ":" + base


def read_committed(output, unit):
    marker = output / (unit + ".commit.private.json")
    if not marker.exists(): return None
    proof = json.loads(marker.read_text())
    path = output / proof["receipt"]
    if proof.get("receipt") != unit + ".receipt.private.json" or digest(path) != proof["receipt_sha256"]:
        raise ValueError("committed source batch changed")
    return json.loads(path.read_text())


def export_chunk(output, specifications, java_classpath, *, build=None, rolling=False):
    rows = []
    with (output / "pilot-source.java.log").open("ab") as log:
        (output / "pilot-source.java.log").chmod(0o600)
        process = subprocess.Popen(["java", "-Xmx256m", "-cp", java_classpath,
            "com.flarefitness.backend.ops.PostLoginFeatureExport", "--demo-risk-context-only" if rolling else "--demo-only"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        try:
            def transmit(value):
                raw = (canonical(value) + "\n").encode()
                if len(raw) > 2 * 1024**2: raise ValueError("source frame byte bound exceeded")
                process.stdin.write(raw); process.stdin.flush()
                response = process.stdout.readline(32 * 1024)
                if not response or len(response) >= 32 * 1024: raise ValueError("Java source export failed")
                return json.loads(response)
            for specification in specifications:
                frame, metadata = (build or data.build)(specification)
                context_ids = [item["frame_id"] for item in frame["baseline_frames"]]
                sessions = sorted({data.digest([e["actor_user_id"], e["session_pseudonym"], e["session_issued_at"]])
                    for e in [frame["attempt"], *frame["context"]] if e.get("actor_user_id") and e.get("session_pseudonym")})
                for baseline in frame["baseline_frames"]:
                    if transmit({"baseline_frame": baseline}).get("warmup_frame_id") != baseline["frame_id"]:
                        raise ValueError("warmup mapping changed")
                frame["baseline_frames"] = []
                numeric = transmit(frame)
                if (numeric["frame_id"] != metadata["frame_id"] or numeric["baseline_established"] != (metadata["cohort"] != "COLD")
                        or numeric["representation_version"] != ("postlogin-risk-rolling-account-v2" if rolling else "postlogin-before-action-v1")
                        or len(numeric["baseline_features"]) != 37 or len(numeric["postlogin_features"]) != 20
                        or numeric["postlogin_features"][2] != 1 or numeric["before_current_outcome"] is not True):
                    raise ValueError("source/producer/session/chronology parity failed")
                extra = {}
                if rolling:
                    if numeric.get("feature_schema_version") != 6 or len(numeric.get("rolling_features", [])) != 8:
                        raise ValueError("new rolling account producer schema/width changed")
                    extra = {"rolling_features": numeric["rolling_features"]}
                rows.append({**metadata, "baseline_established": numeric["baseline_established"],
                    "trusted_window_count": numeric["trusted_window_count"], "baseline_features": numeric["baseline_features"],
                    "postlogin_features": numeric["postlogin_features"], "context_frame_ids": context_ids,
                    "session_fingerprints": sessions, "source_window_start": specification["window_start"], **extra})
            process.stdin.close()
            if process.stdout.read(1) or process.wait(timeout=15): raise ValueError("source child did not terminate cleanly")
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)
    return rows


def load_split(output, fold, split, protocol_sha256, budget, java_classpath):
    specifications = list(data.specifications(fold, split))
    rows = []; proofs = []
    for index in range(0, len(specifications), BATCH_ROWS):
        budget.check()
        unit = f"source-f{fold}-{split}-{index // BATCH_ROWS:04d}"
        expected = {"protocol_sha256": protocol_sha256, "fold": fold, "split": split, "offset": index,
                    "count": len(specifications[index:index + BATCH_ROWS])}
        retained = read_committed(output, unit)
        if retained is None:
            budget.begin(unit, seconds=60)
            actual = export_chunk(output, specifications[index:index + BATCH_ROWS], java_classpath)
            retained = {"binding": expected, "rows": actual}
            proof = commit(output, retained, phase=unit)
            budget.finish(unit, proof)
        if retained["binding"] != expected or len(retained["rows"]) != expected["count"]:
            raise ValueError("source batch binding/count mismatch")
        rows.extend(retained["rows"])
        proofs.append(digest(output / (unit + ".commit.private.json")))
    return rows, data.digest(proofs)
