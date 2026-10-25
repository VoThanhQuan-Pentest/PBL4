#!/usr/bin/env python3
"""Pinned-image source/scoring/publication integration fixture; zero estimator fits."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import time

from ueba_research_artifacts import canonical, commit, digest, private_directory, publish


class FixedNormal:
    def anomaly_scores(self, values):
        import numpy as np
        if values.shape[1] != 37: raise ValueError("normal component received non-prefix features")
        return np.ones(len(values))


class FixedClassifier:
    def _raw_predict(self, values):
        import numpy as np
        return np.zeros((len(values), 3))


class FixtureScorer:
    def anomaly_scores(self, values):
        import numpy as np
        return np.full(len(values), 0.5)


def run(output, fixture):
    started = time.monotonic()
    signal.signal(signal.SIGALRM, signal.SIG_DFL); signal.alarm(180)
    output = private_directory(output); fixture = private_directory(fixture)
    import joblib
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from app.hybrid_incident import HybridIncidentScorer
    from app.normal_support import NormalSupportScorer
    import postlogin_pilot_data as data
    from postlogin_pilot_model import new_model
    from postlogin_pilot_source import classpath, export_chunk
    from postlogin_pilot_artifacts import writer, publish_bundle, read_bundle
    spec = importlib.util.spec_from_file_location("pilot", Path(__file__).with_name("run-ueba-postlogin-pilot.py"))
    pilot = importlib.util.module_from_spec(spec); spec.loader.exec_module(pilot)
    def forbid(*_args, **_kwargs): raise AssertionError("estimator fit forbidden in integration fixture")
    for cls in (HybridIncidentScorer, NormalSupportScorer, HistGradientBoostingClassifier): cls.fit = forbid
    protocol = json.loads((output / "pilot.protocol.private.json").read_text())
    for name, expected in protocol["code_sha256"].items():
        if digest(Path(__file__).parent / name) != expected: raise ValueError("pilot snapshot changed")
    fitting = list(data.specifications(1, "fit"))
    chosen = [fitting[i] for i in (0, 3000, 3200, 3400, 3600, 3800)]
    chosen += [list(data.specifications(1, "calibration"))[5000], list(data.specifications(1, "validation"))[14000]]
    cp = classpath(output)
    rows = export_chunk(fixture, chosen, cp)
    reference = {r["frame_id"]: r for r in json.loads((output / "p3-source-benchmark.numeric.private.json").read_text())["rows"]}
    compared = 0
    for row in rows:
        if row["frame_id"] in reference:
            wanted = reference[row["frame_id"]]
            if any(row[key] != wanted[key] for key in ("baseline_features", "postlogin_features")):
                raise ValueError("integrated source differs from predeclared benchmark")
            compared += 1
    baseline, candidate = new_model("baseline"), new_model("candidate")
    baseline._normal = FixedNormal(); baseline._classifier = FixedClassifier()
    candidate.normal = FixedNormal(); candidate.classifier = FixedClassifier()
    if not np.array_equal(baseline.anomaly_scores(pilot.matrix(rows, "baseline")), candidate.anomaly_scores(pilot.matrix(rows, "candidate"))):
        raise ValueError("candidate fusion differs with identical fixed components")
    renamed = copy.deepcopy(rows)
    for row in renamed:
        row["label"] = 1 - row["label"]; row["account_id"] = "renamed-account"; row["planned_cause"] = "never-model-input"
    for kind in ("baseline", "candidate"):
        if not np.array_equal(pilot.matrix(rows, kind), pilot.matrix(renamed, kind)):
            raise ValueError("metadata leaked into numeric model input")
    publish(fixture / "operator-state.private.json", {"scope": "NO_FIT_INTEGRATION_FIXTURE"})
    publish(fixture / "p3-source-benchmark.receipt.private.json", {"elapsed_seconds": 0})
    source_hash = hashlib.sha256(canonical(rows).encode()).hexdigest()
    with writer(fixture):
        budget = pilot.Budget(fixture)
        rules = pilot.rule_decisions(fixture, 1, rows, source_hash, budget)
        blob = io.BytesIO(); joblib.dump({"model": FixtureScorer(), "calibration": {
            "READY": np.linspace(0, 1, 5000), "COLD": np.linspace(0, 1, 5000)}}, blob)
        binding = {"scope": "FIXTURE_NO_ESTIMATOR_FIT", "pilot_protocol_sha256": digest(output / "pilot.protocol.private.json")}
        publish_bundle(fixture, "fixture-model-bundle", binding, {"model.joblib": blob.getvalue()})
        checked = read_bundle(fixture, "fixture-model-bundle", binding)
        result = pilot.evaluated_unit(fixture, 1, "fixture", checked, rows, rules, binding, budget)
        FixtureScorer.anomaly_scores = forbid
        if pilot.evaluated_unit(fixture, 1, "fixture", checked, rows, rules, binding, budget) != result:
            raise ValueError("verified evaluation not reused")
        if budget.state["composite_invocations"] or budget.state["component_invocations_recorded_before_call"]:
            raise ValueError("fixture unexpectedly trained")
    receipt = {"status": "PIPELINE_INTEGRATION_FIXTURE_PASS", "scope": "SOURCE_ACTUAL_JAVA_AND_RULE_ENGINE_FIXED_SCORERS_NO_ESTIMATOR_FITS",
        "verifier_sha256": digest(__file__),
        "pilot_protocol_sha256": digest(output / "pilot.protocol.private.json"), "fixture_source_sha256": source_hash,
        "rows": len(rows), "cohorts": sorted({r["cohort"] for r in rows}), "benchmark_rows_compared": compared,
        "actual_java_rule_rows": len(rules), "verified_evaluation_reused_without_scoring": True,
        "additional_fit_calls": 0, "holdout_scored": False, "auto_containment": False, "aws_changed": False,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "limits": "Fixed scorers validate plumbing only; actual fit/calibration roundtrip must pass on the first bounded real pilot unit."}
    commit(fixture, receipt, phase="pipeline-integration")
    signal.alarm(0)
    print(canonical(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args(); run(args.output.absolute(), args.fixture.absolute())
