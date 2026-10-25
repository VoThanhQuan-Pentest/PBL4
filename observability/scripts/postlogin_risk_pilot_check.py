#!/usr/bin/env python3
"""No-fit pilot control checks inside the pinned offline worker."""
import argparse
import io
from pathlib import Path
import tempfile

import joblib
import numpy as np

from postlogin_risk_model import ObservableContextScorer
from postlogin_risk_pilot import compare, fit_unit
from postlogin_pilot_artifacts import publish_bundle
from postlogin_risk_source import resource_limits
from postlogin_risk_audit import audit_history
from ueba_research_artifacts import commit, private_directory


def report(fn, fp=0):
    return {"counts": {"global": {"tp": 1000 - fn, "fn": fn, "fp": fp, "tn": 20000 - fp},
                       "action/EMAIL_CHANGE": {"tp": 500 - fn, "fn": fn, "fp": fp, "tn": 10000 - fp}}}


def run(output):
    if not resource_limits()["verified"]:
        raise RuntimeError("capped offline worker required")
    assert compare(report(100), report(75))["status"] == "GO_RESEARCH_SCREEN_ONLY"
    assert compare(report(100), report(76))["status"] == "STOP_NO_IMPROVEMENT"
    assert compare(report(100), report(75, 1))["status"] == "STOP_NO_IMPROVEMENT"
    assert compare(report(0), report(0))["status"] == "BASELINE_PROMISING_REQUIRES_REPLICATION"
    for cohort, windows in (("COLD", 3), ("READY", 48), ("UNSEEN_READY", 48)):
        row = dict(cohort=cohort, trusted_window_count=windows, baseline_established=cohort != "COLD",
                   context_frame_ids=list(range(windows)), rolling_features=[0.] * 7 + [1.])
        audit_history(row)
        row["baseline_established"] = not row["baseline_established"]
        try:
            audit_history(row)
        except ValueError:
            pass
        else:
            raise AssertionError("invented cohort readiness accepted")
    for projection, width in (("baseline", 37), ("candidate", 65)):
        scorer = ObservableContextScorer(projection)
        assert scorer.values(np.zeros((2, 65))).shape == (2, width)
        try:
            scorer.values(np.zeros((2, 57)))
        except ValueError:
            pass
        else:
            raise AssertionError("legacy-width padding accepted")
    class NoFitAllowed:
        def reserve(self, *args):
            raise AssertionError("resume attempted a new fit")
    with tempfile.TemporaryDirectory(prefix="pilot-control-", dir=output) as scratch:
        root = private_directory(Path(scratch))
        binding = {"protocol_sha256": "control", "source_splits_sha256": {}, "projection": "baseline"}
        artifact = {"model": "NO_FITTED_MODEL_CONTROL", "calibration": {"READY": np.arange(5), "COLD": np.arange(5)}}
        encoded = io.BytesIO()
        joblib.dump(artifact, encoded)
        publish_bundle(root, "risk-fit-fold1-baseline", binding, {"model.joblib": encoded.getvalue()})
        restored, proof = fit_unit(root, 1, "baseline", {}, {}, "control", NoFitAllowed())
        assert restored["model"] == artifact["model"] and proof["reused"]
        assert np.array_equal(restored["calibration"]["READY"], artifact["calibration"]["READY"])
    result = {"status": "PILOT_CONTROL_PREFLIGHT_PASS", "new_fits": 0,
              "checks": ["primary_error_reduction_boundary", "protected_slice_regression", "low_error_branch",
                         "schema_projection_rejects_padding", "committed_bundle_resume_without_fit", "frozen_sparse_history_semantics"]}
    commit(output, result, phase="risk-pilot-control-check-v2")
    print(result, flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "frozen-code", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--fold", type=int, required=True)
    p.add_argument("--maximum-seconds", type=int, required=True)
    args = p.parse_args()
    run(private_directory(args.output))
