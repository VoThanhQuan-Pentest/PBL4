"""Explain frozen FIT/calibration behavior; no fit, tuning, or holdout reads."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

import joblib
import numpy as np
from scipy.special import logsumexp
from sklearn.metrics import confusion_matrix

from postlogin_data_quality import load_split, read
from postlogin_pilot_artifacts import read_bundle
from ueba_research_artifacts import canonical, commit, digest, private_directory


def run(source, output):
    protocol = read(source / "pilot.protocol.private.json")
    binding = protocol["source_binding_sha256"]
    if digest(source / "pilot.source.identity.private.json") != binding:
        raise ValueError("frozen source changed")
    splits, hashes = {}, {}
    for split in ("fit", "calibration"):
        splits[split], proof = load_split(source, split, binding)
        hashes[split] = hashlib.sha256(canonical(proof).encode()).hexdigest()
    results = {}
    for kind, width in (("baseline", 37), ("candidate", 57)):
        unit = "fit-fold1-" + kind
        with zipfile.ZipFile(source / (unit + ".bundle.zip")) as z:
            model_binding = json.loads(z.read("manifest.json"))["binding"]
        if (model_binding["protocol_sha256"] != digest(source / "pilot.protocol.private.json")
                or model_binding["fit_sha256"] != hashes["fit"]
                or model_binding["calibration_sha256"] != hashes["calibration"]):
            raise ValueError("own frozen model/source binding changed")
        contents = read_bundle(source, unit, model_binding)
        # Only the hash-verified, locally generated and committed model is loaded.
        retained = joblib.load(io.BytesIO(contents["model.joblib"]))
        model = retained["model"]
        classifier = model._classifier if kind == "baseline" else model.classifier
        normal = model._normal if kind == "baseline" else model.normal
        entries = {}
        for split, rows in splits.items():
            x = np.asarray([r["baseline_features"] + r["postlogin_features"] for r in rows])[:, :width]
            transformed = np.sign(x) * np.log1p(np.abs(x))
            logits = classifier._raw_predict(transformed)
            margin = logsumexp(logits[:, 1:], axis=1) - logits[:, 0]
            distance = np.concatenate([normal.anomaly_scores(x[i:i + 1000, :37]) for i in range(0, len(x), 1000)])
            novelty = np.log(distance + 1e-12)
            fused = np.maximum(margin, novelty)
            y = np.asarray([r["training_context"] for r in rows])
            predicted = classifier.predict(transformed)
            entries[split] = {"confusion": confusion_matrix(y, predicted, labels=[0, 1, 2]).tolist(),
                              "accuracy": float(np.mean(y == predicted)),
                              "novelty_dominates_count": int(np.sum(novelty > margin)), "groups": {}}
            groups = sorted({(r["cohort"], r["family"]) for r in rows})
            for cohort, family in groups:
                mask = np.array([r["cohort"] == cohort and r["family"] == family for r in rows])
                bucket = retained["calibration"]["READY" if cohort != "COLD" else "COLD"]
                entries[split]["groups"][cohort + "/" + family] = {
                    "count": int(np.sum(mask)), "margin_quantiles": np.quantile(margin[mask], [0, .5, .9, 1]).tolist(),
                    "fused_quantiles": np.quantile(fused[mask], [0, .5, .9, 1]).tolist(),
                    "above_frozen_calibration_max": int(np.sum(fused[mask] > np.max(bucket)))}
        results[kind] = {"model_bundle_sha256": digest(source / (unit + ".bundle.zip")),
                         "iterations": classifier.n_iter_, "leaf_limit": classifier.max_leaf_nodes,
                         "feature_width": width, **entries}
    result = {"status": "FROZEN_FIT_DIAGNOSTICS_COMPLETE", "models": results,
              "source_identity_sha256": binding, "new_fits": 0, "validation_used_for_model_choice": False,
              "holdout_scored": False, "auto_containment": False, "aws_changed": False,
              "script_sha256": digest(Path(__file__))}
    marker = commit(output, result, phase="frozen-fit-diagnostics")
    print(json.dumps({"status": result["status"], "receipt": marker,
                      "fit_confusions": {k: v["fit"]["confusion"] for k, v in results.items()}}, sort_keys=True))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True); p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(); run(private_directory(a.source), private_directory(a.output))
