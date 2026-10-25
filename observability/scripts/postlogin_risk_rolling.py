"""Schema6/recipe5 amendment justified before fitting by actual Java blind pairs.

Keeps the legacy 57 dimensions and adds eight observable account/history
summaries. It does not add target labels, fixture identity or OTP evidence.
"""
import json
import math
from pathlib import Path
import subprocess

import postlogin_risk_contract as base
from ueba_research_artifacts import digest, private_directory, publish

ROOT = Path(__file__).resolve().parents[2]
VERSION = "postlogin-risk-rolling-account-v2"
SCHEMA = 6
RECIPE = 5
WIDTH = 65
NAMES = ("prior_http_requests_account_15m", "prior_endpoint_categories_account_15m",
         "prior_http_4xx_account_15m", "prior_http_5xx_account_15m",
         "prior_target_associated_failed_logins_account_15m", "prior_sensitive_attempts_account_15m",
         "closed_history_request_median", "closed_history_request_median_available")


def contract():
    return {**base.contract(), "feature_schema_version": SCHEMA, "recipe_version": RECIPE,
            "feature_width": WIDTH, "representation_version": VERSION,
            "legacy_projection_width": 57, "rolling_feature_names": list(NAMES),
            "candidate_projection": list(range(WIDTH)),
            "amendment_reason": "THREE_JAVA_VERIFIED_PRIOR_WINDOW_FAILURE_BLIND_PAIRS_BEFORE_ANY_NEW_FIT"}


def expected_rolling(frame):
    result = base.reference(frame)
    if result["coverage"] != "COVERED":
        raise ValueError("unassociated observation must remain UNDETERMINED")
    values = result["reference_observations"]
    typical = values["historical_request_median"]
    return [float(values[k]) for k in ("requests", "endpoint_categories", "client_errors", "server_errors",
                                       "failed_logins", "sensitive_attempts")] + [
                                           0. if typical is None else float(typical), 0. if typical is None else 1.]


def model_features(row, *, projection="candidate"):
    legacy = base.model_features(row)
    values = row.get("rolling_features")
    if not isinstance(values, list) or len(values) != 8 or any(
            type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("exact finite rolling8 required; no zero padding or proof features")
    if values[7] not in (0, 1):
        raise ValueError("explicit history availability flag required")
    if projection == "baseline":
        return legacy[:37]
    if projection != "candidate":
        raise ValueError("explicit model projection required")
    return legacy + tuple(values)


def java_classpath(source, output):
    # Caller selects/verifies the frozen app package before importing exporter.
    from postlogin_pilot_source import classpath
    original = classpath(source)
    overlay = output / "java-overlay-risk-v2"
    overlay.mkdir(mode=0o700, exist_ok=True)
    private_directory(overlay)
    sources = [ROOT / "backend/src/main/java/com/flarefitness/backend" / suffix for suffix in (
        "ops/PostLoginFeatureExport.java", "service/siem/PostLoginRiskContextFeatures.java")]
    pins = {str(p.relative_to(ROOT)): digest(p) for p in sources}
    identity_path = overlay / "identity.private.json"
    if identity_path.exists():
        identity = json.loads(identity_path.read_text())
        if identity["sources_sha256"] != pins:
            raise ValueError("published rolling Java sources changed; create a new overlay version")
        for name, expected in identity["classes_sha256"].items():
            if digest(overlay / "classes" / name) != expected:
                raise ValueError("rolling Java class changed")
    else:
        classes = overlay / "classes"
        classes.mkdir(mode=0o700, exist_ok=True)
        with (overlay / "compile.private.log").open("wb") as log:
            (overlay / "compile.private.log").chmod(0o600)
            subprocess.run(["javac", "--release", "21", "-cp", original, "-d", str(classes),
                            *map(str, sources)], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
        identity = {"sources_sha256": pins, "parent_overlay_identity_sha256": digest(source / "java-overlay-stream/identity.private.json"),
                    "classes_sha256": {str(p.relative_to(classes)): digest(p) for p in classes.rglob("*.class")},
                    "compiler_release": 21, "feature_schema_version": SCHEMA, "feature_width": WIDTH}
        publish(identity_path, identity)
    return str(overlay / "classes") + ":" + original
