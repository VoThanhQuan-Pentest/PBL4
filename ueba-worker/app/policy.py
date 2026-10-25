"""Immutable integer-encoded policy: one canonical hash for serving, evaluation and activation."""

from dataclasses import dataclass
import hashlib
import json
import re

PERCENTILE_SCALE = 1_000_000
PROBABILITY_SCALE = 1_000_000
COHORTS = ("READY", "COLD")
DETECTION_GRID = (99_950_000, 99_990_000, 99_995_000, 99_999_000,
                  99_999_500, 99_999_800, 99_999_900, 99_999_950)


def strict_document(detection=99_995_000, cold_detection=None, rule_threshold=45, *, feature_schema=2) -> dict:
    if type(feature_schema) is not int or feature_schema not in (2, 3, 4): raise ValueError("unsupported strict feature schema")
    if detection not in DETECTION_GRID or cold_detection is not None and cold_detection not in DETECTION_GRID:
        raise ValueError("unapproved detection policy")
    if rule_threshold not in (45, 60, 70): raise ValueError("unapproved rule policy")
    cold = detection if cold_detection is None else cold_detection
    prefix = {2: "strict-v2b", 3: "strict-v3c", 4: "strict-v4d"}[feature_schema]
    return {"policy_id": f"{prefix}-r{detection}-c{cold}-rules{rule_threshold}", "policy_schema_version": 2,
            "feature_schema_version": feature_schema, "telemetry_contract_version": 3 if feature_schema == 4 else 2,
            "warning_percentile_micro": 99_900_000,
            "detection_percentile_micro": {"READY": detection, "COLD": cold},
            "positive_level": "VERY_UNUSUAL",
            "quality": {"precision_min_ppm": 998_000, "recall_min_ppm": 990_000,
                        "recall_strict": True, "fpr_max_ppm": 1000, "fpr_strict": True,
                        "minimum_normal": 10_000_000, "minimum_positive": 10_000,
                        "minimum_family_positive": 2000, "slice_recall_min_ppm": 990_000,
                        "alpha_numerator": 1, "alpha_denominator": 20, "global_comparisons": 6,
                        "cluster_resamples": 5000, "scopes": ["MODEL_ONLY", "SIEM_FINAL"]},
            "risk": {"very_unusual_creates_l1": True, "warning_creates_l1": False,
                     "auto_containment": False, "rule_risk_threshold": rule_threshold, "rule_min_signals": 2},
            "shadow": {"minimum_elapsed_seconds": 86400, "maximum_heartbeat_gap_seconds": 300,
                       "minimum_closed_windows": 600}}


def legacy_document(schema=1) -> dict:
    if type(schema) is not int or schema not in (1, 2): raise ValueError("unsupported legacy feature schema")
    return {"policy_id": f"legacy-v2a-schema{schema}", "policy_schema_version": 1,
            "feature_schema_version": schema, "telemetry_contract_version": 1,
            "warning_percentile_micro": 99_000_000,
            "detection_percentile_micro": {"READY": 99_900_000, "COLD": 99_900_000},
            "positive_level": "UNUSUAL"}


def canonical(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class ScorePolicy:
    document_json: str

    def __post_init__(self):
        if not isinstance(self.document_json, str) or not 1 <= len(self.document_json.encode()) <= 8192:
            raise ValueError("policy document outside its bound")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError("duplicate policy field")
                result[key] = value
            return result
        document = json.loads(self.document_json, object_pairs_hook=unique)
        if canonical(document) != self.document_json: raise ValueError("policy must use its canonical encoding")
        if not isinstance(document, dict) or not re.fullmatch(r"[a-z0-9_-]{8,96}", str(document.get("policy_id", ""))):
            raise ValueError("invalid policy identity")
        schema = document.get("policy_schema_version")
        if type(schema) is not int or schema not in (1, 2): raise ValueError("unknown policy schema")
        warning = document.get("warning_percentile_micro")
        detection = document.get("detection_percentile_micro")
        if type(warning) is not int or not isinstance(detection, dict) or set(detection) != set(COHORTS):
            raise ValueError("invalid policy threshold contract")
        if any(type(value) is not int or not 0 <= warning < value <= 100 * PERCENTILE_SCALE for value in detection.values()):
            raise ValueError("policy levels must be finite, ordered integer thresholds")
        if schema == 1:
            expected = legacy_document(document.get("feature_schema_version"))
        else:
            expected = strict_document(detection["READY"], detection["COLD"], document.get("risk", {}).get("rule_risk_threshold"),
                                       feature_schema=document.get("feature_schema_version"))
        if canonical(document) != canonical(expected): raise ValueError("policy differs from its approved immutable contract")

    @classmethod
    def legacy(cls, schema=1): return cls(canonical(legacy_document(schema)))

    @classmethod
    def strict(cls, detection=99_995_000, cold_detection=None, rule_threshold=45, *, schema=2):
        return cls(canonical(strict_document(detection, cold_detection, rule_threshold, feature_schema=schema)))

    @property
    def document(self): return json.loads(self.document_json)

    @property
    def sha256(self): return hashlib.sha256(self.document_json.encode()).hexdigest()

    @property
    def strict_gate(self): return self.document["policy_schema_version"] == 2

    def wire(self):
        return {"policy_id": self.document["policy_id"], "policy_sha256": self.sha256,
                "policy_document_json": self.document_json}

    @classmethod
    def from_wire(cls, wire):
        if not isinstance(wire, dict) or set(wire) != {"policy_id", "policy_sha256", "policy_document_json"}:
            raise ValueError("invalid policy envelope")
        policy = cls(wire["policy_document_json"])
        if wire["policy_sha256"] != policy.sha256 or wire["policy_id"] != policy.document["policy_id"]:
            raise ValueError("policy checksum or identity mismatch")
        return policy

    def level(self, percentile: float, cohort="READY") -> str:
        if cohort not in COHORTS or type(percentile) not in (int, float) or not 0 <= percentile <= 100:
            raise ValueError("invalid score/cohort")
        document = self.document
        if percentile >= document["detection_percentile_micro"][cohort] / PERCENTILE_SCALE: return "VERY_UNUSUAL"
        if percentile >= document["warning_percentile_micro"] / PERCENTILE_SCALE: return "UNUSUAL"
        return "NORMAL_RANGE"

    def detected(self, percentile: float, cohort="READY") -> bool:
        level = self.level(percentile, cohort)
        return level == "VERY_UNUSUAL" if self.strict_gate else level != "NORMAL_RANGE"
