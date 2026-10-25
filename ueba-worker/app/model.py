"""Versioned Isolation Forest for numeric, server-authored account features."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from threading import RLock
from typing import TYPE_CHECKING

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from app.contract import (FEATURE_COUNT, FEATURE_NAMES, FEATURE_SCHEMAS, SCHEMA_VERSION,
                          HYBRID_MODEL_KIND, IF_MODEL_KIND, SUPPORT_MODEL_KIND, SupportTrainingConfig, TrainingConfig,
                          feature_array, model_recipe_binding, parse_training_config, recipe_binding, validate_version)
from app.evaluation import evaluate_percentiles
from app.policy import COHORTS, ScorePolicy

if TYPE_CHECKING:
    from app.hybrid_incident import HybridResearchConfig


class ModelStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = RLock()
        self.active_version: str | None = None
        self.active_payload: dict | None = None
        self.active_schema: int = 1
        self.active_policy: ScorePolicy | None = None
        active = self.directory / "active.json"
        if active.exists():
            try:
                selection = json.loads(active.read_text(encoding="utf-8"))
                self.activate(selection["model_version"], persist=False, expected_selection=selection)
            except (OSError, ValueError, KeyError, TypeError):
                self.active_version = None
                self.active_payload = None

    def train(self, version: str, samples: list[list[float]], calibration: list[list[float]], *,
              schema_version: int = 1, config: TrainingConfig | SupportTrainingConfig | HybridResearchConfig | None = None,
              policy: ScorePolicy | None = None, labeled_samples=None, labeled_targets=None) -> dict:
        """Internal training; normal READY and label/split provenance are caller-verified.

        The trusted caller extracts X only after verifying separate chronological
        labeled training. Labels, cohort and identity are never feature columns;
        no public numeric training request supplies these labeled arguments.
        """
        validate_version(version)
        recipe = config or TrainingConfig()
        score_policy = policy or ScorePolicy.legacy(schema_version)
        identity = recipe_binding(recipe)
        if identity["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND) and (schema_version != 4 or not score_policy.strict_gate):
            raise ValueError("support/hybrid models require strict schema-4 policy")
        if score_policy.document["feature_schema_version"] != schema_version:
            raise ValueError("policy feature schema mismatch")
        if identity["model_kind"] == HYBRID_MODEL_KIND:
            from app.storage_budget import require_headroom
            require_headroom(self.directory, 129 * 1024 ** 2)
            from app.hybrid_incident import MAX_LABELED_ROWS, training_labels
            from app.normal_support import _features
            if labeled_samples is None or labeled_targets is None:
                raise ValueError("hybrid requires separate caller-verified labeled training")
            training = _features(samples, 50_000)
            calibration_array = _features(calibration, 10_000)
            supervised = _features(labeled_samples, MAX_LABELED_ROWS)
            targets = training_labels(labeled_targets, len(supervised)).copy()
        else:
            if labeled_samples is not None or labeled_targets is not None:
                raise ValueError("labeled training is only accepted by the internal hybrid recipe")
            training = feature_array(samples, 50_000, schema_version)
            calibration_array = feature_array(calibration, 10_000, schema_version)
        if len(training) < 500 or len(calibration_array) < 100:
            raise ValueError("training requires 500 normal windows and 100 separate calibration windows")
        if isinstance(recipe, TrainingConfig) and len(training) < recipe.max_samples:
            raise ValueError("training windows cannot be fewer than the selected max_samples")
        if isinstance(recipe, SupportTrainingConfig) and len(training) < recipe.reference_count:
            raise ValueError("training windows cannot be fewer than the selected support references")
        model_path = self.directory / f"{version}.joblib"
        metadata_path = self.directory / f"{version}.json"
        if model_path.exists() or metadata_path.exists() or (self.directory / f".pending-{version}").exists():
            raise ValueError("model version already exists")
        if identity["model_kind"] == IF_MODEL_KIND:
            model = IsolationForest(**recipe.parameters())
        elif identity["model_kind"] == SUPPORT_MODEL_KIND:
            from app.normal_support import NormalSupportScorer
            model = NormalSupportScorer(**recipe.parameters())
        else:
            from app.hybrid_incident import HybridIncidentScorer
            model = HybridIncidentScorer(recipe)
        if identity["model_kind"] == HYBRID_MODEL_KIND:
            model.fit(training, supervised, targets)
        else:
            model.fit(training)
        calibration_scores = np.sort(-model.score_samples(calibration_array))
        payload = {"model": model, "calibration_scores": calibration_scores}
        metadata = {
            "model_version": version,
            "feature_schema_version": schema_version,
            "feature_names": FEATURE_SCHEMAS[schema_version],
            "model_config": dict(vars(recipe)) if identity["model_kind"] == HYBRID_MODEL_KIND else recipe.parameters(),
            "score_policy": score_policy.wire(),
            "calibration_sha256": self.calibration_hash(payload),
            "training_windows": len(training),
            "calibration_windows": len(calibration_array),
            "threshold_99": float(np.quantile(calibration_scores, 0.99)),
            "threshold_999": float(np.quantile(calibration_scores, 0.999)),
        }
        if schema_version == 4: metadata["data_provenance"] = "DEMO_ONLY"
        if score_policy.strict_gate: metadata["calibration_scope"] = "INITIAL_FIT_ONLY"
        if identity["model_kind"] in (SUPPORT_MODEL_KIND, HYBRID_MODEL_KIND):
            metadata.update(identity, scoring_implementation=self.scoring_identity(model))
        if identity["model_kind"] == HYBRID_MODEL_KIND:
            metadata.update(labeled_training_windows=len(supervised),
                labeled_class_windows={str(value): int(np.count_nonzero(targets == value)) for value in (0, 1, 2)},
                labeled_training_scope="CALLER_VERIFIED_SEPARATE_CHRONOLOGICAL_TRAINING_ONLY",
                normal_training_scope="NORMAL_READY_FIT_ONLY_CALLER_ENFORCED",
                confirmed_attack_target_available=False)
        return self.publish_candidate(version, payload, metadata)

    @staticmethod
    def scoring_identity(model) -> dict | None:
        """Bind new scorer code as well as saved bytes; legacy IF caches stay unchanged."""
        if type(model) is IsolationForest: return None
        from app.hybrid_incident import HybridIncidentScorer
        if type(model) is HybridIncidentScorer:
            import scipy
            import sklearn
            from app.model_state_dispatch import verifier_sha256
            directory = Path(__file__).resolve().parent
            return {**recipe_binding(model.config), "sources": {
                        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                        for name in ("hybrid_incident.py", "hybrid_semantic.py", "model.py", "normal_support.py",
                                     "contract.py", "model_state_dispatch.py")},
                    "dependencies": {"numpy": np.__version__, "scipy": scipy.__version__, "scikit-learn": sklearn.__version__},
                    "numeric_verifier_sha256": verifier_sha256(HYBRID_MODEL_KIND)}
        from app.normal_support import NormalSupportScorer
        if type(model) is not NormalSupportScorer: raise ValueError("unknown raw-score model type")
        parameters = model.parameters()
        config = SupportTrainingConfig(**{key: parameters[key] for key in SupportTrainingConfig.__dataclass_fields__})
        directory = Path(__file__).resolve().parent
        return {**recipe_binding(config), "sources": {
                    name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                    for name in ("normal_support.py", "contract.py")},
                "dependencies": {"numpy": np.__version__}}

    def publish_candidate(self, version: str, payload: dict, metadata: dict) -> dict:
        """Private worker-created artifact publication; never accepts uploaded pickle files."""
        validate_version(version)
        identity = model_recipe_binding(metadata)
        if identity["model_kind"] == HYBRID_MODEL_KIND:
            from app.hybrid_incident import HybridIncidentScorer
            from app.hybrid_semantic import from_state, to_state
            from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
            config = parse_training_config(HYBRID_MODEL_KIND, metadata.get("model_config"))
            model = payload.get("model")
            policy = ScorePolicy.from_wire(metadata.get("score_policy"))
            classes = metadata.get("labeled_class_windows")
            if (type(model) is not HybridIncidentScorer or config != model.config
                    or recipe_binding(config) != identity or metadata.get("feature_schema_version") != 4
                    or not policy.strict_gate or policy.document["feature_schema_version"] != 4
                    or metadata.get("data_provenance") != "DEMO_ONLY"
                    or metadata.get("training_windows") != model.normal_fit_count
                    or metadata.get("labeled_training_windows") != model.labeled_fit_count
                    or type(classes) is not dict or set(classes) != {"0", "1", "2"}
                    or any(type(value) is not int or value < 20 for value in classes.values())
                    or sum(classes.values()) != model.labeled_fit_count
                    or metadata.get("scoring_implementation") != self.scoring_identity(model)
                    or metadata.get("calibration_sha256") != self.calibration_hash(payload)):
                raise ValueError("hybrid publication recipe/state/implementation mismatch")
            numeric = {"model_state_format": state_format(HYBRID_MODEL_KIND),
                       "model_state_sha256": state_sha256(payload),
                       "model_state_verifier_sha256": verifier_sha256(HYBRID_MODEL_KIND)}
            if any(key in metadata and metadata[key] != value for key, value in numeric.items()):
                raise ValueError("hybrid publication numeric identity mismatch")
            metadata = {**metadata, **numeric}
            state = to_state(model)
            from_state(state)  # Validate persisted primitives, never fit().
            payload = {**payload, "model": state}
        elif identity["model_kind"] == SUPPORT_MODEL_KIND:
            from app.normal_support import NormalSupportScorer
            if type(payload.get("model")) is not NormalSupportScorer:
                raise ValueError("known fitted support model required")
            # Persist bounded plain numeric state, not executable support objects
            # or derived caches. Restoration validates/rebuilds it without fit().
            state = payload["model"].to_state()
            NormalSupportScorer.from_state(state)
            payload = {**payload, "model": state}
        model_path, metadata_path = self.directory / f"{version}.joblib", self.directory / f"{version}.json"
        with self.lock:
            if model_path.exists() or metadata_path.exists(): raise ValueError("model version already exists")
            if identity["model_kind"] == HYBRID_MODEL_KIND:
                from app.storage_budget import require_headroom
                require_headroom(self.directory, 129 * 1024 ** 2)
            pending = self.directory / f".pending-{version}"
            pending.mkdir(mode=0o700)  # Failed/interrupted publications are retained, not overwritten.
            candidate_path, metadata_temp = pending / "model.joblib", pending / "metadata.json"
            if identity["model_kind"] == HYBRID_MODEL_KIND:
                # Only newly published, own-worker-created numeric HYBRID state
                # is compressed. Existing files and legacy codecs are untouched.
                joblib.dump(payload, candidate_path, compress=("lzma", 3))
                candidate_path.chmod(0o600)
                if candidate_path.stat().st_size > 128 * 1024 ** 2:
                    raise ValueError("compressed hybrid artifact exceeds fixed publication byte bound")
                restored = joblib.load(candidate_path)
                if (state_sha256(restored) != metadata["model_state_sha256"]
                        or self.calibration_hash(restored) != metadata["calibration_sha256"]):
                    raise ValueError("compressed hybrid numeric/calibration readback mismatch")
                metadata = {**metadata, "artifact_compression": {"codec": "lzma", "level": 3}}
            else:
                joblib.dump(payload, candidate_path)
            candidate_path.chmod(0o600)
            result = {**metadata, "model_version": version, "sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest()}
            metadata_temp.write_text(json.dumps(result, sort_keys=True, allow_nan=False), encoding="utf-8")
            metadata_temp.chmod(0o600)
            os.replace(candidate_path, model_path)
            os.replace(metadata_temp, metadata_path)
            pending.rmdir()  # Only our now-empty, validated transaction directory is removed.
        return result

    def recalibrated_candidate(self, source: str, version: str, buckets: dict, policy: ScorePolicy, *,
                               expected_source_sha256: str, dataset_sha256: str, split_sha256: dict,
                               calibration_scope: str) -> dict:
        """Reuse an existing fitted forest. This operation never calls fit()."""
        metadata, payload = self.load_candidate(source)
        if (not policy.strict_gate or metadata["feature_schema_version"] not in (2, 3, 4)
                or policy.document["feature_schema_version"] != metadata["feature_schema_version"]
                or metadata["sha256"] != expected_source_sha256
                or not isinstance(dataset_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", dataset_sha256)
                or not isinstance(split_sha256, dict) or set(split_sha256) != set(COHORTS)
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in split_sha256.values())
                or calibration_scope not in ("STRICT", "PILOT_ONLY") or not isinstance(buckets, dict) or set(buckets) != set(COHORTS)):
            raise ValueError("recalibration artifact/dataset/cohort binding mismatch")
        minimum = 1_000_000 if calibration_scope == "STRICT" else 100
        arrays = {}
        for name, values in buckets.items():
            array = np.asarray(values, dtype=np.float64)
            if (array.ndim != 1 or not minimum <= len(array) <= 2_000_000 or not np.isfinite(array).all()
                    or np.any(array[1:] < array[:-1])): raise ValueError("bounded sorted cohort calibration required")
            arrays[name] = array
        updated_payload = {"model": payload["model"], "calibration_scores": arrays["READY"], "calibration_by_cohort": arrays}
        updated_metadata = {key: value for key, value in metadata.items()
                            if key not in ("sha256", "model_version", "score_policy", "calibration_sha256", "threshold_99", "threshold_999")}
        if model_recipe_binding(metadata)["model_kind"] == HYBRID_MODEL_KIND:
            # New calibration changes outer identity, never the fitted model.
            for key in ("model_state_sha256", "model_state_format", "model_state_verifier_sha256"):
                updated_metadata.pop(key, None)
        updated_metadata.update(score_policy=policy.wire(), calibration_scope=calibration_scope,
                                dataset_manifest_sha256=dataset_sha256, source_model_version=source,
                                source_model_sha256=expected_source_sha256, calibration_split_sha256=split_sha256,
                                calibration_windows=sum(len(values) for values in arrays.values()),
                                calibration_cohort_windows={name: len(values) for name, values in arrays.items()},
                                calibration_sha256=self.calibration_hash(updated_payload), additional_fit_calls=0,
                                threshold_99=float(np.quantile(arrays["READY"], 0.99)),
                                threshold_999=float(np.quantile(arrays["READY"], 0.999)))
        return self.publish_candidate(version, updated_payload, updated_metadata)

    def activate(self, version: str, persist: bool = True, *, expected_selection: dict | None = None) -> dict:
        metadata, payload = self.load_candidate(version)
        policy = ScorePolicy.from_wire(metadata["score_policy"]) if "score_policy" in metadata else ScorePolicy.legacy(metadata["feature_schema_version"])
        binding = {"model_version": version, "model_sha256": metadata["sha256"],
                   "feature_schema_version": metadata["feature_schema_version"],
                   "calibration_sha256": self.calibration_hash(payload), "policy_sha256": policy.sha256}
        if policy.strict_gate:
            dataset = metadata.get("dataset_manifest_sha256")
            if not isinstance(dataset, str) or not re.fullmatch(r"[a-f0-9]{64}", dataset):
                raise ValueError("strict candidate requires immutable dataset binding")
            binding["dataset_sha256"] = dataset
        if expected_selection is not None:
            if policy.strict_gate or len(expected_selection) > 1:
                if any(expected_selection.get(key) != value for key, value in binding.items()):
                    raise ValueError("active selection artifact/calibration/policy binding mismatch")
            elif expected_selection != {"model_version": version}:
                raise ValueError("invalid legacy active selection")
        elif not persist and policy.strict_gate:
            raise ValueError("strict restore requires a verified active selection")
        if policy.strict_gate:
            buckets = payload.get("calibration_by_cohort", {})
            if (metadata.get("calibration_scope") != "STRICT" or set(buckets) != set(COHORTS)
                    or any(len(values) < 1_000_000 for values in buckets.values())
                    or metadata.get("calibration_cohort_windows") != {name: len(values) for name, values in buckets.items()}):
                raise ValueError("strict activation requires complete independent cohort calibration, not pilot/initial fitting")
        # Legacy active models remain restorable. New contextual models cannot be
        # promoted simply because fitting succeeded; the frozen evaluation is required.
        if metadata["feature_schema_version"] in (2, 3, 4):
            evaluation_path = self.directory / f"{version}.evaluation.json"
            if not evaluation_path.is_file():
                raise ValueError("candidate has not passed quality evaluation")
            evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
            if (evaluation.get("quality_gate") != "PASS" or evaluation.get("evaluation_scope") != "FROZEN_HOLDOUT"
                    or evaluation.get("model_sha256") != metadata["sha256"]):
                raise ValueError("candidate has not passed quality evaluation")
            if policy.strict_gate:
                if (evaluation.get("policy_sha256") != policy.sha256 or evaluation.get("calibration_sha256") != binding["calibration_sha256"]
                        or evaluation.get("dataset_sha256") != binding["dataset_sha256"]):
                    raise ValueError("strict evaluation policy/calibration binding mismatch")
                scopes = evaluation.get("scopes", {})
                if set(scopes) != {"MODEL_ONLY", "SIEM_FINAL"} or any(
                        result.get("quality_gate") != "PASS" or result.get("policy_sha256") != policy.sha256
                        for result in scopes.values()):
                    raise ValueError("both independent and final SIEM quality gates are required")
                from app.quality_proof import verify_quality
                verify_quality(self.directory, version, policy, binding)
                self.validate_shadow(version, binding)
            elif evaluation.get("scope") != "MODEL_ONLY":
                raise ValueError("legacy evaluation scope mismatch")
        with self.lock:
            if persist:
                temp = self.directory / ".active.json.tmp"
                temp.write_text(json.dumps(binding, sort_keys=True), encoding="utf-8")
                temp.chmod(0o600)
                os.replace(temp, self.directory / "active.json")
            self.active_version = version
            self.active_schema = metadata["feature_schema_version"]
            self.active_policy = policy
            self.active_payload = payload
        return metadata

    @staticmethod
    def calibration_hash(payload: dict) -> str:
        digest = hashlib.sha256()
        buckets = payload.get("calibration_by_cohort")
        if buckets is None: return hashlib.sha256(np.asarray(payload["calibration_scores"], dtype="<f8").tobytes()).hexdigest()
        for name in sorted(buckets):
            digest.update(name.encode()); digest.update(b"\0")
            digest.update(np.asarray(buckets[name], dtype="<f8").tobytes())
        return digest.hexdigest()

    def validate_shadow(self, version: str, binding: dict) -> None:
        from datetime import datetime, timedelta
        path = self.directory / f"{version}.shadow.json"
        if not path.is_file(): raise ValueError("candidate has not completed the required shadow run")
        state = json.loads(path.read_text())
        if (any(state.get(key) != value for key, value in binding.items()) or state.get("status") != "COMPLETED"
                or state.get("clock_provenance") != "REAL_SERVER_CLOCK"):
            raise ValueError("shadow artifact/policy binding mismatch")
        from contextlib import closing
        from app.quality_proof import readonly
        run_id = state.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id): raise ValueError("shadow run identity missing")
        with closing(readonly(self.directory / "shadow/runs.sqlite")) as db:
            stored = db.execute("SELECT state_json FROM runs WHERE id=?", (run_id,)).fetchone()
            if stored is None or json.loads(stored[0]) != state or db.execute("SELECT count(*) FROM scores WHERE run_id=?", (run_id,)).fetchone()[0] != state.get("closed_windows"):
                raise ValueError("shadow proof differs from actual separate run/scores journal")
        try:
            start = datetime.fromisoformat(state["started_at_utc"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(state["ended_at_utc"].replace("Z", "+00:00"))
            wall = (end - start).total_seconds()
        except (ValueError, KeyError, TypeError): raise ValueError("invalid shadow timestamps") from None
        elapsed = state.get("elapsed_monotonic_seconds")
        gap = state.get("maximum_heartbeat_gap_seconds")
        windows = state.get("closed_windows")
        if (start.utcoffset() != timedelta(0) or end.utcoffset() != timedelta(0) or wall < 86400
                or type(elapsed) not in (int, float) or not np.isfinite(elapsed) or elapsed < 86400
                or type(gap) not in (int, float) or not np.isfinite(gap) or not 0 <= gap <= 300
                or type(windows) is not int or windows < 600
                or state.get("candidate_side_effects") != {"incidents": 0, "history": 0, "ip_lookups": 0,
                                                           "ip_blocks": 0, "session_revocations": 0, "policy_publications": 0}):
            raise ValueError("shadow timing, coverage or side-effect gate failed")

    def load_candidate(self, version: str) -> tuple[dict, dict]:
        validate_version(version)
        model_path = self.directory / f"{version}.joblib"
        metadata_path = self.directory / f"{version}.json"
        if not model_path.is_file() or not metadata_path.is_file():
            raise ValueError("unknown model version")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        identity = model_recipe_binding(metadata)
        compression = metadata.get("artifact_compression")
        if compression is not None and (
                identity["model_kind"] != HYBRID_MODEL_KIND or type(compression) is not dict
                or set(compression) != {"codec", "level"} or compression["codec"] != "lzma"
                or type(compression["level"]) is not int or compression["level"] != 3):
            raise ValueError("unsupported own-worker artifact compression descriptor")
        schema = metadata.get("feature_schema_version")
        if schema not in FEATURE_SCHEMAS:
            raise ValueError("incompatible feature schema")
        if tuple(metadata.get("feature_names", [])) != FEATURE_SCHEMAS[schema]:
            raise ValueError("incompatible feature names or order")
        if "score_policy" in metadata:
            policy = ScorePolicy.from_wire(metadata["score_policy"])
            if policy.document["feature_schema_version"] != schema: raise ValueError("policy feature schema mismatch")
        if schema == 4 and ("score_policy" not in metadata or not policy.strict_gate
                            or metadata.get("data_provenance") != "DEMO_ONLY"):
            raise ValueError("schema-4 models require strict policy and DEMO_ONLY provenance")
        if hashlib.sha256(model_path.read_bytes()).hexdigest() != metadata.get("sha256"):
            raise ValueError("model checksum mismatch")
        # Only load an artifact this worker created; the API never accepts model uploads.
        payload = joblib.load(model_path)
        if not isinstance(payload, dict): raise ValueError("invalid model artifact")
        if identity["model_kind"] == IF_MODEL_KIND:
            valid_model = type(payload.get("model")) is IsolationForest
        elif identity["model_kind"] == SUPPORT_MODEL_KIND:
            from app.normal_support import NormalSupportScorer
            valid_model = schema == 4 and type(payload.get("model")) is dict
            if valid_model:
                restored = NormalSupportScorer.from_state(payload["model"])
                config = parse_training_config(SUPPORT_MODEL_KIND, metadata.get("model_config"))
                parameters = restored.parameters()
                if (recipe_binding(config) != identity
                        or any(parameters.get(key) != value for key, value in config.parameters().items())
                        or metadata.get("training_windows") != restored.to_state()["fit_count"]
                        or metadata.get("scoring_implementation") != self.scoring_identity(restored)):
                    raise ValueError("support model recipe/state/implementation mismatch")
                payload["model"] = restored
        else:
            from app.hybrid_semantic import from_state
            valid_model = schema == 4 and type(payload.get("model")) is dict
            if valid_model:
                restored = from_state(payload["model"])
                config = parse_training_config(HYBRID_MODEL_KIND, metadata.get("model_config"))
                classes = metadata.get("labeled_class_windows")
                if (recipe_binding(config) != identity or config != restored.config
                        or metadata.get("training_windows") != restored.normal_fit_count
                        or metadata.get("labeled_training_windows") != restored.labeled_fit_count
                        or metadata.get("scoring_implementation") != self.scoring_identity(restored)
                        or type(classes) is not dict or set(classes) != {"0", "1", "2"}
                        or any(type(value) is not int or value < 20 for value in classes.values())
                        or sum(classes.values()) != restored.labeled_fit_count):
                    raise ValueError("hybrid model recipe/state/implementation mismatch")
                payload["model"] = restored
        if (not valid_model or (identity["model_kind"] != HYBRID_MODEL_KIND
                and payload["model"].n_features_in_ != len(FEATURE_SCHEMAS[schema]))):
            raise ValueError("invalid model artifact")
        if identity["model_kind"] == IF_MODEL_KIND and identity["recipe_sha256"] is not None:
            config = parse_training_config(IF_MODEL_KIND, metadata.get("model_config"))
            if recipe_binding(config) != identity or any(payload["model"].get_params().get(key) != value
                                                       for key, value in config.parameters().items()):
                raise ValueError("isolation forest recipe/state mismatch")
        calibration = np.asarray(payload.get("calibration_scores"), dtype=np.float64)
        if (calibration.ndim != 1 or len(calibration) < 100 or not np.isfinite(calibration).all()
                or np.any(calibration[1:] < calibration[:-1])):
            raise ValueError("invalid calibration artifact")
        if "calibration_sha256" in metadata and metadata["calibration_sha256"] != self.calibration_hash(payload):
            raise ValueError("calibration checksum mismatch")
        if "calibration_by_cohort" in payload:
            buckets = payload["calibration_by_cohort"]
            if not isinstance(buckets, dict) or set(buckets) != set(COHORTS):
                raise ValueError("calibration cohort contract mismatch")
            for values in buckets.values():
                array = np.asarray(values, dtype=np.float64)
                if (array.ndim != 1 or len(array) < 100 or not np.isfinite(array).all()
                        or np.any(array[1:] < array[:-1])): raise ValueError("invalid cohort calibration artifact")
        if identity["model_kind"] == HYBRID_MODEL_KIND:
            from app.model_state_dispatch import state_format, state_sha256, verifier_sha256
            if (metadata.get("model_state_format") != state_format(HYBRID_MODEL_KIND)
                    or metadata.get("model_state_verifier_sha256") != verifier_sha256(HYBRID_MODEL_KIND)
                    or metadata.get("model_state_sha256") != state_sha256(payload)):
                raise ValueError("hybrid calibrated numeric identity mismatch")
        return metadata, payload

    def score(self, rows: list[list[float]], schema_version: int = 1, cohorts: list[str] | None = None) -> dict:
        features = feature_array(rows, 256, schema_version)
        with self.lock:
            if self.active_payload is None:
                return {"available": False, "reason": "MODEL_NOT_READY", "results": []}
            payload = self.active_payload
            version = self.active_version
            schema = self.active_schema
            policy = self.active_policy
        if schema_version != schema:
            return {"available": False, "reason": "MODEL_SCHEMA_MISMATCH", "results": []}
        return self.score_payload(payload, features, version, schema, policy=policy, cohorts=cohorts)

    def score_candidate(self, version: str, rows: list[list[float]], schema_version: int = 1, cohorts: list[str] | None = None) -> dict:
        metadata, payload = self.load_candidate(version)
        if metadata["feature_schema_version"] != schema_version:
            raise ValueError("candidate feature schema mismatch")
        features = feature_array(rows, 256, schema_version)
        policy = ScorePolicy.from_wire(metadata["score_policy"]) if "score_policy" in metadata else ScorePolicy.legacy(schema_version)
        return self.score_payload(payload, features, version, schema_version, policy=policy, cohorts=cohorts)

    def evaluate_candidate(self, version: str, rows: list[list[float]], labels: list[int],
                           families: list[str], groups: list[str], *, schema_version: int = 2) -> dict:
        metadata, payload = self.load_candidate(version)
        if metadata["feature_schema_version"] != schema_version:
            raise ValueError("candidate feature schema mismatch")
        policy = ScorePolicy.from_wire(metadata["score_policy"]) if "score_policy" in metadata else ScorePolicy.legacy(schema_version)
        if policy.strict_gate:
            raise ValueError("strict evaluation requires the checksum-bound streaming catalogue path, not legacy in-memory evaluation")
        features = feature_array(rows, 20_000, schema_version)
        # Validate before consuming the single evaluation attempt, including the cluster contract.
        evaluate_percentiles(np.zeros(len(features)), labels, families, groups, bootstrap_samples=1)
        destination = self.directory / f"{version}.evaluation.json"
        with self.lock:
            if destination.exists():
                raise ValueError("candidate holdout evaluation is already frozen")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump({"status": "RUNNING", "quality_gate": "NOT_RUN", "model_sha256": metadata["sha256"]}, stream)
        try:
            scored = self.score_payload(payload, features, version, schema_version)
            result = evaluate_percentiles([row["normal_percentile"] for row in scored["results"]], labels, families, groups)
            dataset = {"feature_schema_version": schema_version, "vectors": features.tolist(),
                       "labels": labels, "families": families, "groups": groups}
            result.update(status="SUCCEEDED", model_version=version, model_sha256=metadata["sha256"],
                          feature_schema_version=schema_version,
                          evaluation_dataset_sha256=hashlib.sha256(json.dumps(dataset, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode()).hexdigest())
        except Exception as exception:
            result = {"status": "FAILED", "quality_gate": "FAIL", "model_sha256": metadata["sha256"],
                      "error_type": type(exception).__name__}
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, sort_keys=True, allow_nan=False), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        return result

    @staticmethod
    def score_payload(payload: dict, features: np.ndarray, version: str, schema: int, *,
                      policy: ScorePolicy | None = None, cohorts: list[str] | None = None) -> dict:
        policy = policy or ScorePolicy.legacy(schema)
        contexts = cohorts or ["READY"] * len(features)
        if len(contexts) != len(features) or any(cohort not in COHORTS for cohort in contexts):
            raise ValueError("score cohorts must match the window batch")
        if schema == 4 and any(cohort == "COLD" and np.any(row[[8, 9, 10, 11, 12, 20, 21]] != 0)
                               for row, cohort in zip(features, contexts)):
            raise ValueError("cold-start must not fabricate personalized features")
        scores = -payload["model"].score_samples(features)
        calibration = payload["calibration_scores"]
        results = []
        for score, cohort in zip(scores, contexts):
            buckets = payload.get("calibration_by_cohort")
            if policy.strict_gate and cohort == "COLD" and buckets is None:
                raise ValueError("strict cold-start scoring requires its separate calibration")
            if buckets is not None:
                if cohort not in buckets: raise ValueError("calibration cohort missing")
                calibration = buckets[cohort]
            # Mid-rank ties: identical normal scores should be at the middle of
            # their calibration mass, not falsely reported at percentile 100.
            left = np.searchsorted(calibration, score, side="left")
            right = np.searchsorted(calibration, score, side="right")
            percentile = float((left + right) / (2 * len(calibration)) * 100)
            results.append({"raw_anomaly_score": float(score),
                            "normal_percentile": percentile,
                            "level": policy.level(percentile, cohort), "scoring_cohort": cohort,
                            "model_scope": "PERSONAL" if cohort == "READY" and schema == 2 else "GLOBAL_PROXY"})
        return {"available": True, "model_version": version,
                "feature_schema_version": schema, "score_policy": policy.wire(),
                "calibration_sha256": ModelStore.calibration_hash(payload), "results": results}
