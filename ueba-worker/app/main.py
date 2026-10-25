"""Internal-only training and scoring API for customer behavior windows."""

from __future__ import annotations

import json
import asyncio
from contextlib import asynccontextmanager, suppress
import hashlib
import os
import secrets
import stat
import uuid
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.model import FEATURE_NAMES, ModelStore, SCHEMA_VERSION, feature_array
from app.contract import FEATURE_SCHEMAS, TrainingConfig
from app.evaluation import evaluate_percentiles
from app.policy import ScorePolicy
from app.operator_catalog import OperatorCatalog, train_recipe
from app.shadow import ShadowStore
from app.catalog_evaluation import evaluate_recipe

@asynccontextmanager
async def shadow_lifespan(_app):
    if os.environ.get("UEBA_POSTLOGIN_SERVING_ONLY") == "true":
        yield
        return
    def tick():
        current = ShadowStore(store())
        try: current.heartbeat_all()
        finally: current.close()
    async def loop():
        while True:
            await asyncio.sleep(60)
            await asyncio.to_thread(tick)
    task = asyncio.create_task(loop())
    try: yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError): await task


app = FastAPI(title="Flare UEBA Worker", docs_url=None, redoc_url=None, openapi_url=None, lifespan=shadow_lifespan)
_job_lock = Lock()
_training_lock = Lock()
_evaluation_lock = Lock()
_shadow_start_lock = Lock()
_activation_lock = Lock()
_known_jobs: set[str] = set()
ADOPTION_REFERENCE_FIELDS = {"recipe_id", "dataset_id", "data_provenance", "feature_schema_version",
    "training_windows", "calibration_windows", "from_utc", "to_utc", "completed_search_fits",
    "manifest_sha256", "policy_sha256", "blocked_holdout_split_sha256", "selected_model_sha256",
    "selected_calibration_sha256", "model_state_sha256", "model_state_verifier_sha256", "model_state_format",
    "model_kind", "recipe_version", "recipe_sha256", "strict_proof_sha256", "selection_sha256",
    "source_label_manifest_sha256_by_fold", "zero_fit_recalibrations", "fold", "random_state"}


@lru_cache(maxsize=1)
def store() -> ModelStore:
    return ModelStore(Path(os.environ.get("UEBA_MODEL_DIR", "/var/lib/ueba")))


def require_token(x_ueba_token: str | None = Header(default=None)) -> None:
    token_file = Path(os.environ.get("UEBA_SERVICE_TOKEN_FILE", "/run/secrets/ueba.token"))
    try:
        expected = token_file.read_text(encoding="utf-8").strip()
    except OSError:
        raise HTTPException(status_code=503, detail="worker credential unavailable") from None
    if len(expected) < 32 or not x_ueba_token or not secrets.compare_digest(expected, x_ueba_token):
        raise HTTPException(status_code=403, detail="forbidden")


class TrainRequest(BaseModel):
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")
    feature_schema_version: Literal[1, 2, 3]
    feature_names: list[str]
    samples: list[list[float]]
    calibration: list[list[float]]
    config: dict | None = None
    score_policy: dict | None = None


class CatalogTrainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")
    recipe_id: str = Field(pattern=r"^[a-z0-9_-]{8,96}$")


class CatalogEvaluationRequest(CatalogTrainRequest):
    pass


class ActivationJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class QualifiedAdoptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")
    adoption_receipt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class ScoreRequest(BaseModel):
    feature_schema_version: Literal[1, 2, 3, 4]
    feature_names: list[str]
    vectors: list[list[float]]
    cohorts: list[Literal["READY", "COLD"]] | None = None

    @model_validator(mode="before")
    @classmethod
    def schema4_numeric_features(cls, value):
        # Preserve old request parsing, but never coerce new metadata booleans or
        # numeric-looking strings into server-authored schema-4 observations.
        if isinstance(value, dict) and value.get("feature_schema_version") == 4 and isinstance(value.get("vectors"), list):
            for row in value["vectors"]:
                if isinstance(row, list) and any(type(number) not in (int, float) for number in row):
                    raise ValueError("numeric schema-4 feature vector required")
        return value


class ActivateRequest(BaseModel):
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")


class CandidateScoreRequest(ScoreRequest):
    model_version: str = Field(pattern=r"^[a-z0-9_-]{8,64}$")


class PostloginScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    snapshots: list[dict] = Field(min_length=1, max_length=32)


class EvaluationRequest(CandidateScoreRequest):
    labels: list[Literal[0, 1]]
    families: list[str]
    groups: list[str]


class ShadowStartRequest(ActivateRequest):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class ShadowWindowsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    windows: list[dict] = Field(min_length=1, max_length=256)


def shadow_call(run):
    current = ShadowStore(store())
    try: return run(current)
    except (ValueError, TypeError, KeyError, OSError):
        raise HTTPException(status_code=400, detail="shadow request unavailable, ineligible or failed integrity validation") from None
    finally: current.close()


@app.post("/internal/v1/shadow-runs", dependencies=[Depends(require_token)], status_code=202)
def start_shadow(request: ShadowStartRequest, background_tasks: BackgroundTasks):
    # Backend commits this server-generated ID before submission. Repeating an
    # ambiguous HTTP request therefore cannot restart the 24-hour clock.
    if request.request_id is None:
        return shadow_call(lambda current: current.start(request.model_version))
    job_id = request.request_id
    with _job_lock:
        path = job_file(job_id)
        if path.is_file():
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("kind") != "SHADOW_START" or value.get("model_version") != request.model_version:
                raise HTTPException(status_code=409, detail="shadow request identity conflict")
            status = value["status"]
            if status in {"QUEUED", "RUNNING"} and job_id not in _known_jobs:
                status = "INTERRUPTED"
            return {"job_id": job_id, "status": status, "model_version": request.model_version}
    if not _shadow_start_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="a shadow eligibility job is already running")
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"kind": "SHADOW_START", "status": "QUEUED", "model_version": request.model_version})
        background_tasks.add_task(run_shadow_start, job_id, request.model_version)
    except Exception:
        _shadow_start_lock.release()
        raise
    return {"job_id": job_id, "status": "QUEUED", "model_version": request.model_version}


def run_shadow_start(job_id, version):
    current = None
    try:
        current = ShadowStore(store())
        write_job(job_id, {"kind": "SHADOW_START", "status": "RUNNING", "model_version": version})
        state = current.start(version, run_id=job_id)
        write_job(job_id, {"kind": "SHADOW_START", "status": "SUCCEEDED", "model_version": version, "metadata": state})
    except Exception as failure:
        write_job(job_id, {"kind": "SHADOW_START", "status": "FAILED", "model_version": version,
                           "error_type": type(failure).__name__})
    finally:
        if current is not None: current.close()
        _shadow_start_lock.release()


@app.post("/internal/v1/shadow-runs/{run_id}/heartbeat", dependencies=[Depends(require_token)])
def shadow_heartbeat(run_id: str):
    return shadow_call(lambda current: current.heartbeat(run_id))


@app.get("/internal/v1/shadow-runs/{run_id}", dependencies=[Depends(require_token)])
def shadow_status(run_id: str):
    return shadow_call(lambda current: current.state(run_id))


@app.post("/internal/v1/shadow-runs/{run_id}/windows", dependencies=[Depends(require_token)])
def shadow_windows(run_id: str, request: ShadowWindowsRequest):
    return shadow_call(lambda current: current.score(run_id, request.windows))


class BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Enforce a streaming body limit without consuming the endpoint's input."""

    def __init__(self, wrapped_app):
        self.wrapped_app = wrapped_app

    async def __call__(self, scope, receive, send):
        if (scope["type"] == "http" and os.environ.get("UEBA_POSTLOGIN_SERVING_ONLY") == "true"
                and scope.get("path") not in {"/health", "/internal/v1/postlogin/score", "/internal/v1/postlogin/shadow-score"}):
            await JSONResponse(status_code=404, content={"detail": "serving-only worker"})(scope, receive, send)
            return
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.wrapped_app(scope, receive, send)
            return
        maximum = 512 * 1024 if scope.get("path") in {"/internal/v1/postlogin/score","/internal/v1/postlogin/shadow-score"} else 12 * 1024 * 1024
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = 0
        if content_length > maximum:
            await JSONResponse(status_code=413, content={"detail": "request too large"})(scope, receive, send)
            return
        consumed = 0
        exceeded = False
        response_started = False

        async def limited_receive():
            nonlocal consumed, exceeded
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > maximum:
                    exceeded = True
                    raise BodyTooLarge
            return message

        async def guarded_send(message):
            nonlocal response_started
            # FastAPI may convert a receive exception into a 400 response.
            # Suppress that response and emit the size-limit result instead.
            if exceeded:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.wrapped_app(scope, limited_receive, guarded_send)
        except BodyTooLarge:
            pass
        if exceeded and not response_started:
            await JSONResponse(status_code=413, content={"detail": "request too large"})(scope, receive, send)


app.add_middleware(BodyLimitMiddleware)


@app.get("/health")
def health():
    from app.postlogin_serving import health as postlogin_health
    if os.environ.get("UEBA_POSTLOGIN_SERVING_ONLY") == "true":
        return {"service": "ueba-worker", "feature_schema_version": SCHEMA_VERSION,
                "feature_names": FEATURE_SCHEMAS[SCHEMA_VERSION], "supported_feature_schemas": [1, 2, 3, 4],
                "model_available": False, "model_version": None, "postlogin": postlogin_health(), "serving_only": True}
    current = store()
    schema = current.active_schema if current.active_payload is not None else SCHEMA_VERSION
    return {"service": "ueba-worker", "feature_schema_version": schema,
            "feature_names": FEATURE_SCHEMAS[schema], "supported_feature_schemas": [1, 2, 3, 4],
            "model_available": current.active_payload is not None,
            "model_version": current.active_version, "postlogin": postlogin_health()}


@app.post("/internal/v1/postlogin/score", dependencies=[Depends(require_token)])
def score_postlogin(request: PostloginScoreRequest):
    from app.postlogin_serving import configured_model
    try:
        model = configured_model()
    except (OSError, ValueError, RuntimeError):
        raise HTTPException(status_code=503, detail="project postlogin model unavailable") from None
    try:
        return model.score(request.snapshots)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid pre-action snapshot") from None
    except (OSError, RuntimeError):
        raise HTTPException(status_code=503, detail="project postlogin model identity unavailable") from None


@app.post("/internal/v1/postlogin/shadow-score", dependencies=[Depends(require_token)])
def score_auth_shadow(request: PostloginScoreRequest):
    from app.auth_shadow_serving import configured_shadow
    try:
        return configured_shadow().score(request.snapshots)
    except ValueError:
        raise HTTPException(status_code=400,detail="invalid or changed shadow contract") from None
    except (OSError,RuntimeError):
        raise HTTPException(status_code=503,detail="shadow disabled or unavailable; baseline unchanged") from None


def job_file(job_id: str) -> Path:
    directory = store().directory / "jobs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{job_id}.json"


def write_job(job_id: str, payload: dict) -> None:
    path = job_file(job_id)
    temporary = path.with_suffix(".tmp")
    with _job_lock:
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, path)


def private_model_json(path: Path, maximum: int):
    """Read bounded operator-installed proof without following links."""
    if path.is_symlink():
        raise ValueError("private model proof symlink refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise ValueError("bounded private model proof required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(raw) != before.st_size or signature(before) != signature(after)
                or signature(before) != signature(named)):
            raise ValueError("model proof changed during read")
    from app.quality_proof import parse_json
    return parse_json(raw)


def private_model_sha(path: Path, maximum: int):
    """Hash one protected artifact without following links or reading stdout data."""
    if path.is_symlink():
        raise ValueError("private model artifact symlink refused")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise ValueError("bounded owner-controlled model artifact required")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(before) != signature(after) or signature(before) != signature(named):
            raise ValueError("model artifact changed while hashing")
    return digest.hexdigest()


def run_catalog_training(job_id, request, recipe):
    try:
        write_job(job_id, {"status": "RUNNING", "model_version": request.model_version, "recipe_id": request.recipe_id})
        def advanced(value):
            write_job(job_id, {"status": "RUNNING", "model_version": request.model_version, "recipe_id": request.recipe_id,
                               "phase": "CALIBRATION", "progress": value})
        metadata = train_recipe(store(), recipe, request.model_version, store().directory / "score-cache", progress=advanced)
        write_job(job_id, {"status": "SUCCEEDED", "model_version": request.model_version, "recipe_id": request.recipe_id,
                           "metadata": metadata, "quality_gate": "NOT_RUN"})
    except Exception as exception:
        write_job(job_id, {"status": "FAILED", "model_version": request.model_version, "error_type": type(exception).__name__})
    finally: _training_lock.release()


@app.post("/internal/v1/train-catalog", dependencies=[Depends(require_token)], status_code=202)
def catalog_training(request: CatalogTrainRequest, background_tasks: BackgroundTasks):
    try:
        recipe = OperatorCatalog(Path(os.environ.get("UEBA_EXPERIMENT_CATALOG_DIR", "/run/ueba-catalog"))).recipe(request.recipe_id)
    except (ValueError, TypeError, OSError, KeyError):
        raise HTTPException(status_code=400, detail="operator recipe unavailable or failed integrity validation") from None
    current = store()
    if (current.directory / f"{request.model_version}.joblib").exists() or (current.directory / f"{request.model_version}.json").exists():
        raise HTTPException(status_code=409, detail="model version already exists")
    if not _training_lock.acquire(blocking=False): raise HTTPException(status_code=409, detail="a training job is already running")
    job_id = uuid.uuid4().hex
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"status": "QUEUED", "model_version": request.model_version, "recipe_id": request.recipe_id})
        background_tasks.add_task(run_catalog_training, job_id, request, recipe)
    except Exception:
        _training_lock.release(); raise
    return {"job_id": job_id, "status": "QUEUED", "model_version": request.model_version}


def run_training(job_id: str, request: TrainRequest) -> None:
    try:
        write_job(job_id, {"status": "RUNNING", "model_version": request.model_version})
        result = store().train(request.model_version, request.samples, request.calibration,
                               schema_version=request.feature_schema_version,
                               config=TrainingConfig(**(request.config or {})),
                               policy=ScorePolicy.from_wire(request.score_policy) if request.score_policy else None)
        write_job(job_id, {"status": "SUCCEEDED", "model_version": request.model_version,
                           "metadata": result})
    except Exception as exception:
        write_job(job_id, {"status": "FAILED", "model_version": request.model_version,
                           "error_type": exception.__class__.__name__})
    finally:
        _training_lock.release()


def run_evaluation(job_id: str, request: EvaluationRequest) -> None:
    try:
        write_job(job_id, {"status": "RUNNING", "model_version": request.model_version})
        result = store().evaluate_candidate(request.model_version, request.vectors, request.labels,
                                           request.families, request.groups,
                                           schema_version=request.feature_schema_version)
        write_job(job_id, {"status": result["status"], "model_version": request.model_version,
                           "metadata": result})
    except Exception as exception:
        write_job(job_id, {"status": "FAILED", "model_version": request.model_version,
                           "error_type": type(exception).__name__})
    finally:
        _evaluation_lock.release()


def run_catalog_evaluation(job_id, request, recipe, workspace):
    try:
        write_job(job_id, {"kind": "CATALOG_EVALUATION", "status": "RUNNING", "model_version": request.model_version,
                           "recipe_id": request.recipe_id})
        def advanced(value):
            write_job(job_id, {"kind": "CATALOG_EVALUATION", "status": "RUNNING", "model_version": request.model_version,
                               "recipe_id": request.recipe_id, "progress": value})
        result = evaluate_recipe(store(), recipe, request.model_version, workspace, progress=advanced)
        write_job(job_id, {"kind": "CATALOG_EVALUATION", "status": "SUCCEEDED", "model_version": request.model_version,
                           "recipe_id": request.recipe_id, "metadata": result})
    except Exception as failure:
        write_job(job_id, {"kind": "CATALOG_EVALUATION", "status": "FAILED", "model_version": request.model_version,
                           "error_type": type(failure).__name__})
    finally: _evaluation_lock.release()


@app.post("/internal/v1/evaluations/catalog", dependencies=[Depends(require_token)], status_code=202)
def evaluate_catalog(request: CatalogEvaluationRequest, background_tasks: BackgroundTasks):
    try:
        recipe = OperatorCatalog(Path(os.environ.get("UEBA_EXPERIMENT_CATALOG_DIR", "/run/ueba-catalog"))).recipe(request.recipe_id)
        if recipe.mode != "STRICT": raise ValueError("preview evaluation cannot qualify")
        metadata, _ = store().load_candidate(request.model_version)
        if metadata.get("recipe_id") != request.recipe_id or metadata.get("dataset_manifest_sha256") != recipe.dataset.sha256:
            raise ValueError("candidate belongs to a different registered recipe")
        workspace = Path(os.environ.get("UEBA_RISK_WORKSPACE", "/run/ueba-risk")).resolve(strict=True)
    except (ValueError, TypeError, OSError, KeyError):
        raise HTTPException(status_code=400, detail="registered strict candidate or decision workspace is unavailable") from None
    if not _evaluation_lock.acquire(blocking=False): raise HTTPException(status_code=409, detail="an evaluation job is already running")
    job_id = uuid.uuid4().hex
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"kind": "CATALOG_EVALUATION", "status": "QUEUED", "model_version": request.model_version,
                           "recipe_id": request.recipe_id})
        background_tasks.add_task(run_catalog_evaluation, job_id, request, recipe, workspace)
    except Exception:
        _evaluation_lock.release(); raise
    return {"job_id": job_id, "status": "QUEUED", "model_version": request.model_version}


@app.post("/internal/v1/train", dependencies=[Depends(require_token)], status_code=202)
def train(request: TrainRequest, background_tasks: BackgroundTasks):
    if tuple(request.feature_names) != FEATURE_SCHEMAS[request.feature_schema_version]:
        raise HTTPException(status_code=400, detail="feature names or order do not match schema")
    if len(request.samples) < 500 or len(request.calibration) < 100:
        raise HTTPException(status_code=400, detail="insufficient normal windows")
    if len(request.samples) > 50_000 or len(request.calibration) > 10_000:
        raise HTTPException(status_code=400, detail="too many windows")
    try:
        feature_array(request.samples, 50_000, request.feature_schema_version)
        feature_array(request.calibration, 10_000, request.feature_schema_version)
        recipe = TrainingConfig(**(request.config or {}))
        if request.score_policy is not None:
            policy = ScorePolicy.from_wire(request.score_policy)
            if policy.document["feature_schema_version"] != request.feature_schema_version:
                raise ValueError("policy feature schema mismatch")
        if len(request.samples) < recipe.max_samples:
            raise ValueError("training windows cannot be fewer than the selected max_samples")
    except (ValueError, TypeError) as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception
    current = store()
    if (current.directory / f"{request.model_version}.joblib").exists():
        raise HTTPException(status_code=409, detail="model version already exists")
    if not _training_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="a training job is already running")
    job_id = uuid.uuid4().hex
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"status": "QUEUED", "model_version": request.model_version})
        background_tasks.add_task(run_training, job_id, request)
    except Exception:
        _training_lock.release()
        raise
    return {"job_id": job_id, "status": "QUEUED"}


@app.get("/internal/v1/jobs/{job_id}", dependencies=[Depends(require_token)])
def job_status(job_id: str):
    if len(job_id) != 32 or not all(char in "0123456789abcdef" for char in job_id):
        raise HTTPException(status_code=400, detail="invalid job ID")
    path = job_file(job_id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="unknown job")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value["status"] in {"QUEUED", "RUNNING"} and job_id not in _known_jobs:
        return {**value, "status": "INTERRUPTED"}
    return value


@app.post("/internal/v1/models/activate", dependencies=[Depends(require_token)])
def activate(request: ActivateRequest):
    try:
        return store().activate(request.model_version)
    except ValueError as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception


def run_activation(job_id, version):
    try:
        write_job(job_id, {"kind": "ACTIVATION", "status": "RUNNING", "model_version": version})
        metadata = store().activate(version)  # Full journal + real shadow verification precedes publication.
        write_job(job_id, {"kind": "ACTIVATION", "status": "SUCCEEDED", "model_version": version, "metadata": metadata})
    except Exception as failure:
        write_job(job_id, {"kind": "ACTIVATION", "status": "FAILED", "model_version": version, "error_type": type(failure).__name__})
    finally: _activation_lock.release()


@app.post("/internal/v1/models/activation-jobs", dependencies=[Depends(require_token)], status_code=202)
def activate_job(request: ActivationJobRequest, background_tasks: BackgroundTasks):
    job_id = request.request_id
    with _job_lock:
        path = job_file(job_id)
        if path.is_file():
            value = json.loads(path.read_text())
            if value.get("kind") != "ACTIVATION" or value.get("model_version") != request.model_version:
                raise HTTPException(status_code=409, detail="activation request identity conflict")
            status = value["status"]
            if status in {"QUEUED", "RUNNING"} and job_id not in _known_jobs: status = "INTERRUPTED"
            return {"job_id": job_id, "status": status, "model_version": request.model_version}
    if not _activation_lock.acquire(blocking=False): raise HTTPException(status_code=409, detail="an activation job is already running")
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"kind": "ACTIVATION", "status": "QUEUED", "model_version": request.model_version})
        background_tasks.add_task(run_activation, job_id, request.model_version)
    except Exception:
        _activation_lock.release(); raise
    return {"job_id": job_id, "status": "QUEUED", "model_version": request.model_version}


@app.get("/internal/v1/models/primary", dependencies=[Depends(require_token)])
def primary_metadata():
    current = store()
    if current.active_version is None: return {"available": False}
    try:
        metadata, _ = current.load_candidate(current.active_version)
        policy = ScorePolicy.from_wire(metadata["score_policy"]) if "score_policy" in metadata else ScorePolicy.legacy(current.active_schema)
        if (metadata["feature_schema_version"] != current.active_schema
                or metadata["calibration_sha256"] != ModelStore.calibration_hash(current.active_payload)
                or policy.wire() != current.active_policy.wire()):
            raise ValueError("active artifact binding changed")
        return {"available": True, "metadata": metadata}
    except (ValueError, TypeError, KeyError, OSError):
        raise HTTPException(status_code=503, detail="primary metadata failed integrity validation") from None


def _qualified_candidate(version: str):
    """Recheck installed model bytes, fresh proof, and persisted score journal."""
    current = store()
    metadata, _payload = current.load_candidate(version)
    if metadata.get("feature_schema_version") != 4 or metadata.get("calibration_scope") != "STRICT":
        raise ValueError("schema-4 strictly calibrated candidate required")
    policy = ScorePolicy.from_wire(metadata["score_policy"])
    if not policy.strict_gate:
        raise ValueError("strict candidate policy required")
    from app.frozen_evaluation import model_binding
    from app.quality_proof import verify_quality
    binding = model_binding(metadata, policy)
    verify_quality(current.directory, version, policy, binding)
    evidence_path = current.directory / f"{version}.evaluation.json"
    identity_path = current.directory / f"{version}.evaluation-identity.json"
    evaluation = private_model_json(evidence_path, 4 * 1024 * 1024)
    identity = private_model_json(identity_path, 4 * 1024 * 1024)
    receipt_path = current.directory / "operator-adoptions" / f"{version}.private.json"
    receipt = private_model_json(receipt_path, 1024 * 1024)
    receipt_sha = private_model_sha(receipt_path, 1024 * 1024)
    artifacts = receipt.get("artifact_sha256")
    actual_artifacts = {
        "joblib": private_model_sha(current.directory / f"{version}.joblib", 128 * 1024 ** 2),
        "metadata": private_model_sha(current.directory / f"{version}.json", 4 * 1024 * 1024),
        "evaluation": private_model_sha(evidence_path, 4 * 1024 * 1024),
        "evaluation_identity": private_model_sha(identity_path, 4 * 1024 * 1024),
        "metrics": private_model_sha(current.directory / f"{version}.metrics.sqlite", 8 * 1024 ** 3),
    }
    selection = receipt.get("selection_proof")
    strict_reference = receipt.get("strict_reference")
    if (not isinstance(evaluation, dict) or not isinstance(identity, dict) or not isinstance(receipt, dict)
            or receipt.get("format") != "UEBA_QUALIFIED_ADOPTION_V1"
            or receipt.get("status") != "CANDIDATE_INSTALLED"
            or receipt.get("model_version") != version
            or receipt.get("data_provenance") != "DEMO_ONLY"
            or receipt.get("artifact_sha256") != actual_artifacts
            or receipt.get("model_sha256") != metadata.get("sha256")
            or receipt.get("model_state_sha256") != metadata.get("model_state_sha256")
            or receipt.get("calibration_sha256") != metadata.get("calibration_sha256")
            or receipt.get("policy_sha256") != policy.sha256
            or receipt.get("original_training_manifest_sha256") != metadata.get("dataset_manifest_sha256")
            or receipt.get("fresh_holdout_manifest_sha256") != identity.get("fresh_holdout_manifest_sha256")
            or receipt.get("holdout_split_sha256") != identity.get("holdout_split_sha256")
            or receipt.get("selection_receipt_sha256") != identity.get("frozen_selection_receipt_sha256")
            or not isinstance(strict_reference, dict)
            or set(strict_reference) != ADOPTION_REFERENCE_FIELDS
            or strict_reference.get("recipe_id") != receipt.get("recipe_id")
            or strict_reference.get("dataset_id") != receipt.get("original_dataset_id")
            or strict_reference.get("data_provenance") != "DEMO_ONLY"
            or strict_reference.get("feature_schema_version") != 4
            or strict_reference.get("model_kind") != metadata.get("model_kind")
            or strict_reference.get("recipe_version") != metadata.get("recipe_version")
            or strict_reference.get("recipe_sha256") != metadata.get("recipe_sha256")
            or strict_reference.get("model_state_sha256") != metadata.get("model_state_sha256")
            or strict_reference.get("model_state_verifier_sha256") != metadata.get("model_state_verifier_sha256")
            or strict_reference.get("model_state_format") != metadata.get("model_state_format")
            or strict_reference.get("manifest_sha256") != receipt.get("original_training_manifest_sha256")
            or strict_reference.get("blocked_holdout_split_sha256") == receipt.get("holdout_split_sha256")
            or strict_reference.get("fold") != 3 or strict_reference.get("random_state") != 42
            or strict_reference.get("selected_model_sha256") != metadata.get("sha256")
            or strict_reference.get("selected_calibration_sha256") != metadata.get("calibration_sha256")
            or strict_reference.get("policy_sha256") != metadata.get("score_policy", {}).get("policy_sha256")
            or strict_reference.get("strict_proof_sha256") != identity.get("hybrid_strict_proof", {}).get("proof_sha256")
            or strict_reference.get("selection_sha256") != identity.get("hybrid_strict_proof", {}).get("selection_sha256")
            or strict_reference.get("source_label_manifest_sha256_by_fold") != {
                fold: value.get("manifest_sha256") for fold, value in
                identity.get("hybrid_strict_proof", {}).get("source_label_manifests", {}).items()}
            or evaluation.get("status") != "SUCCEEDED" or evaluation.get("quality_gate") != "PASS"
            or evaluation.get("evaluation_scope") != "FROZEN_HOLDOUT"
            or evaluation.get("data_provenance") != "DEMO_ONLY"
            or evaluation.get("evaluation_identity") != identity
            or evaluation.get("model_version") != version
            or evaluation.get("model_sha256") != metadata.get("sha256")
            or evaluation.get("scored_journal_sha256") != actual_artifacts["metrics"]
            or strict_reference.get("zero_fit_recalibrations") != selection.get("zero_fit_recalibrations")
            or not isinstance(selection, dict)
            or selection.get("actual_composite_trials") != 360
            or selection.get("actual_component_fit_calls") != 720
            or selection.get("validation_runs") != 360
            or strict_reference.get("zero_fit_recalibrations") != selection.get("zero_fit_recalibrations")
            or not 45 <= selection.get("zero_fit_recalibrations", 0) <= 360
            or selection.get("holdout_scored") is not False):
        raise ValueError("installed candidate, fresh evidence, or frozen selection receipt mismatch")
    return {"status": "QUALIFIED", "model_version": version,
            "adoption_receipt_sha256": receipt_sha, "adoption_receipt": receipt,
            "metadata": metadata, "evaluation": evaluation, "evaluation_identity": identity}


@app.get("/internal/v1/models/{version}/qualification", dependencies=[Depends(require_token)])
def qualified_candidate(version: str):
    try:
        return _qualified_candidate(version)
    except HTTPException:
        raise
    except Exception as failure:
        raise HTTPException(status_code=409, detail="candidate qualification refused: " + type(failure).__name__) from None


@app.post("/internal/v1/models/qualified-adoptions", dependencies=[Depends(require_token)], status_code=202)
def register_qualified_adoption(request: QualifiedAdoptionRequest):
    expected_request = hashlib.sha256(
        ("UEBA_QUALIFIED_ADOPTION_V1:" + request.adoption_receipt_sha256).encode()
    ).hexdigest()[:32]
    if request.request_id != expected_request:
        raise HTTPException(status_code=409, detail="adoption request identity mismatch")
    with _job_lock:
        path = job_file(request.request_id)
        if path.is_file():
            value = private_model_json(path, 2 * 1024 * 1024)
            if (value.get("kind") != "QUALIFIED_ADOPTION"
                    or value.get("model_version") != request.model_version
                    or value.get("adoption_receipt_sha256") != request.adoption_receipt_sha256):
                raise HTTPException(status_code=409, detail="adoption request identity conflict")
            return {"job_id": request.request_id, "status": value["status"], "model_version": request.model_version}
    try:
        qualified = _qualified_candidate(request.model_version)
        if qualified["adoption_receipt_sha256"] != request.adoption_receipt_sha256:
            raise ValueError("adoption receipt checksum changed")
        primary = store().active_version
        receipt = qualified["adoption_receipt"]
        primary_before = receipt.get("primary_before")
        if not isinstance(primary_before, dict) or primary_before.get("model_version") != primary:
            raise ValueError("primary model changed after candidate installation")
        if primary is not None:
            current_metadata, _ = store().load_candidate(primary)
            if primary_before.get("model_sha256") != current_metadata.get("sha256"):
                raise ValueError("primary artifact changed after candidate installation")
        payload = {"kind": "QUALIFIED_ADOPTION", "status": "SUCCEEDED",
                   "model_version": request.model_version, "adoption_receipt_sha256": request.adoption_receipt_sha256,
                   "metadata": qualified["metadata"]}
        write_job(request.request_id, payload)
        return {"job_id": request.request_id, "status": "SUCCEEDED", "model_version": request.model_version}
    except Exception as failure:
        raise HTTPException(status_code=409, detail="candidate adoption refused: " + type(failure).__name__) from None


@app.post("/internal/v1/score", dependencies=[Depends(require_token)])
def score(request: ScoreRequest):
    if tuple(request.feature_names) != FEATURE_SCHEMAS[request.feature_schema_version]:
        raise HTTPException(status_code=400, detail="feature names or order do not match schema")
    try:
        return {**store().score(request.vectors, request.feature_schema_version, request.cohorts), "feature_names": request.feature_names}
    except ValueError as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception


@app.post("/internal/v1/score-candidate", dependencies=[Depends(require_token)])
def score_candidate(request: CandidateScoreRequest):
    if tuple(request.feature_names) != FEATURE_SCHEMAS[request.feature_schema_version]:
        raise HTTPException(status_code=400, detail="feature names or order do not match schema")
    try:
        return {**candidate_cache().score(store(), request.model_version, request.vectors, request.feature_schema_version, request.cohorts),
                "feature_names": request.feature_names}
    except ValueError as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception


@lru_cache(maxsize=1)
def candidate_cache():
    from app.candidate_cache import HTTP_CANDIDATE_CACHE
    return HTTP_CANDIDATE_CACHE


@app.post("/internal/v1/evaluations", dependencies=[Depends(require_token)], status_code=202)
def evaluate(request: EvaluationRequest, background_tasks: BackgroundTasks):
    if tuple(request.feature_names) != FEATURE_SCHEMAS[request.feature_schema_version]:
        raise HTTPException(status_code=400, detail="feature names or order do not match schema")
    try:
        feature_array(request.vectors, 20_000, request.feature_schema_version)
        validated = evaluate_percentiles([0] * len(request.vectors), request.labels, request.families,
                                         request.groups, bootstrap_samples=1)
        if not validated["minimum_sizes_met"]:
            raise ValueError("holdout requires 10000 normal windows and 1000 abnormalities across five families")
        metadata, _ = store().load_candidate(request.model_version)
        if "score_policy" in metadata and ScorePolicy.from_wire(metadata["score_policy"]).strict_gate:
            raise ValueError("strict evaluation requires the streaming catalogue endpoint")
        if metadata["feature_schema_version"] != request.feature_schema_version:
            raise ValueError("candidate feature schema mismatch")
    except (ValueError, TypeError) as exception:
        raise HTTPException(status_code=400, detail=str(exception)) from exception
    if (store().directory / f"{request.model_version}.evaluation.json").exists():
        raise HTTPException(status_code=409, detail="candidate holdout evaluation is already frozen")
    if not _evaluation_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="an evaluation job is already running")
    job_id = uuid.uuid4().hex
    try:
        _known_jobs.add(job_id)
        write_job(job_id, {"status": "QUEUED", "model_version": request.model_version})
        background_tasks.add_task(run_evaluation, job_id, request)
    except Exception:
        _evaluation_lock.release()
        raise
    return {"job_id": job_id, "status": "QUEUED"}
