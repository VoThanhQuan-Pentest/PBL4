from pathlib import Path
from types import SimpleNamespace

import pytest

from app.parallel_worker import _checked_cache, _fit_with_worker_cache, _run_lock, worker_cache_directory


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def test_worker_cache_slots_are_separate_and_phase_scoped(tmp_path):
    root = private_dir(tmp_path / "strict")
    fit_0 = worker_cache_directory(root, "fit", 0)
    fit_1 = worker_cache_directory(root, "fit", 1)
    validation_0 = worker_cache_directory(root, "validation", 0)

    assert fit_0 != fit_1
    assert fit_0 != validation_0
    assert fit_0.is_relative_to(root)
    assert fit_1.is_relative_to(root)


def test_worker_cache_rejects_escape_and_creates_private_tree(tmp_path):
    root = private_dir(tmp_path / "strict")
    cache = worker_cache_directory(root, "fit", 0)
    checked = _checked_cache(root, cache)
    assert checked == cache
    assert checked.stat().st_mode & 0o777 == 0o700
    with pytest.raises(ValueError, match="inside its campaign dataset"):
        _checked_cache(root, tmp_path / "outside")


def test_parallel_run_lock_prevents_duplicate_same_run(tmp_path):
    root = private_dir(tmp_path / "strict")
    first = _run_lock(root, "fit", "hybrid-v1-test-run-0001")
    try:
        with pytest.raises(ValueError, match="already being handled"):
            _run_lock(root, "fit", "hybrid-v1-test-run-0001")
    finally:
        first.close()

    second = _run_lock(root, "fit", "hybrid-v1-test-run-0001")
    second.close()


def test_fit_routes_only_calibration_cache_without_changing_fit_source(tmp_path):
    observed = []

    def recalibrate(*args, **kwargs):
        observed.append((args[6], kwargs.get("progress")))
        return {"status": "calibrated"}

    def fit_one(*args, **kwargs):
        assert "cache_directory" not in kwargs
        return operator.recalibrate("store", "dataset", 1, "source", "target", "policy",
                                    Path("default-cache"), progress="progress")

    operator = SimpleNamespace(recalibrate=recalibrate, fit_one=fit_one)
    cache = tmp_path / "private-worker-cache"
    original = operator.recalibrate
    result = _fit_with_worker_cache(operator, tmp_path, "hybrid-v1-test-run-0001",
                                    "normal_plus_incident_research", "d" * 64,
                                    "a" * 64, cache)

    assert result == {"status": "calibrated"}
    assert observed == [(cache, "progress")]
    assert operator.recalibrate is original
