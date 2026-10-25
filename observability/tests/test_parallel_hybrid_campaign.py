import importlib.util
import os
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "parallel_hybrid_campaign.py"
SPEC = importlib.util.spec_from_file_location("parallel_hybrid_campaign_test_target", SCRIPT)
parallel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parallel)


def _private_tree(root):
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def test_parallel_source_clone_hardlinks_only_declared_static_inputs(tmp_path):
    source = _private_tree(tmp_path / "old-source")
    for name in parallel.SOURCE_MARKERS:
        (source / name).write_text("pinned marker\n")
        (source / name).chmod(0o600)
    standard = _private_tree(source / "standard")
    for name in parallel.SOURCE_STATIC_FILES:
        (standard / name).write_text(f"static {name}\n")
        (standard / name).chmod(0o600)
    for name in parallel.SOURCE_STATIC_DIRS:
        directory = _private_tree(standard / name)
        (directory / "input.json").write_text("immutable input\n")
        (directory / "input.json").chmod(0o600)
    # Prior model/validation outputs must never be cloned into a fresh campaign.
    old_runs = _private_tree(standard / "hybrid-runs")
    (old_runs / "old.json").write_text("old receipt\n")
    (old_runs / "old.json").chmod(0o600)
    for fold in (1, 2, 3):
        labels = _private_tree(source / f"labels-fold{fold}")
        (labels / "manifest.private.json").write_text("label source\n")
        (labels / "manifest.private.json").chmod(0o600)

    clone = tmp_path / "new-source"
    parallel.copy_static_source(source, clone)

    source_file = standard / "shards" / "input.json"
    clone_file = clone / "standard" / "shards" / "input.json"
    assert os.stat(source_file).st_ino == os.stat(clone_file).st_ino
    assert (clone / "labels-fold2" / "manifest.private.json").is_file()
    assert not (clone / "standard" / "hybrid-runs").exists()
    assert not (clone / "standard" / "hybrid-models").exists()
    assert (clone / "standard" / "generation.lock").stat().st_size == 0


def test_parallel_container_names_are_bounded_and_unique():
    left = parallel._container_name("abcdef0123456789", "fit", 0, "hybrid-v1-run-fold1")
    right = parallel._container_name("abcdef0123456789", "fit", 1, "hybrid-v1-run-fold1")
    other = parallel._container_name("abcdef0123456789", "validation", 0, "hybrid-v1-run-fold1")
    assert left != right
    assert left != other
    assert len(left) <= 63
    assert left.startswith("flare-ph-abcdef01-fit-w0-")
