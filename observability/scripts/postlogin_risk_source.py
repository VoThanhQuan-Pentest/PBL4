#!/usr/bin/env python3
"""Measured, private, resumable raw-to-real-Java source generation, never a fit."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import time

import postlogin_risk_data as sampling
import postlogin_risk_rolling as rolling
from postlogin_risk_probe import frozen_generator
from ueba_research_artifacts import canonical, commit, digest, private_directory


def source_protocol(source, output):
    code = [Path(__file__), Path(sampling.__file__), Path(rolling.__file__),
            Path(__file__).with_name("postlogin_risk_contract.py"), Path(__file__).with_name("postlogin_pilot_source.py")]
    value = {"contract": rolling.contract(), "sampling": sampling.protocol(),
             "source_identity_sha256": digest(source / "pilot.source.identity.private.json"),
             "java_overlay_identity_sha256": digest(output / "java-overlay-risk-v2/identity.private.json"),
             "code_sha256": {p.name: digest(p) for p in code}, "source_class": "PILOT_ONLY_RULE_DISTILLATION",
             "before_outcome": True, "maximum_output_bytes": 2 * 1024**3, "disk_reserve_bytes": 5000000000}
    value["required_runtime"] = {"cpu_maximum": 2, "memory_maximum_bytes": 2 * 1024**3, "network": "none"}
    current = output / "risk-source-protocol-v4.commit.private.json"
    if current.exists():
        marker = json.loads(current.read_text())
        path = output / marker["receipt"]
        if marker["receipt"] != "risk-source-protocol-v4.receipt.private.json" or digest(path) != marker["receipt_sha256"]:
            raise ValueError("source protocol commit changed")
        existing = json.loads(path.read_text())
        if {k: v for k, v in existing.items() if k != "continuation"} != value:
            raise ValueError("frozen source v4 implementation changed")
        return marker["receipt_sha256"]
    parent_marker = json.loads((output / "risk-source-protocol-v3.commit.private.json").read_text())
    parent_path = output / parent_marker["receipt"]
    if digest(parent_path) != parent_marker["receipt_sha256"]:
        raise ValueError("parent source protocol changed")
    parent = json.loads(parent_path.read_text())
    if (parent["contract"] != value["contract"] or parent["source_identity_sha256"] != value["source_identity_sha256"]
            or parent["sampling"] != {k: v for k, v in value["sampling"].items() if k != "ready_account_sampling"}):
        raise ValueError("source continuation cannot change task, labels, strata, features or generator identity")
    inherited = {}
    for marker_path in sorted(output.glob("risk-source-f*-*.commit.private.json")):
        marker = json.loads(marker_path.read_text())
        unit = marker_path.name.removesuffix(".commit.private.json")
        if marker["receipt"] != unit + ".receipt.private.json":
            raise ValueError("inherited source receipt path changed")
        path = output / marker["receipt"]
        if digest(path) != marker["receipt_sha256"]:
            raise ValueError("inherited source batch changed")
        retained = json.loads(path.read_text())
        if retained["binding"]["protocol_sha256"] != parent_marker["receipt_sha256"]:
            raise ValueError("unrecognized source ancestry")
        inherited[unit] = {"receipt_sha256": marker["receipt_sha256"],
                           "protocol_sha256": parent_marker["receipt_sha256"]}
    value["continuation"] = {"reason": "FIX_READY_RESERVED_SLOT_EXHAUSTION_BEFORE_ANY_FIT",
                              "parent_protocol_sha256": parent_marker["receipt_sha256"], "inherited_batches": inherited}
    proof = commit(output, value, phase="risk-source-protocol-v4")
    return proof["receipt_sha256"]


def resource_limits():
    cgroup = Path('/sys/fs/cgroup')
    memory = (cgroup / 'memory.max').read_text().strip()
    cpu = (cgroup / 'cpu.max').read_text().split()
    interfaces = sorted(p.name for p in Path('/sys/class/net').iterdir())
    verified = (memory.isdigit() and int(memory) <= 2 * 1024**3 and cpu[0].isdigit()
                and int(cpu[0]) / int(cpu[1]) <= 2 and interfaces == ['lo'])
    return {"verified": verified, "memory_max": memory, "cpu_max": cpu, "interfaces": interfaces}


def guard(output, started, maximum_seconds):
    hold = output / "operator-hold.private.json"
    if hold.exists() and json.loads(hold.read_text()).get("hold_new_units"):
        raise RuntimeError("STOP_OPERATOR_HOLD")
    if time.monotonic() - started >= maximum_seconds - 10:
        raise RuntimeError("STOP_BUDGET_AT_SOURCE_BATCH_BOUNDARY")
    if shutil.disk_usage(output).free < 5000000000:
        raise RuntimeError("STOP_DISK_RESERVE")
    if sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) >= 2 * 1024**3:
        raise RuntimeError("STOP_OUTPUT_BYTE_CAP")


def export_selected(output, selected, cp):
    from postlogin_pilot_source import export_chunk
    payload = {item[0]["index"]: item for item in selected}
    rows = export_chunk(output, [item[0] for item in selected], cp,
        build=lambda spec: (copy.deepcopy(payload[spec["index"]][1]), dict(payload[spec["index"]][2])), rolling=True)
    for row in rows:
        if row["rolling_features"] != row.pop("expected_rolling"):
            raise ValueError("actual Java rolling features differ from raw before-action reference")
        rolling.model_features(row)
    return rows


def benchmark(data, source, output, cp, protocol_sha, maximum_seconds):
    start = time.monotonic()
    sampler = sampling.Sampler(data, 1, "validation", [i * 16 for i in range(4000)])
    stats = {}
    for stratum, indices in sampling.benchmark_indices(data).items():
        guard(output, start, maximum_seconds)
        before = time.monotonic()
        selected = [sampler.select(index) for index in indices]
        rows = export_selected(output, selected, cp)
        elapsed = time.monotonic() - before
        stats[stratum] = {"rows": len(rows), "elapsed_seconds": elapsed,
                          "bytes": len(canonical(rows).encode()),
                          "selection_attempts": sum(row["selection_attempts"] for row in rows)}
        print(json.dumps({"stratum": stratum, **stats[stratum]}), flush=True)
    population = sampling.stratum_population()
    projection = sum(stats[key]["elapsed_seconds"] / stats[key]["rows"] * count for key, count in population.items())
    bytes_projection = sum(stats[key]["bytes"] / stats[key]["rows"] * count for key, count in population.items())
    receipt = {"status": "SOURCE_BENCHMARK_COMPLETE_NOT_TRAINING_ADMISSION", "protocol_sha256": protocol_sha,
               "strata": stats, "rows": sum(v["rows"] for v in stats.values()),
               "one_fold_rows": sum(population.values()), "projection_seconds_with_50_percent_margin": projection * 1.5,
               "projection_bytes_with_50_percent_margin": bytes_projection * 1.5,
               "elapsed_seconds": time.monotonic() - start, "new_fits": 0,
               "resource_limits": resource_limits(),
               "benchmark_ready_accounts": "fixed representative bank; production uses actual accepted FIT accounts",
               "holdout_scored": False, "auto_containment": False, "aws_changed": False}
    proof = commit(output, receipt, phase="risk-source-benchmark-v4")
    print(json.dumps({"receipt": proof, "projection_seconds_with_margin": projection * 1.5}), flush=True)


def generate(data, source, output, cp, protocol_sha, fold, maximum_seconds):
    from postlogin_pilot_source import read_committed
    start = time.monotonic()
    benchmark_receipt = read_committed(output, "risk-source-benchmark-v4")
    if not benchmark_receipt or benchmark_receipt["protocol_sha256"] != protocol_sha:
        raise ValueError("matching representative benchmark required before full source")
    if not benchmark_receipt.get("resource_limits", {}).get("verified"):
        raise ValueError("native timing alone does not admit the capped worker")
    budget = json.loads((output / "budget.private.json").read_text())
    remaining_pilot = budget["pilot_cap_seconds"] - budget["group_seconds"].get("pilot", 0)
    projected = remaining_projection(output, fold, protocol_sha, benchmark_receipt)
    if projected + 120 > min(maximum_seconds, remaining_pilot):
        raise RuntimeError("NO_GO_SOURCE_TIME_PROJECTION")
    fit_accounts = []
    ancestry = json.loads((output / "risk-source-protocol-v4.receipt.private.json").read_text())["continuation"]["inherited_batches"]
    counts, hashes = {}, {}
    for split, count in sampling.COUNTS.items():
        sampler = sampling.Sampler(data, fold, split, fit_accounts)
        split_hashes, all_rows = [], []
        for offset in range(0, count, 32):
            guard(output, start, maximum_seconds)
            unit = f"risk-source-f{fold}-{split}-{offset // 32:04d}"
            binding = {"protocol_sha256": protocol_sha, "fold": fold, "split": split,
                       "offset": offset, "count": min(32, count - offset)}
            retained = source_batch(output, unit, binding, sampler, cp, ancestry)
            if len(retained["rows"]) != binding["count"]:
                raise ValueError("committed source batch cardinality changed")
            all_rows.extend(retained["rows"])
            split_hashes.append(digest(output / (unit + ".commit.private.json")))
            if (offset // 32) % 16 == 0:
                print(json.dumps({"fold": fold, "split": split, "committed_rows": len(all_rows),
                                  "elapsed_seconds": time.monotonic() - start}), flush=True)
        if split == "fit":
            fit_accounts = [r["source_account_ordinal"] for r in all_rows]
        counts[split] = len(all_rows)
        hashes[split] = data.digest(split_hashes)
    result = {"status": "SOURCE_GENERATION_COMPLETE_NOT_QUALITY_PASS", "fold": fold,
              "protocol_sha256": protocol_sha, "split_rows": counts, "split_commit_hashes_sha256": hashes,
              "elapsed_seconds": time.monotonic() - start, "new_fits": 0, "holdout_scored": False}
    proof = commit(output, result, phase=f"risk-source-fold{fold}-result")
    print(json.dumps({"status": result["status"], "receipt": proof}), flush=True)


def source_batch(output, unit, binding, sampler, cp, ancestry=None):
    """Production batch boundary, shared by real interruption/recovery verification."""
    from postlogin_pilot_source import read_committed
    retained = read_committed(output, unit)
    if retained is None:
        selected = [sampler.select(i) for i in range(binding["offset"], binding["offset"] + binding["count"])]
        rows = export_selected(output, selected, cp)
        retained = {"binding": binding, "rows": rows, "rejected_so_far": dict(sampler.rejected)}
        commit(output, retained, phase=unit)
    else:
        if not accepted_binding(output, unit, retained["binding"], binding, ancestry or {}):
            raise ValueError("committed source input binding changed")
        for row in retained["rows"]:
            sampler.remember(row)
        sampler.rejected.update({k: v - sampler.rejected.get(k, 0)
                                 for k, v in retained["rejected_so_far"].items()})
    return retained


def accepted_binding(output, unit, actual, expected, ancestry):
    if actual == expected:
        return True
    inherited = ancestry.get(unit)
    return bool(inherited and actual.get("protocol_sha256") == inherited["protocol_sha256"]
                and {k: v for k, v in actual.items() if k != "protocol_sha256"}
                == {k: v for k, v in expected.items() if k != "protocol_sha256"}
                and digest(output / (unit + ".receipt.private.json")) == inherited["receipt_sha256"])


def remaining_projection(output, fold, protocol_sha, benchmark_receipt):
    from postlogin_pilot_source import read_committed
    remaining = sampling.stratum_population()
    ancestry = json.loads((output / "risk-source-protocol-v4.receipt.private.json").read_text())["continuation"]["inherited_batches"]
    for split, count in sampling.COUNTS.items():
        for offset in range(0, count, 32):
            unit = f"risk-source-f{fold}-{split}-{offset // 32:04d}"
            retained = read_committed(output, unit)
            if retained is None:
                continue
            expected = {"protocol_sha256": protocol_sha, "fold": fold, "split": split,
                        "offset": offset, "count": min(32, count - offset)}
            if not accepted_binding(output, unit, retained["binding"], expected, ancestry) or len(retained["rows"]) != expected["count"]:
                raise ValueError("committed source binding/count changed during resume projection")
            for row in retained["rows"]:
                key = row["cohort"] + "/" + row["family"]
                remaining[key] -= 1
                if remaining[key] < 0:
                    raise ValueError("committed population exceeds the declared stratum")
    return sum(benchmark_receipt["strata"][key]["elapsed_seconds"] /
               benchmark_receipt["strata"][key]["rows"] * count * 1.5 for key, count in remaining.items())


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--mode", choices=("benchmark", "generate"), required=True)
    p.add_argument("--fold", type=int, choices=(1, 2, 3), default=1)
    p.add_argument("--maximum-seconds", type=int, required=True)
    a = p.parse_args()
    if not resource_limits()["verified"]:
        raise RuntimeError("CAPPED_SOURCE_WORKER_REQUIRED_BEFORE_BENCHMARK_OR_GENERATION")
    source, output = private_directory(a.source), private_directory(a.output)
    data = frozen_generator(source, a.frozen_code.resolve())
    cp = rolling.java_classpath(source, output)
    protocol_sha = source_protocol(source, output)
    if a.mode == "benchmark":
        benchmark(data, source, output, cp, protocol_sha, a.maximum_seconds)
    else:
        generate(data, source, output, cp, protocol_sha, a.fold, a.maximum_seconds)
