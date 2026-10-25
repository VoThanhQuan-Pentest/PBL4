#!/usr/bin/env python3
"""Replay the real reserved calibration prefix and exercise all remaining READY slots.

Does not publish production rows or alter any inherited batch. It verifies the
single sampler repair before resuming the long generation job.
"""
import argparse
import json
from pathlib import Path

from postlogin_risk_probe import frozen_generator
from postlogin_risk_data import Sampler, COUNTS
from postlogin_risk_rolling import java_classpath
from postlogin_risk_source import source_protocol, accepted_binding, export_selected, resource_limits
from ueba_research_artifacts import commit, digest, private_directory


def run(source, frozen, output):
    if not resource_limits()["verified"]:
        raise RuntimeError("capped offline worker required")
    data = frozen_generator(source, frozen)
    from postlogin_pilot_source import read_committed
    cp = java_classpath(source, output)
    protocol = source_protocol(source, output)
    ancestry = json.loads((output / "risk-source-protocol-v4.receipt.private.json").read_text())["continuation"]["inherited_batches"]
    loaded, retained = {}, {}
    for split in ("fit", "calibration"):
        rows = []
        for offset in range(0, COUNTS[split], 32):
            unit = f"risk-source-f1-{split}-{offset // 32:04d}"
            previous = read_committed(output, unit)
            if previous is None:
                break
            expected = {"protocol_sha256": protocol, "fold": 1, "split": split, "offset": offset,
                        "count": min(32, COUNTS[split] - offset)}
            if not accepted_binding(output, unit, previous["binding"], expected, ancestry):
                raise ValueError("inherited source binding changed")
            retained[unit] = digest(output / (unit + ".receipt.private.json"))
            rows.extend(previous["rows"])
        loaded[split] = rows
    if len(loaded["fit"]) != 4000 or not 0 < len(loaded["calibration"]) < 4000:
        raise ValueError("real partially filled READY calibration prefix required")
    sampler = Sampler(data, 1, "calibration", [r["source_account_ordinal"] for r in loaded["fit"]])
    for row in loaded["calibration"]:
        sampler.remember(row)
    selected, checked = [], 0
    for index in range(len(loaded["calibration"]), 4000):
        item = sampler.select(index)
        if item[2]["training_context"] != 0:
            raise ValueError("reference context changed during slot repair")
        checked += 1
        if len(selected) < 4 or index >= 3996:
            selected.append(item)
    probes = export_selected(output, selected, cp)
    for unit, before in retained.items():
        if digest(output / (unit + ".receipt.private.json")) != before:
            raise ValueError("sampler repair rewrote inherited source")
    result = {"status": "REAL_PREFIX_READY_SLOT_RECOVERY_PASS", "retained_rows": sum(map(len, loaded.values())),
              "retained_batches": len(retained), "retained_batch_hashes_sha256": data.digest(retained),
              "remaining_ready_rows_checked": checked, "ready_account_hours_after_probe": len(sampler.used),
              "actual_java_probe_rows": len(probes), "old_batches_unchanged": True,
              "new_production_rows": 0, "new_fits": 0, "protocol_sha256": protocol,
              "scope": "DIAGNOSTIC_RECOVERY_ONLY_NOT_TRAINING_POPULATION"}
    proof = commit(output, result, phase="risk-ready-resume-check")
    print(json.dumps({"status": result["status"], "checked": checked, "receipt": proof}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--frozen-code", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--fold", type=int, default=1)
    p.add_argument("--maximum-seconds", type=int, required=True)
    a = p.parse_args()
    run(private_directory(a.source), a.frozen_code.resolve(), private_directory(a.output))
