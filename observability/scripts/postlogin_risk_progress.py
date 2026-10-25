#!/usr/bin/env python3
"""Compact read-only view of durable risk-source batches and the live deadline."""
import argparse
from datetime import datetime, timezone
import json

from ueba_research_artifacts import digest, private_directory


def progress(root):
    counts = {}
    for split, expected in (("fit", 4000), ("calibration", 10000), ("validation", 21000)):
        markers = sorted(root.glob(f"risk-source-f1-{split}-*.commit.private.json"))
        if not markers:
            counts[split] = {"committed": 0, "expected": expected}
            continue
        last = markers[-1]
        marker = json.loads(last.read_text())
        receipt = root / marker["receipt"]
        if receipt.name != last.name.replace(".commit.", ".receipt.") or digest(receipt) != marker["receipt_sha256"]:
            raise ValueError("last source commit changed")
        binding = json.loads(receipt.read_text())["binding"]
        if len(markers) != binding["offset"] // 32 + 1:
            raise ValueError("source batch inventory has a gap")
        counts[split] = {"committed": binding["offset"] + binding["count"], "expected": expected}
    budget = json.loads((root / "budget.private.json").read_text())
    active = budget["active_unit"]
    remaining = None if active is None else max(0, (datetime.fromisoformat(active["deadline_utc"])
                                                   - datetime.now(timezone.utc)).total_seconds())
    return {"source_rows": counts, "active_unit": None if active is None else active["id"],
            "seconds_until_active_deadline": remaining, "charged_job_seconds": budget["elapsed_seconds"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root")
    args = p.parse_args()
    print(json.dumps(progress(private_directory(args.root))), flush=True)
