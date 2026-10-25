#!/usr/bin/env python3
"""Read-only compact progress; partial rows never imply a passing lab gate."""
import argparse
from collections import Counter
import json

from ueba_research_artifacts import private_directory

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("output")
args=parser.parse_args()
root=private_directory(args.output)
path=root/"otp-trial-full-v1.private.json"
if path.is_symlink() or path.stat().st_size>16*1024**2 or path.stat().st_mode & 0o077:
    raise ValueError("private bounded trial snapshot required")
document=json.loads(path.read_text())
print(json.dumps({"completed":len(document["outcomes"]),"expected":14004,
    "by_operation":dict(Counter(r["operation"]for r in document["outcomes"])),
    "status":document["status"],"snapshot_elapsed_seconds":document["elapsed_seconds"]}),flush=True)
