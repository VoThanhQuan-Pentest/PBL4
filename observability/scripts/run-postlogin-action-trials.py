#!/usr/bin/env python3
"""Two-CPU bounded lab trials; no real mail configuration or real recipients."""
import argparse
import os
from pathlib import Path
import subprocess

from ueba_research_artifacts import private_directory

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--owners", type=int, required=True)
parser.add_argument("--invalid", type=int, required=True)
parser.add_argument("--name", choices=("benchmark-v4", "full-v1"), required=True)
parser.add_argument("--maximum-seconds", type=int, required=True)
args = parser.parse_args()
root = private_directory(args.output)
if not 1 <= args.owners <= 5000 or not 1 <= args.invalid <= 2000 or not 30 <= args.maximum_seconds <= 8700:
    raise ValueError("bounded lab counts and deadline required")
cpus = sorted(os.sched_getaffinity(0))[:2]
if len(cpus) != 2:
    raise RuntimeError("two available lab CPUs required")
cpuset = ",".join(map(str, cpus))
environment = {k: v for k, v in os.environ.items() if not k.startswith(("APP_MAIL_", "FLARE_LIVE_"))}
environment.update(FLARE_CONTROLLED_ACTION_TRIAL="true", FLARE_LAB_CPUSET=cpuset,
                   JDK_JAVA_OPTIONS="-Xmx512m -XX:ActiveProcessorCount=2", MAVEN_OPTS="-Xmx128m")
result = subprocess.run(["taskset", "-c", cpuset, "mvn", "-q", "-f", "backend/pom.xml",
    "-Dtest=SensitiveActionTrialIntegrationTest", "-Dconfirmation.trials.enabled=true",
    "-Dconfirmation.trials.owners=" + str(args.owners), "-Dconfirmation.trials.invalid=" + str(args.invalid),
    "-Dconfirmation.trials.output=" + str(root / ("otp-trial-" + args.name + ".private.json")), "test"],
    env=environment, timeout=args.maximum_seconds)
raise SystemExit(result.returncode)
