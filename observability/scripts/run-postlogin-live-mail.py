#!/usr/bin/env python3
"""Bounded Maven lab; credentials enter the child environment, never argv/output."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from postlogin_mail_config import load
from ueba_research_artifacts import private_directory

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--config", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--mode", choices=("scoped", "profile"), default="scoped")
args = parser.parse_args()
root = private_directory(args.output)
settings = load(args.config)
recipient = json.loads((root / "mail-smoke-target.private.json").read_text())
if recipient["source"] != "USER_PROVIDED_OWNED_LAB_MAILBOX":
    raise ValueError("OWNED_MAILBOX_ATTESTATION_REQUIRED")
environment = {**os.environ, **settings, "FLARE_LIVE_MAIL_SMOKE": "true",
               "FLARE_LIVE_MAIL_RECIPIENT": recipient["recipient"], "FLARE_LIVE_MAIL_OUTPUT": str(root)}
environment["FLARE_LIVE_PROFILE_SMOKE"] = "true" if args.mode == "profile" else "false"
environment["JDK_JAVA_OPTIONS"] = "-Xmx768m -XX:ActiveProcessorCount=2"
test = "SensitiveActionLiveProfileTest" if args.mode == "profile" else "SensitiveActionLiveMailSmokeTest"
result = subprocess.run(["mvn", "-q", "-f", "backend/pom.xml", "-Dtest=" + test, "test"],
                        env=environment, timeout=1190 if args.mode == "profile" else 590)
raise SystemExit(result.returncode)
