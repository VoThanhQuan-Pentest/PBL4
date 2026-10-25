#!/usr/bin/env python3
"""Accept a gated, explicitly allowlisted local lab policy; never touch AWS/global config."""
import argparse
import os
from pathlib import Path
import subprocess

from postlogin_action_lab_gate import checked
from ueba_research_artifacts import private_directory

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("output",type=Path)
args=parser.parse_args()
root=private_directory(args.output)
gate=checked(root,"lab-action-gate-result-v1")
if gate["status"]!="LAB_ACTION_GATE_PASS":raise RuntimeError("LOCAL_OTP_ACTIVATION_REQUIRES_LAB_GATE")
environment={k:v for k,v in os.environ.items() if not k.startswith(("APP_MAIL_","FLARE_LIVE_"))}
environment.update(FLARE_LOCAL_OTP_ACCEPTANCE="true",APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED="true",
    APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST="confirmation-password,confirmation-email,confirmation-mail-fault,confirmation-db-fault,confirmation-password-runtime",
    JDK_JAVA_OPTIONS="-Xmx512m -XX:ActiveProcessorCount=2",MAVEN_OPTS="-Xmx128m")
result=subprocess.run(["mvn","-q","-f","backend/pom.xml","-Dtest=SensitiveActionLocalAllowlistAcceptanceTest","test"],env=environment,timeout=250)
raise SystemExit(result.returncode)
