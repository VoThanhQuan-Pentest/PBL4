#!/usr/bin/env python3
"""Run opt-in JavaFX acceptance against the local primary API; credentials stay in child memory."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
FOLDER=ROOT/'observability/runtime/private-backups/siem-workspace-20261024-r1'
OLD=ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'

def main():
    spec=importlib.util.spec_from_file_location('workspace_demo',ROOT/'observability/scripts/local-soc-demo.py');demo=importlib.util.module_from_spec(spec);spec.loader.exec_module(demo)
    env=os.environ.copy();env.update(FLARE_SIEM_LIVE_UI='true',FLARE_SIEM_LIVE_PRECISION_UI='true',FLARE_SIEM_LIVE_UI_OUTPUT=str(FOLDER/'live-ui'),
        FLARE_SIEM_PRACTICE_CASES=','.join(json.loads((OLD/'live-ui/case-ids.private.json').read_text())),
        FLARE_SIEM_PRECISION_CASE_ID=json.loads((OLD/'live-ui/precision-case-id.private.json').read_text()),
        JAVA_TOOL_OPTIONS='-Xmx384m -XX:ActiveProcessorCount=2',MAVEN_OPTS='-Xmx256m')
    for role in ('l1','l2'):
        for key in ('username','password'):env['FLARE_SOC_'+role.upper()+'_'+key.upper()]=demo.ACCOUNTS[role][key]
    with (FOLDER/'desktop-live-acceptance.private.log').open('w') as log:
        result=subprocess.run(['xvfb-run','-a','-s','-screen 0 1920x1080x24','mvn','-B','-ntp','-o','-f',str(ROOT/'desktop-client/pom.xml'),'-Dtest=LiveWorkspaceAcceptanceTest,LiveEvidencePrecisionTest','test'],env=env,stdout=log,stderr=log,timeout=240)
    print('LIVE_UI_ACCEPTANCE_EXIT',result.returncode)
    raise SystemExit(result.returncode)

if __name__=='__main__':main()
