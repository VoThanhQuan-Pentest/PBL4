#!/usr/bin/env python3
"""One isolated continuous OBSERVE epoch using the exact built worker; no live mail or fits."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request
import zipfile

from postlogin_impl_control import OUTPUT,REPO,RUNTIME,held,read,now
from postlogin_preparation_audit import checked
from postlogin_project_release import verify_source
from ueba_research_artifacts import commit,private_directory,publish,digest

NAME='flare-postlogin-impl-observe-worker-v1'

def check_classes(release):
    jar=OUTPUT/'release-build-v1/app.jar'
    if digest(jar)!=release['application_jar_sha256']:raise RuntimeError('PACKAGED_JAR_CHANGED')
    with zipfile.ZipFile(jar) as archive:
        for path in (REPO/'backend/target/classes').rglob('*'):
            if not path.is_file():continue
            entry='BOOT-INF/classes/'+str(path.relative_to(REPO/'backend/target/classes'))
            if hashlib.sha256(archive.read(entry)).hexdigest()!=digest(path):raise RuntimeError('TESTED_CLASS_DIFFERS_FROM_PACKAGED_APPLICATION')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--epoch',type=int,default=1)
    args=parser.parse_args()
    if not 1<=args.epoch<=10:raise ValueError('BOUNDED_EXPLICIT_EPOCH_REQUIRED')
    name=f'flare-postlogin-impl-observe-worker-v{args.epoch}'
    phase=f'project-one-hour-observe-v{args.epoch}'
    release=checked(OUTPUT,'project-release-v1');verify_source(release);check_classes(release)
    if held():raise RuntimeError('OPERATOR_HOLD')
    if (OUTPUT/(phase+'.commit.private.json')).exists():
        checked(OUTPUT,phase);print('REUSE_VERIFIED_OBSERVE');return
    root=OUTPUT/f'observe-v{args.epoch}';root.mkdir(mode=0o700,exist_ok=True);private_directory(root)
    if (root/'observe-result.private.json').exists():raise RuntimeError('RECONCILE_PRIOR_OBSERVE_EPOCH_NO_BLIND_REPLAY')
    token=root/'lab-only.token'
    if not token.exists():
        with token.open('x') as stream:
            os.chmod(token,0o600);stream.write('postlogin-isolated-zero-fit-lab-only-token-v1');stream.flush();os.fsync(stream.fileno())
    hold=root/'runtime-hold.json';publish(hold,{'hold_new_units':False})
    existing=subprocess.run(['docker','inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if existing.returncode==0:raise RuntimeError('OBSERVE_WORKER_ALREADY_EXISTS_VERIFY_OWNERSHIP_FIRST')
    env={**os.environ,'FLARE_POSTLOGIN_OBSERVE':'true','FLARE_CONTROLLED_ACTION_TRIAL':'true',
        'FLARE_POSTLOGIN_OBSERVE_DIR':str(root),'FLARE_POSTLOGIN_TOKEN_FILE':str(token),
        'FLARE_POSTLOGIN_RUNTIME_HOLD_FILE':str(hold),'FLARE_POSTLOGIN_IMPLEMENTATION_HOLD_FILE':str(OUTPUT/'operator-hold.private.json'),
        'JAVA_TOOL_OPTIONS':'-Xmx768m -XX:ActiveProcessorCount=2','MAVEN_OPTS':'-Xmx256m'}
    child=None
    def interrupted(signum,frame):raise InterruptedError('SAFE_OBSERVE_INTERRUPTION')
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    try:
        subprocess.run(['docker','run','-d','--name',name,'--label','flare.postlogin.implementation=legacy-20261022',
            '--label','flare.postlogin.unit=project-observe','--cpus','1','--memory','384m','--user','1000:1000',
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,size=64m',
            '-p','127.0.0.1::8091','-e','UEBA_SERVICE_TOKEN_FILE=/run/lab.token',
            '-e','UEBA_POSTLOGIN_MODEL_DIR=/run/model','-e','UEBA_POSTLOGIN_MANIFEST_SHA256='+release['manifest_sha256'],
            '-v',str(token)+':/run/lab.token:ro','-v',str(RUNTIME/'model-v1')+':/run/model:ro',
            release['images']['worker']['image_id']],check=True,stdout=subprocess.DEVNULL)
        address=json.loads(subprocess.check_output(['docker','inspect',name,'--format','{{json .NetworkSettings.Ports}}'],text=True))['8091/tcp'][0]
        url='http://127.0.0.1:'+address['HostPort'];env['FLARE_POSTLOGIN_WORKER_URL']=url
        deadline=time.monotonic()+30
        while True:
            try:
                with urllib.request.urlopen(url+'/health',timeout=2) as response:
                    value=json.loads(response.read(65536))
                    if value.get('serving_only') is True and value['postlogin'].get('manifest_sha256')==release['manifest_sha256']:break
            except (OSError,ValueError):pass
            if time.monotonic()>deadline:raise RuntimeError('SERVING_WORKER_START_DEADLINE')
            time.sleep(.25)
        state=read('operator-state.private.json');state.update(status='PROJECT_OBSERVE_RUNNING',phase='P5',
            active_handle={'worker':name,'endpoint':url,'epoch':args.epoch},next_action='Continuous1h isolated OBSERVE;0fit; no live mail or production qualification.')
        publish(OUTPUT/'operator-state.private.json',state)
        child=subprocess.Popen(['mvn','-q','-o','-f','backend/pom.xml','-Dtest=PostloginProjectObserveTest','test'],cwd=REPO,env=env)
        code=child.wait(timeout=4050)
        result_path=root/'observe-result.private.json'
        if not result_path.exists():raise RuntimeError('OBSERVE_NO_FINAL_RESULT_CHECK_TEST_REPORT')
        result=json.loads(result_path.read_text())
        if code or result.get('status')!='PROJECT_ONE_HOUR_OBSERVE_PASS':raise RuntimeError('OBSERVE_NOT_COMPLETE_NO_DEPLOY')
        verify_source(release);check_classes(release)
        if result['continuous_seconds']<3600 or result['evaluations']<30:raise RuntimeError('CONTINUOUS_OBSERVE_GATE_NOT_MET')
        commit(OUTPUT,{**result,'release_receipt_sha256':digest(OUTPUT/'project-release-v1.receipt.private.json'),
            'evaluations_sha256':digest(root/'observe-evaluations.private.json'),
            'worker_image_id':release['images']['worker']['image_id'],'live_website_changed':False,'epoch':args.epoch},phase=phase)
        print('PROJECT_ONE_HOUR_OBSERVE_PASS',flush=True)
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=10)
        owned=subprocess.run(['docker','inspect',name,'--format','{{index .Config.Labels "flare.postlogin.implementation"}}'],capture_output=True,text=True)
        if owned.returncode==0 and owned.stdout.strip()=='legacy-20261022':
            subprocess.run(['docker','stop','-t','10',name],check=True,stdout=subprocess.DEVNULL)
            # Stopped evidence remains inspectable until the next explicitly reconciled epoch.

if __name__=='__main__':main()
