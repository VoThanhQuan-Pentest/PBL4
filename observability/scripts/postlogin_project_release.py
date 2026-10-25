#!/usr/bin/env python3
"""Build a source-bound, dependency-preserving local release. No fits or deployments."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from postlogin_impl_control import OUTPUT,REPO,RUNTIME,held,runtime_hold
from postlogin_preparation_audit import checked
from ueba_research_artifacts import commit,digest,private_directory

WORKER_BASE='sha256:f7712a973c12e2d33c01f4559a94c5259d105b247efd0018a6fe63deb7d03a9f'
SOURCE_ROOTS=['backend/src/main','ueba-worker/app','frontend/src','desktop-client/src/main']

def inventory():
    result={}
    for root in SOURCE_ROOTS:
        for path in sorted((REPO/root).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':result[str(path.relative_to(REPO))]=digest(path)
    for name in ['backend/pom.xml','frontend/package.json','frontend/package-lock.json','desktop-client/pom.xml']:
        result[name]=digest(REPO/name)
    return result

def verify_source(receipt):
    if inventory()!=receipt['source_sha256']:raise RuntimeError('RELEASE_SOURCE_CHANGED_USE_A_NEW_VERSION')

def run(argv,**kwargs):
    if held():raise RuntimeError('OPERATOR_HOLD')
    return subprocess.run(argv,cwd=kwargs.pop('cwd',REPO),check=True,**kwargs)

def model_publication():
    model=OUTPUT/'project-model-v1'
    proof=checked(OUTPUT,'fixed-model-export-v1')
    expected='7baa6304d138647db3c4c9c6ef9176fe63f425ec861a1c5b5561865ac8f97784'
    if digest(model/'manifest.json')!=expected:raise RuntimeError('FIXED_MANIFEST_CHANGED')
    manifest=json.loads((model/'manifest.json').read_text())
    for name,key in [('model-state.json','state_sha256'),('calibration.json','calibration_sha256')]:
        if digest(model/name)!=manifest[key]:raise RuntimeError('MODEL_COMPONENT_CHANGED')
    RUNTIME.mkdir(mode=0o750,exist_ok=True)
    if RUNTIME.is_symlink() or RUNTIME.stat().st_mode&0o027:raise RuntimeError('UNSAFE_RUNTIME_DIRECTORY')
    target=RUNTIME/'model-v1';target.mkdir(mode=0o750,exist_ok=True)
    for name in ['manifest.json','model-state.json','calibration.json']:
        path=target/name
        if path.exists():
            if path.is_symlink() or digest(path)!=digest(model/name):raise RuntimeError('PUBLISHED_MODEL_CHANGED')
        else:
            with path.open('xb') as output:
                os.chmod(path,0o640);output.write((model/name).read_bytes());output.flush();os.fsync(output.fileno())
    runtime_hold(True)
    return expected

def main():
    phase='project-release-v1'
    marker=OUTPUT/(phase+'.commit.private.json')
    if marker.exists():
        proof=checked(OUTPUT,phase);verify_source(proof)
        for service,value in proof['images'].items():
            actual=subprocess.check_output(['docker','image','inspect',value['tag'],'--format','{{.Id}}'],text=True).strip()
            if actual!=value['image_id']:raise RuntimeError('RELEASE_IMAGE_CHANGED')
        print('REUSE_VERIFIED_PROJECT_RELEASE');return
    if held():raise RuntimeError('OPERATOR_HOLD')
    if shutil.disk_usage(OUTPUT).free<5_000_000_000:raise RuntimeError('DISK_RESERVE')
    before=inventory();manifest=model_publication()
    run(['mvn','-q','-o','-f','backend/pom.xml','-DskipTests','package'],env={**os.environ,'MAVEN_OPTS':'-Xmx512m'})
    run(['npm','run','build'],cwd=REPO/'frontend')
    build=OUTPUT/'release-build-v1';build.mkdir(mode=0o700,exist_ok=True);private_directory(build)
    shutil.copy2(REPO/'backend/target/backend-0.0.1-SNAPSHOT.jar',build/'app.jar')
    shutil.copytree(REPO/'frontend/dist',build/'frontend',dirs_exist_ok=True)
    shutil.copytree(REPO/'ueba-worker/app',build/'worker/app',dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    bases={'app':subprocess.check_output(['docker','inspect','flare-otp-local-app-1','--format','{{.Image}}'],text=True).strip(),
           'nginx':subprocess.check_output(['docker','inspect','flare-otp-local-nginx-1','--format','{{.Image}}'],text=True).strip(),
           'worker':WORKER_BASE}
    images={}
    for service,base in bases.items():
        base_tag='flare/postlogin-base-'+service+':20261022'
        run(['docker','tag',base,base_tag])
        dockerfile=build/('Dockerfile.'+service)
        copy={'app':'COPY --chown=10001:10001 app.jar /app/app.jar\n',
              'nginx':'COPY --chown=101:101 frontend/ /usr/share/nginx/html/\n',
              'worker':'COPY --chown=10001:10001 worker/app/ /service/app/\nENV UEBA_POSTLOGIN_SERVING_ONLY=true OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1\n'}[service]
        dockerfile.write_text('FROM '+base_tag+'\nLABEL flare.postlogin.implementation="legacy-20261022"\n'+copy)
        tag='flare/postlogin-'+service+':project-v1'
        run(['docker','build','--network','none','-f',str(dockerfile),'-t',tag,str(build)])
        image_id=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
        images[service]={'tag':tag,'image_id':image_id,'base_image_id':base}
    if inventory()!=before:raise RuntimeError('SOURCE_CHANGED_DURING_RELEASE')
    commit(OUTPUT,{'status':'SOURCE_BOUND_PROJECT_RELEASE_BUILT','source_sha256':before,'images':images,
        'application_jar_sha256':digest(build/'app.jar'),'manifest_sha256':manifest,'new_fits':0,
        'dependency_upgrades':False,'deployed':False,'qualification_scope':'PROJECT_LIMITED'},phase=phase)
    print('SOURCE_BOUND_PROJECT_RELEASE_BUILT; not deployed',flush=True)

if __name__=='__main__':main()
