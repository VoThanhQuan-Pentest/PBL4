#!/usr/bin/env python3
"""Operate the bounded, local-only fixed-model release; never trains or restores a live DB."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import urllib.parse

from postlogin_impl_control import OUTPUT,REPO,RUNTIME,held,runtime_hold,now
from postlogin_mail_config import load as load_mail
from postlogin_preparation_audit import checked
from postlogin_project_release import verify_source
from ueba_research_artifacts import commit,digest,publish

DB='flare-otp-local-db-1'
POLICY='postlogin-project-limited-v1'
COMPOSE=REPO/'docker-compose.postlogin-project.yml'

def docker(argv,**kwargs):
    return subprocess.run(['docker',*argv],check=True,**kwargs)

def inspect(name):
    return json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]

def owned_live():
    c=inspect(DB)
    if c['Config']['Labels'].get('com.docker.compose.project')!='flare-otp-local' or not c['State']['Running']:
        raise RuntimeError('RUNNING_LOCAL_OTP_DATABASE_REQUIRED')

def sql(statement,container=DB):
    result=docker(['exec','-i',container,'sh','-ceu',
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --default-character-set=utf8mb4 -N -B -u "$MYSQL_USER" "$MYSQL_DATABASE"'],
        input=statement,text=True,capture_output=True,timeout=30)
    return result.stdout.strip()

def protection(container=DB):
    # Hash inside MySQL: credentials and private profile fields never leave the database.
    users=sql("""SELECT id,SHA2(CAST(JSON_OBJECT('password',password,'email',email,'email_verified_at',email_verified_at,
        'auth_version',auth_version,'role',role,'deleted',is_deleted) AS CHAR),256)
        FROM tbl_nguoi_dung WHERE id IN ('e2e-customer','soc-demo-customer','soc-demo-l1','soc-demo-l2') ORDER BY id;""",container)
    cases=sql("""SELECT id,status,queue_tier,COALESCE(assignee_user_id,''),conclusion,version,updated_at,
        (SELECT COUNT(*) FROM siem_incident_notes n WHERE n.incident_id=i.id),
        (SELECT COUNT(*) FROM siem_incident_history h WHERE h.incident_id=i.id),
        (SELECT COUNT(*) FROM siem_response_actions r WHERE r.incident_id=i.id)
        FROM siem_incidents i WHERE id LIKE 'soc-demo-%' ORDER BY id;""",container)
    if not users or not cases:raise RuntimeError('PROTECTED_DEMO_OR_ACCOUNT_MISSING')
    return {'users_sha256':hashlib.sha256(users.encode()).hexdigest(),'reserved_cases_sha256':hashlib.sha256(cases.encode()).hexdigest()}

def verified_release():
    release=checked(OUTPUT,'project-release-v1');verify_source(release)
    for value in release['images'].values():
        actual=subprocess.check_output(['docker','image','inspect',value['tag'],'--format','{{.Id}}'],text=True).strip()
        if actual!=value['image_id']:raise RuntimeError('RELEASE_IMAGE_CHANGED')
    manifest=RUNTIME/'model-v1/manifest.json'
    if digest(manifest)!=release['manifest_sha256']:raise RuntimeError('RUNTIME_MODEL_MANIFEST_CHANGED')
    contents=json.loads(manifest.read_text())
    for name,key in [('model-state.json','state_sha256'),('calibration.json','calibration_sha256')]:
        if digest(manifest.parent/name)!=contents[key]:raise RuntimeError('RUNTIME_MODEL_COMPONENT_CHANGED')
    return release

def environment(release):
    path=REPO/'observability/runtime/local-otp-rollout-20261020-r1/site-settings.private.json'
    info=path.lstat()
    if path.is_symlink() or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise RuntimeError('PRIVATE_SITE_SETTINGS_REQUIRED')
    settings=json.loads(path.read_text())
    if settings.get('APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED')!='true':raise RuntimeError('EXISTING_OTP_MUST_REMAIN_ENABLED')
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','DOCKER_HOST','DOCKER_CONTEXT','XDG_RUNTIME_DIR')}
    env.update(settings);env.update(load_mail('/home/quan/.config/flare-lab/mail.env'))
    env.update(SPRING_DATASOURCE_USERNAME=settings['MYSQL_USER'],SPRING_DATASOURCE_PASSWORD=settings['MYSQL_PASSWORD'],
        FLARE_INTERNAL_SUBNET='172.31.90.0/24',MYSQL_HOST_PORT='13307',
        APP_CORS_ALLOWED_ORIGINS='http://localhost:8088,http://127.0.0.1:8088',
        OTP_LOCAL_FLYWAY_IGNORE_MIGRATION_PATTERNS='repeatable:missing',
        APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST='e2e-customer',
        FLARE_POSTLOGIN_RUNTIME_DIR=str(RUNTIME),FLARE_POSTLOGIN_SERVICE_TOKEN=str(REPO/'.secrets/ueba/worker.token'),
        FLARE_POSTLOGIN_MANIFEST_SHA256=release['manifest_sha256'],
        FLARE_POSTLOGIN_APP_IMAGE=release['images']['app']['tag'],FLARE_POSTLOGIN_NGINX_IMAGE=release['images']['nginx']['tag'],
        FLARE_POSTLOGIN_WORKER_IMAGE=release['images']['worker']['tag'])
    return env

def compose(release,*args):
    return docker(['compose','--env-file','/dev/null','-p','flare-otp-local','-f','docker-compose.yml',
        '-f','docker-compose.otp-local.yml','-f',str(COMPOSE),*args],cwd=REPO,env=environment(release))

def validate_compose(release):
    result=docker(['compose','--env-file','/dev/null','-p','flare-otp-local','-f','docker-compose.yml',
        '-f','docker-compose.otp-local.yml','-f',str(COMPOSE),'config','--format','json'],
        cwd=REPO,env=environment(release),capture_output=True,text=True)
    services=json.loads(result.stdout)['services']
    selected=[services[name] for name in ('app','nginx','db','redis','postlogin-worker')]
    cpu=sum(float(service['cpus']) for service in selected);memory=sum(int(service['mem_limit']) for service in selected)
    app=services['app']['environment'];worker=services['postlogin-worker']
    origin=urllib.parse.urlsplit(app['SIEM_UEBA_URL'])
    aliases=worker.get('networks',{}).get('flare-internal',{}).get('aliases',[])
    if (origin.scheme!='http' or origin.hostname!='ueba-worker' or origin.port!=8091
            or origin.username is not None or origin.password is not None or origin.path or origin.query or origin.fragment
            or 'ueba-worker' not in aliases or worker.get('ports') or cpu>4 or memory>4*1024**3
            or app.get('APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED')!='true'
            or app.get('APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST')!='e2e-customer'
            or app.get('SIEM_UEBA_ENABLED')!='false'
            or worker['environment'].get('UEBA_POSTLOGIN_SERVING_ONLY')!='true'):
        raise RuntimeError('COMPOSE_INTERNAL_ORIGIN_OTP_OR_RESOURCE_CONTRACT_FAILED')
    return {'cpu':cpu,'memory_bytes':memory,'worker_origin':'http://ueba-worker:8091'}

def backup():
    path=OUTPUT/'local-site-before-project-rollout.sql.gz'
    marker=OUTPUT/'project-rollout-backup-v1.commit.private.json'
    if marker.exists():
        proof=checked(OUTPUT,'project-rollout-backup-v1')
        if digest(path)!=proof['sha256']:raise RuntimeError('ROLLOUT_BACKUP_CHANGED')
        return path
    if path.exists():raise RuntimeError('UNCOMMITTED_BACKUP_REQUIRES_RECONCILIATION')
    process=subprocess.Popen(['docker','exec',DB,'sh','-ceu',
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --single-transaction --no-tablespaces --skip-lock-tables -u "$MYSQL_USER" "$MYSQL_DATABASE"'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with path.open('xb') as output:
        os.chmod(path,0o600)
        with gzip.GzipFile(fileobj=output,mode='wb',mtime=0) as compressed:
            while block:=process.stdout.read(1024*1024):compressed.write(block)
        output.flush();os.fsync(output.fileno())
    process.wait(timeout=30)
    if process.returncode:raise RuntimeError('PRIVATE_BACKUP_FAILED')
    with gzip.open(path,'rb') as check:
        if len(check.read())<1000:raise RuntimeError('EMPTY_BACKUP')
    commit(OUTPUT,{'status':'ROLLOUT_BACKUP_READBACK_PASS','sha256':digest(path),'path':path.name,
        'protection':protection(),'source_modified':False},phase='project-rollout-backup-v1')
    return path

def wait_health(name,seconds=180):
    deadline=time.monotonic()+seconds
    while True:
        state=inspect(name)['State']
        if state.get('Health',{}).get('Status')=='healthy':return
        if not state['Running']:raise RuntimeError('CONTAINER_EXITED_CHECK_PRIVATE_LOGS')
        if time.monotonic()>deadline:raise RuntimeError('HEALTH_DEADLINE')
        time.sleep(2)

def clone_migration(release):
    if held():raise RuntimeError('OPERATOR_HOLD')
    if (OUTPUT/'project-migration-clone-v1.commit.private.json').exists():
        proof=checked(OUTPUT,'project-migration-clone-v1')
        if proof['release_receipt_sha256']!=digest(OUTPUT/'project-release-v1.receipt.private.json'):raise RuntimeError('CLONE_RELEASE_MISMATCH')
        print('REUSE_VERIFIED_MIGRATION_CLONE');return
    owned_live();source=backup()
    prefix='flare-postlogin-migration-clone-v1';network=prefix
    names=[prefix+'-db',prefix+'-redis',prefix+'-app']
    for name in names:
        p=subprocess.run(['docker','inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if not p.returncode:raise RuntimeError('CLONE_EXISTS_AUDIT_BEFORE_RETRY')
    docker(['network','create','--internal','--label','flare.postlogin.implementation=legacy-20261022',network],stdout=subprocess.DEVNULL)
    created=[]
    label=['--label','flare.postlogin.implementation=legacy-20261022','--label','flare.postlogin.unit=migration-clone']
    try:
        docker(['run','-d','--name',names[0],*label,'--network',network,'--cpus','1','--memory','1g',
            '-e','MYSQL_ROOT_PASSWORD=CloneOnlyRoot#2026','-e','MYSQL_DATABASE=flare_fitness','-e','MYSQL_USER=flare',
            '-e','MYSQL_PASSWORD=CloneOnlyAccount#2026','--health-cmd',
            'MYSQL_PWD="$MYSQL_PASSWORD" mysql -h 127.0.0.1 -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B -e "SELECT 1"',
            '--health-interval','2s','--health-timeout','2s','--health-retries','45',
            'mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af'],stdout=subprocess.DEVNULL)
        created.append(names[0]);wait_health(names[0])
        if held():raise RuntimeError('OPERATOR_HOLD')
        importer=subprocess.Popen(['docker','exec','-i',names[0],'sh','-ceu',
            'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"'],
            stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            with gzip.open(source,'rb') as stream:
                while chunk:=stream.read(1024*1024):importer.stdin.write(chunk)
            importer.stdin.close();importer.wait(timeout=60)
            if importer.returncode:raise RuntimeError('CLONE_IMPORT_FAILED_SEE_PRIVATE_EVIDENCE')
        finally:
            if importer.poll() is None:importer.terminate();importer.wait(timeout=10)
        before=protection(names[0])
        if held():raise RuntimeError('OPERATOR_HOLD')
        docker(['run','-d','--name',names[1],*label,'--network',network,'--cpus','0.25','--memory','64m',
            'redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99','redis-server','--save','','--appendonly','no'],stdout=subprocess.DEVNULL)
        created.append(names[1])
        docker(['run','-d','--name',names[2],*label,'--network',network,'--cpus','1','--memory','768m','--read-only',
            '--tmpfs','/tmp:rw,nosuid,size=64m','--cap-drop','ALL','--security-opt','no-new-privileges',
            '-e','JAVA_TOOL_OPTIONS=-Xmx512m -XX:ActiveProcessorCount=1',
            '-e',f'SPRING_DATASOURCE_URL=jdbc:mysql://{names[0]}:3306/flare_fitness?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=Asia/Ho_Chi_Minh',
            '-e','SPRING_DATASOURCE_USERNAME=flare','-e','SPRING_DATASOURCE_PASSWORD=CloneOnlyAccount#2026',
            '-e','SPRING_DATA_REDIS_HOST='+names[1],'-e','SPRING_DATA_REDIS_PASSWORD=',
            '-e','APP_JWT_SECRET=isolated-clone-only-never-live-jwt-secret-2026',
            '-e','SPRING_FLYWAY_IGNORE_MIGRATION_PATTERNS=repeatable:missing',
            '-e','MANAGEMENT_HEALTH_MAIL_ENABLED=false','-e','SIEM_POSTLOGIN_ENABLED=false',
            '--health-cmd','curl --fail --silent http://127.0.0.1:8080/actuator/health',
            '--health-interval','3s','--health-timeout','3s','--health-retries','60',
            release['images']['app']['image_id']],stdout=subprocess.DEVNULL)
        created.append(names[2]);wait_health(names[2],240)
        after=protection(names[0])
        if before!=after:raise RuntimeError('CLONE_PROTECTED_STATE_CHANGED')
        version=sql("SELECT MAX(CAST(version AS UNSIGNED)) FROM flyway_schema_history WHERE success=1;",names[0])
        if version!='40':raise RuntimeError('EXPECTED_VERSION40_MIGRATION')
        if sql('SELECT mode FROM siem_postlogin_policy;',names[0])!='OFF':raise RuntimeError('MIGRATION_ENABLED_POLICY')
        commit(OUTPUT,{'status':'PROJECT_MIGRATION_CLONE_PASS','schema_version':40,'protection':after,
            'backup_sha256':digest(source),'release_receipt_sha256':digest(OUTPUT/'project-release-v1.receipt.private.json'),
            'original_database_modified':False,'live_mail_sent':False,'policy_after_migration':'OFF'},phase='project-migration-clone-v1')
        print('PROJECT_MIGRATION_CLONE_PASS')
    finally:
        for name in reversed(created):
            if inspect(name)['Config']['Labels'].get('flare.postlogin.unit')=='migration-clone':
                docker(['stop','--time','15',name],stdout=subprocess.DEVNULL)

def selected_observe():
    matches=[]
    for marker in OUTPUT.glob('project-one-hour-observe-v*.commit.private.json'):
        phase=marker.name.removesuffix('.commit.private.json');proof=checked(OUTPUT,phase)
        if proof.get('status')=='PROJECT_ONE_HOUR_OBSERVE_PASS' and proof.get('continuous_seconds',0)>=3600 and proof.get('evaluations',0)>=30:
            if proof['release_receipt_sha256']==digest(OUTPUT/'project-release-v1.receipt.private.json'):matches.append(phase)
    if not matches:raise RuntimeError('CONTINUOUS_OBSERVE_GATE_REQUIRED')
    return sorted(matches)[-1]

def policy(mode,release):
    if mode not in ('OFF','OBSERVE','ENFORCE_LIMITED'):raise ValueError('INVALID_POLICY_MODE')
    # Values are fixed operator constants, never request/user strings.
    manifest=release['manifest_sha256']
    if len(manifest)!=64 or any(c not in 'abcdef0123456789' for c in manifest):raise RuntimeError('PINNED_SHA_REQUIRED')
    sql("START TRANSACTION; UPDATE siem_postlogin_policy SET mode='"+mode+"',account_allowlist_json='[\"e2e-customer\"]',"
        "model_manifest_sha256='"+manifest+"',updated_at=UTC_TIMESTAMP(6),version=version+1 WHERE id='"+POLICY+"'; COMMIT;")

def verify_live(release):
    for service,key in [('app','app'),('nginx','nginx'),('postlogin-worker','worker')]:
        name='flare-otp-local-'+service+'-1';c=inspect(name)
        if c['Image']!=release['images'][key]['image_id'] or not c['State']['Running']:raise RuntimeError('LIVE_IMAGE_IDENTITY_MISMATCH')
    app=inspect('flare-otp-local-app-1')
    env=dict(value.split('=',1) for value in app['Config']['Env'])
    expected={'SIEM_POSTLOGIN_ENABLED':'true','SIEM_UEBA_ENABLED':'false',
        'APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED':'true',
        'APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST':'e2e-customer',
        'SIEM_POSTLOGIN_MANIFEST_SHA256':release['manifest_sha256']}
    if any(env.get(k)!=v for k,v in expected.items()):raise RuntimeError('LIVE_POLICY_OR_OTP_CONFIGURATION_MISMATCH')
    if sql("SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id='e2e-customer' AND email_verified_at IS NOT NULL AND is_deleted=0;")!='1':
        raise RuntimeError('EXISTING_VERIFIED_CUSTOMER_REQUIRED')
    for route in ('/api/health','/'):
        with urllib.request.urlopen('http://127.0.0.1:8088'+route,timeout=10) as r:
            if r.status!=200:raise RuntimeError('LIVE_HEALTH_FAILED')
    spec=importlib.util.spec_from_file_location('postlogin_soc_smoke',REPO/'observability/scripts/local-soc-demo.py')
    soc=importlib.util.module_from_spec(spec);spec.loader.exec_module(soc)
    client=soc.client()
    try:
        client.login(soc.ACCOUNTS['l1'])
        value=client.request('GET','/api/siem/postlogin-policy')
        runtime=json.loads((RUNTIME/'operator-hold.json').read_text())['hold_new_units']
        expected_mode='OBSERVE' if runtime else 'ENFORCE_LIMITED'
        if (value.get('mode')!=expected_mode or value.get('scope')!='PROJECT_LIMITED'
                or value.get('otp_required') is not True or value.get('maximum_hold_seconds')!=600):
            raise RuntimeError('LIVE_SOC_POLICY_CONTRACT_MISMATCH')
        decisions=client.request('GET','/api/siem/postlogin-decisions?page=0&size=1')
        if 'content' not in decisions:raise RuntimeError('LIVE_SOC_DECISIONS_UNAVAILABLE')
    finally:client.request('POST','/api/auth/logout',{})
    # Do not login/reset the customer's password or request a real OTP as an automation smoke test.

def deploy(release):
    observe=selected_observe();clone=checked(OUTPUT,'project-migration-clone-v1')
    if clone['release_receipt_sha256']!=digest(OUTPUT/'project-release-v1.receipt.private.json'):raise RuntimeError('CLONE_RELEASE_MISMATCH')
    if held():raise RuntimeError('OPERATOR_HOLD')
    validate_compose(release)
    owned_live();before=protection();runtime_hold(True);backup()
    commit(OUTPUT,{'status':'LOCAL_ROLLOUT_INTENT','protection_before':before,'observe_phase':observe,
        'release_receipt_sha256':digest(OUTPUT/'project-release-v1.receipt.private.json'),'policy_scope':'e2e-customer only'},phase='project-local-rollout-intent-v1')
    try:
        compose(release,'up','-d','--no-build','--pull','never','--no-deps','postlogin-worker')
        wait_health('flare-otp-local-postlogin-worker-1',90)
        if held():raise RuntimeError('OPERATOR_HOLD')
        compose(release,'up','-d','--no-build','--pull','never','--no-deps','app','nginx')
        wait_health('flare-otp-local-app-1',240)
        policy('OBSERVE',release);verify_live(release)
        if protection()!=before:raise RuntimeError('PROTECTED_STATE_CHANGED_DURING_ROLLOUT')
        if held():raise RuntimeError('OPERATOR_HOLD')
        policy('ENFORCE_LIMITED',release);runtime_hold(False)
        try:
            verify_live(release)
            if held():raise RuntimeError('OPERATOR_HOLD')
            if protection()!=before:raise RuntimeError('PROTECTED_STATE_CHANGED_AFTER_ENABLE')
        except BaseException:
            runtime_hold(True);policy('OBSERVE',release);raise
        commit(OUTPUT,{'status':'LOCAL_PROJECT_ENFORCE_LIMITED_PASS','enabled_at_utc':now(),'observe_phase':observe,
            'release_receipt_sha256':digest(OUTPUT/'project-release-v1.receipt.private.json'),
            'protected_state':before,'allowlist':['e2e-customer'],'otp_required':True,'maximum_hold_seconds':600,
            'images':release['images'],'new_fits':0,'aws_changed':False,'strict_production_qualified':False},phase='project-local-rollout-v1')
        print('LOCAL_PROJECT_ENFORCE_LIMITED_PASS http://localhost:8088')
    except BaseException:
        runtime_hold(True)
        # Keep the migrated binary and schema together. Never restore, repair, drop or deploy an older binary.
        if sql("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='siem_postlogin_policy';")=='1':
            policy('OBSERVE',release)
        raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['clone-check','deploy','start','observe','off','status'])
    args=p.parse_args();release=verified_release()
    if args.action=='clone-check':clone_migration(release)
    elif args.action=='deploy':deploy(release)
    elif args.action in ('observe','off'):
        runtime_hold(True);owned_live();policy(args.action.upper(),release);print('RUNTIME_HELD; OTP unchanged')
    elif args.action=='start':
        if held():raise RuntimeError('EXPLICIT_RESUME_REQUIRED')
        checked(OUTPUT,'project-local-rollout-v1')
        validate_compose(release)
        runtime_hold(True)
        compose(release,'up','-d','--no-build','--pull','never','--wait','--wait-timeout','240','db','redis','postlogin-worker','app','nginx')
        verify_live(release);runtime_hold(False);print('VERIFIED_LOCAL_PROJECT_SITE_READY http://localhost:8088')
    else:
        owned_live();print(json.dumps({'policy':sql('SELECT mode,version,account_allowlist_json FROM siem_postlogin_policy;'),
            'operator_hold':json.loads((RUNTIME/'operator-hold.json').read_text())['hold_new_units'],'scope':'PROJECT_LIMITED'}))

if __name__=='__main__':main()
