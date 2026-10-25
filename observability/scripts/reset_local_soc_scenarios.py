#!/usr/bin/env python3
"""Explicit local fixture reset: delete scoped demo/practice evidence and create one case of each."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from datetime import datetime,timezone

from ueba_research_artifacts import private_directory,publish,digest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('soc_fixture_reset',ROOT/'observability/scripts/local-soc-demo.py')
soc=importlib.util.module_from_spec(spec);spec.loader.exec_module(soc)
TARGETS=('soc-demo-customer','soc-practice-customer')
APP='flare-otp-local-app-1'
VOLUME='flare-otp-local_security-event-logs'
WORKER='flare/postlogin-worker:project-v1'
ID=re.compile(r'soc-(demo|practice)-\d{8}-\d{6}-[0-9a-f]{6}')

def checked_fixtures(rows):
    for row in rows:
        if (not ID.fullmatch(row['id']) or row['origin']!='UEBA' or row['rule_id']!='SOC_DEMO_WORKFLOW'
                or row['target_user_id'] not in TARGETS or not row['classification_reason'].startswith('DEMO_ONLY_WORKFLOW_FIXTURE:')):
            raise RuntimeError('REFUSE_NONFIXTURE_INCIDENT_WITH_SIMILAR_PREFIX')
    return rows

def scope(ids):
    if not ids or any(not ID.fullmatch(value) for value in ids):raise ValueError('EXPLICIT_FIXTURE_IDS_REQUIRED')
    return '('+','.join(soc.literal(value) for value in ids)+')'

def selectors(ids):
    cases=scope(ids);accounts='('+','.join(soc.literal(value) for value in TARGETS)+')'
    result={name:'incident_id IN '+cases for name in ('siem_alert_refs','siem_incident_notes','siem_incident_history','siem_response_actions')}
    result['siem_incidents']='id IN '+cases
    result['siem_security_events']='actor_user_id IN '+accounts+' OR target_user_id IN '+accounts
    result['siem_account_behavior_windows']='account_id IN '+accounts
    return result

def fetch(table,where):
    if table not in selectors(['soc-demo-20000101-000000-000000']):raise ValueError('ALLOWLISTED_TABLE_REQUIRED')
    columns=soc.sql("SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name="
        +soc.literal(table)+' ORDER BY ordinal_position;').splitlines()
    if any(not re.fullmatch('[a-z0-9_]+',c) for c in columns):raise RuntimeError('UNEXPECTED_COLUMN_NAME')
    pairs=','.join(soc.literal(c)+',`'+c+'`' for c in columns)
    return [json.loads(line) for line in soc.sql('SELECT JSON_OBJECT('+pairs+') FROM `'+table+'` WHERE ('+where+');').splitlines() if line]

def identity_digest():
    # Return hashes only; no password/profile values leave MySQL.
    rows=soc.sql("SELECT id,SHA2(CAST(JSON_OBJECT('password',password,'email',email,'role',role,'version',auth_version,'deleted',is_deleted) AS CHAR),256) "
        "FROM tbl_nguoi_dung ORDER BY id;")
    return hashlib.sha256(rows.encode()).hexdigest()

def other_counts(ids):
    return {'incidents':soc.sql('SELECT COUNT(*) FROM siem_incidents WHERE id NOT IN '+scope(ids)+';'),
        'postlogin_decisions':soc.sql('SELECT COUNT(*) FROM siem_postlogin_decisions;'),
        'policy':soc.sql('SELECT mode,version,account_allowlist_json FROM siem_postlogin_policy;')}

LOG_FILTER=r'''
import glob,json,os,stat
targets={'soc-demo-customer','soc-practice-customer'}
counts={}
for filename in sorted(glob.glob('/logs/security-events.ndjson*')):
    info=os.lstat(filename)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise RuntimeError('UNSAFE_LOG_FILE')
    temporary=filename+'.soc-reset-pending'
    removed=kept=0
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,stat.S_IMODE(info.st_mode))
    try:
        with open(filename,'rb') as source,os.fdopen(fd,'wb') as output:
            for line in source:
                try:
                    row=json.loads(line)
                    actor=row.get('user',{}).get('id')
                    target=row.get('target',{}).get('user',{}).get('id')
                    selected=actor in targets or target in targets
                except (ValueError,AttributeError,TypeError):selected=False
                if selected:removed+=1
                else:output.write(line);kept+=1
            output.flush();os.fsync(output.fileno())
        if removed:os.replace(temporary,filename)
        else:os.unlink(temporary)
        counts[os.path.basename(filename)]={'removed':removed,'kept':kept}
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
directory=os.open('/logs',os.O_DIRECTORY);os.fsync(directory);os.close(directory)
print(json.dumps(counts))
'''

def main():
    soc.guard()
    rows=fetch('siem_incidents',"id LIKE 'soc-demo-%' OR id LIKE 'soc-practice-%'")
    checked_fixtures(rows)
    ids=[row['id'] for row in rows]
    if not ids:raise RuntimeError('NO_OLD_FIXTURES_TO_RESET')
    where=selectors(ids)
    for table in ('siem_ip_blocks','siem_postlogin_decisions'):
        if soc.sql('SELECT COUNT(*) FROM '+table+' WHERE incident_id IN '+scope(ids)+';')!='0':
            raise RuntimeError('FIXTURE_HAS_NON_WORKFLOW_LINKS_REVIEW_BEFORE_DELETE')
    if soc.sql("SELECT COUNT(*) FROM siem_ueba_shadow_deliveries WHERE window_id IN (SELECT id FROM siem_account_behavior_windows "
            "WHERE account_id IN ('soc-demo-customer','soc-practice-customer'));")!='0':
        raise RuntimeError('RESEARCH_SHADOW_REFERENCE_PRESERVE')
    timestamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]
    backup=soc.STATE/('reset-'+timestamp);backup.mkdir(mode=0o700);private_directory(backup)
    # Scoped recoverable backup, outside the active scenario pointers/log display.
    states=backup/'previous-pointers';states.mkdir(mode=0o700)
    oldfiles=[p for p in soc.STATE.iterdir() if p.is_file() and (p.name.startswith(('latest-','practice-batch-','rehearsal-')) or p.name=='ready.private.json')]
    for path in oldfiles:
        if path.is_symlink():raise RuntimeError('UNSAFE_SCENARIO_POINTER')
        with (states/path.name).open('xb') as copy:
            os.chmod(copy.name,0o600);copy.write(path.read_bytes());copy.flush();os.fsync(copy.fileno())
    mount=json.loads(subprocess.check_output(['docker','inspect',APP],text=True))[0]
    if not any(v.get('Name')==VOLUME and v['Destination']=='/var/log/flare' for v in mount['Mounts']):
        raise RuntimeError('EXPECTED_LOCAL_LOG_VOLUME_REQUIRED')
    # Stop the exporter and HTTP writers before rewriting its NDJSON and database evidence.
    subprocess.run(['docker','stop','--time','30',APP],check=True,stdout=subprocess.DEVNULL,timeout=45)
    try:
        current=fetch('siem_incidents',"id LIKE 'soc-demo-%' OR id LIKE 'soc-practice-%'")
        checked_fixtures(current)
        if {r['id'] for r in current}!=set(ids):raise RuntimeError('CONCURRENT_FIXTURE_SET_CHANGED')
        snapshot={table:fetch(table,predicate) for table,predicate in where.items()}
        publish(backup/'deleted-fixtures.private.json',snapshot,maximum=32*1024**2)
        before_users=identity_digest();before_other=other_counts(ids)
        statements=[]
        demo=soc.new_case(statements=statements)
        practice=soc.new_case(practice_kind='L2',statements=statements)
        delete_order=['siem_response_actions','siem_alert_refs','siem_incident_notes','siem_incident_history',
                      'siem_incidents','siem_security_events','siem_account_behavior_windows']
        sql='START TRANSACTION;\n'+''.join('DELETE FROM `'+table+'` WHERE ('+where[table]+');\n' for table in delete_order)
        sql+='\n'.join(statements)+'\nCOMMIT;'
        soc.sql(sql)
        log_result=subprocess.run(['docker','run','--rm','--network','none','--read-only','--cpus','0.5','--memory','128m',
            '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--mount','type=volume,source='+VOLUME+',target=/logs',WORKER,'python','-c',LOG_FILTER],
            check=True,capture_output=True,text=True,timeout=45)
        logs=json.loads(log_result.stdout)
        soc.publish('latest-case.private.json',demo)
        soc.publish('latest-practice.private.json',{'status':'PRACTICE_ESCALATION_ISOLATION_READY','cases':[practice],
            'practice_customer_username':soc.PRACTICE_CUSTOMER['username'],'new_fits':0})
        for path in oldfiles:
            if path.name not in ('latest-case.private.json','latest-practice.private.json'):path.unlink()
        # User explicitly requested replacing the previous presentation cases.
        after_other=other_counts([demo['incident_id'],practice['incident_id']])
        if identity_digest()!=before_users or after_other!=before_other:raise RuntimeError('UNRELATED_STATE_CHANGED')
        for case in (demo,practice):
            value=soc.sql('SELECT status,queue_tier,COALESCE(assignee_user_id,\'\'),version FROM siem_incidents WHERE id='+soc.literal(case['incident_id'])+';')
            if value!='NEW\tL1\t\t0':raise RuntimeError('NEW_CASE_NOT_READY')
        result={'status':'DEMO_AND_PRACTICE_ESCALATION_ISOLATION_READY','demo':demo,'practice':practice,
            'removed_rows':{table:len(values) for table,values in snapshot.items()},'security_log_files':logs,
            'accounts_unchanged':True,'other_incidents_and_policy_unchanged':True,'new_fits':0,
            'recovery_backup':str(backup),'isolation':'REVOKE_CUSTOMER_SESSIONS_THEN_REQUIRE_LOGIN',
            'previous_scenarios_replaced_by_explicit_user_request':True}
        soc.publish('ready.private.json',result)
        publish(backup/'reset-result.private.json',result,maximum=64*1024)
        print(json.dumps(result,ensure_ascii=False))
    finally:
        subprocess.run(['docker','start',APP],check=True,stdout=subprocess.DEVNULL,timeout=20)

if __name__=='__main__':main()
