#!/usr/bin/env python3
"""After the one-hour gate, verify customer containment on the existing practice account.

Never resets passwords/email/OTP or touches lecturer/demo accounts. The expected
practice auth_version increment is retained so old tokens can never be restored.
"""
from datetime import datetime,timedelta,timezone
import importlib.util
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import uuid

ROOT=Path(__file__).resolve().parents[2]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

live=load('account_live','observability/scripts/siem-live-acceptance.py')
control=load('account_control','observability/scripts/siem-cutover-local.py')
ops=control.ops
FOLDER=ops.ROOT/'observability/runtime/private-backups/siem-upgrade-20261023-r1'
TARGET='soc-practice-customer'

def snapshot():
    raw=ops.sql("""SELECT id,SHA2(CAST(JSON_OBJECT('password',password,'email',email,'email_verified_at',email_verified_at,
      'role',role,'deleted',is_deleted) AS CHAR),256),auth_version FROM tbl_nguoi_dung ORDER BY id;""").decode().strip().splitlines()
    return {row.split('\t')[0]:{'credential_sha256':row.split('\t')[1],'auth_version':int(row.split('\t')[2])} for row in raw}

def save(path,value):
    temporary=path.with_suffix('.partial')
    with temporary.open('w') as output:json.dump(value,output);output.flush();os.fsync(output.fileno())
    temporary.replace(path);path.chmod(0o600)

def transition(c,id,action,reason=None,conclusion=None):
    incident=c.request('GET','/api/siem/incidents/'+id)['incident'];body={'expected_version':incident['version'],'action':action}
    if reason:body['reason']=reason
    if conclusion:body['conclusion']=conclusion
    return c.request('POST','/api/siem/incidents/'+id+'/transitions',body)

def main():
    gates=[json.loads(path.read_text()) for path in FOLDER.glob('operational-gate-*.receipt.private.json')]
    assert any(g.get('status')=='SIEM_ONE_HOUR_HTTP_GATE_PASS' and g.get('continuous_seconds',0)>=3600 and g.get('evaluations',0)>=30 and g.get('new_fits')==0 for g in gates),'CONTINUOUS_GATE_REQUIRED'
    state_path=FOLDER/'account-practice.checkpoint.private.json'
    if state_path.exists():raise RuntimeError('Account practice checkpoint already exists; reconcile before replay')
    before=snapshot();assert TARGET in before
    assert ops.sql("SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id='soc-practice-customer' AND password LIKE '{bcrypt-sha256}%' AND is_deleted=0;").decode().strip()=='1'
    save(FOLDER/'account-practice-before.private.json',before)
    demo=load('account_practice_demo','observability/scripts/local-soc-demo.py');demo.ORIGIN='http://127.0.0.1:8088'
    customer=demo.client();old=demo.client();fresh=demo.client();l1=live.client('l1');l2=live.client('l2');id=None;action=None;released=False
    try:
        response=old.login(demo.PRACTICE_CUSTOMER);assert response['user']['id']==TARGET
        assert old.request('GET','/api/auth/me')['id']==TARGET
        now=datetime.now(timezone.utc);hit=None;begin=time.monotonic()
        while time.monotonic()-begin<60:
            root=live.es('POST','/logs-flare.security-lab/_search',{'size':1,'sort':[{'@timestamp':{'order':'desc'}}],'query':{'bool':{'filter':[{'term':{'user.id':TARGET}},{'term':{'event.action':'LOGIN'}},{'term':{'event.outcome':'SUCCESS'}},{'range':{'@timestamp':{'gte':(now-timedelta(seconds=5)).isoformat()}}}]}}})
            if root['hits']['hits']:hit=root['hits']['hits'][0];break
            time.sleep(2)
        assert hit,'PRACTICE_LOGIN_LOG_NOT_FOUND'
        incident=l1.request('POST','/api/siem/incidents',{'title':'SOC-PRACTICE account isolation and recovery '+uuid.uuid4().hex[:8],'events':[{'index':hit['_index'],'id':hit['_id']}]});id=incident['id'];assert incident['target_user_id']==TARGET
        save(state_path,{'status':'CASE_CREATED','incident_id':id,'target':TARGET})
        transition(l1,id,'CLAIM');transition(l1,id,'ESCALATE','SOC-PRACTICE controlled customer containment; no real compromise.');incident=transition(l2,id,'CLAIM')
        request={'request_id':str(uuid.uuid4()),'expected_version':incident['version'],'reason':'SOC-PRACTICE customer isolation until release; verify old sessions never return.','duration':'UNTIL_REVOKED'}
        try:l1.request('POST','/api/siem/incidents/'+id+'/containment-actions',request);raise AssertionError('L1 customer containment accepted')
        except urllib.error.HTTPError as error:assert error.code==403
        action=l2.request('POST','/api/siem/incidents/'+id+'/containment-actions',request)
        assert action['target_user_id']==TARGET and action['status']=='APPLIED' and action['expires_at'] is None
        duplicate=l2.request('POST','/api/siem/incidents/'+id+'/containment-actions',request);assert duplicate['id']==action['id']
        assert snapshot()[TARGET]['auth_version']==before[TARGET]['auth_version']+1
        save(state_path,{'status':'ISOLATED','incident_id':id,'action_id':action['id'],'target':TARGET})
        try:old.request('GET','/api/auth/me');raise AssertionError('Old customer token survived isolation')
        except urllib.error.HTTPError as error:assert error.code==401
        failure_at=datetime.now(timezone.utc)
        try:customer.login(demo.PRACTICE_CUSTOMER);raise AssertionError('Isolated customer logged in')
        except urllib.error.HTTPError as error:assert error.code==401
        failure_seen=False;begin=time.monotonic()
        while time.monotonic()-begin<60:
            events=live.es('POST','/logs-flare.security-lab/_search',{'size':5,'query':{'bool':{'filter':[{'term':{'target.user.id':TARGET}},{'term':{'event.action':'LOGIN'}},{'term':{'event.outcome':'FAILURE'}},{'range':{'@timestamp':{'gte':(failure_at-timedelta(seconds=2)).isoformat()}}}]}}})['hits']['hits']
            if events:
                for item in events:assert not item['_source'].get('user',{}).get('name') and not item['_source'].get('user',{}).get('id')
                failure_seen=True;break
            time.sleep(2)
        assert failure_seen,'Failed login was not observed separately from an authenticated actor'
        release={'request_id':str(uuid.uuid4()),'expected_version':action['version'],'reason':'SOC-PRACTICE recovery checks passed; allow new logins without restoring old tokens.'}
        value=l2.request('POST','/api/siem/containment-actions/'+action['id']+'/release',release);assert value['status']=='RELEASED';released=True
        assert l2.request('POST','/api/siem/containment-actions/'+action['id']+'/release',release)['id']==action['id']
        assert fresh.login(demo.PRACTICE_CUSTOMER)['user']['id']==TARGET
        assert fresh.request('GET','/api/auth/me')['id']==TARGET
        try:old.request('GET','/api/auth/me');raise AssertionError('Release restored an old token')
        except urllib.error.HTTPError as error:assert error.code==401
        incident=l2.request('GET','/api/siem/incidents/'+id)['incident']
        l2.request('POST','/api/siem/incidents/'+id+'/response-checks',{'request_id':str(uuid.uuid4()),'expected_version':incident['version'],'reason':'SOC-PRACTICE PASSED: sessions revoked, login blocked during isolation, fresh login succeeds after release, old token stays invalid.','response_result':'PASSED','recovery_result':'PASSED'})
        incident=transition(l2,id,'CLOSE','SOC-PRACTICE controlled customer isolation/release completed; no actual account compromise.','BENIGN_ACTIVITY');assert incident['status']=='CLOSED'
        after=snapshot();assert before.keys()==after.keys()
        for user_id,value in before.items():
            assert value['credential_sha256']==after[user_id]['credential_sha256'],'CREDENTIAL_OR_PROFILE_CHANGED'
            assert after[user_id]['auth_version']==value['auth_version']+(1 if user_id==TARGET else 0),'UNEXPECTED_SESSION_VERSION_CHANGE'
        assert ops.sql("SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id='soc-practice-customer' AND soc_isolated=0 AND soc_isolated_until IS NULL;").decode().strip()=='1'
        save(state_path,{'status':'PRACTICE_RELEASED_AND_CLOSED','incident_id':id,'action_id':action['id'],'target':TARGET,'expected_auth_version_increment':1})
        live.publish('live-customer-containment-contract.json',{'status':'LIVE_CUSTOMER_ISOLATION_RELEASE_AND_RECOVERY_PASS','incident_id':id,'scope':'Existing SOC-PRACTICE customer only','duration_type':'UNTIL_REVOKED','expires_at':None,'idempotent_create_and_release':True,'l1_response_forbidden':True,'old_token_revoked_and_not_restored':True,'new_login_blocked_until_release':True,'failed_login_has_no_authenticated_actor':True,'fresh_login_after_release':True,'password_email_otp_and_all_other_accounts_unchanged':True,'practice_auth_version_increment':1,'practice_account_left_released':True,'practice_case_closed_benign':True})
    finally:
        if id is not None and not released:
            try:
                for pending in l2.request('GET','/api/siem/incidents/'+id+'/containment-actions'):
                    if pending['status']=='APPLIED':
                        l2.request('POST','/api/siem/containment-actions/'+pending['id']+'/release',{'request_id':str(uuid.uuid4()),'expected_version':pending['version'],'reason':'SOC-PRACTICE safety recovery: release controlled account after interrupted verification.'})
            except Exception:pass
        for c in [old,customer,fresh,l1,l2]:
            try:c.request('POST','/api/auth/logout',{})
            except Exception:pass

if __name__=='__main__':main()
