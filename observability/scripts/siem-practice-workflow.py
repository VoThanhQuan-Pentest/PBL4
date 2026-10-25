#!/usr/bin/env python3
"""Exercise new SOC workflow with a new SOC-PRACTICE case and real ELK references.

Does not claim/change reserved demo cases or customer accounts. The observed SOC
principal is deliberately used as a protected containment target and must be refused.
"""
import importlib.util
import json
from pathlib import Path
import urllib.error
import uuid

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('live_acceptance',ROOT/'observability/scripts/siem-live-acceptance.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def main():
    l1=m.client('l1');l2=m.client('l2')
    try:
        events=m.es('POST','/logs-flare.security-lab/_search',{'size':1,'sort':[{'@timestamp':{'order':'desc'}}],'query':{'bool':{'filter':[{'term':{'user.id':'soc-demo-l1'}},{'term':{'event.outcome':'SUCCESS'}},{'range':{'@timestamp':{'gte':'now-2h'}}}]}}})['hits']['hits']
        assert events
        ref={'index':events[0]['_index'],'id':events[0]['_id']}
        incident=l1.request('POST','/api/siem/incidents',{'title':'SOC-PRACTICE protected-target and evidence workflow '+uuid.uuid4().hex[:8],'events':[ref]})
        id=incident['id'];assert incident['origin']=='MANUAL' and incident['target_user_id']=='soc-demo-l1'
        evidence=m.get_exact(l1,'/api/siem/incidents/'+id+'/evidence')
        assert len(evidence['content'])==1 and evidence['content'][0]['association']['match_type']=='DIRECT'
        assert evidence['content'][0]['elk_hit']['_source']==events[0]['_source']
        def transition(c,action,reason=None,conclusion=None,current=None):
            value=current or c.request('GET','/api/siem/incidents/'+id)['incident']
            body={'expected_version':value['version'],'action':action}
            if reason:body['reason']=reason
            if conclusion:body['conclusion']=conclusion
            return c.request('POST','/api/siem/incidents/'+id+'/transitions',body)
        initial=incident['version'];incident=transition(l1,'CLAIM')
        try:l1.request('POST','/api/siem/incidents/'+id+'/transitions',{'expected_version':initial,'action':'ESCALATE','reason':'SOC-PRACTICE stale version must be refused.'});raise AssertionError('Stale transition accepted')
        except urllib.error.HTTPError as error:assert error.code==409
        l1.request('POST','/api/siem/incidents/'+id+'/notes',{'content':'SOC-PRACTICE: real server-authored SOC login log; intentional protected-role containment rejection test, not evidence of compromise.'})
        incident=transition(l1,'ESCALATE','SOC-PRACTICE L2 authorization and raw-event linkage verification.')
        incident=transition(l2,'CLAIM')
        try:l2.request('POST','/api/siem/incidents/'+id+'/containment-actions',{'request_id':str(uuid.uuid4()),'expected_version':incident['version'],'reason':'SOC-PRACTICE protected SOC target must never be isolated.','duration':'15_MINUTES'});raise AssertionError('Protected SOC target isolated')
        except urllib.error.HTTPError as error:assert error.code==403
        assert l1.request('GET','/api/siem/incidents/'+id+'/containment-actions')==[]
        incident=transition(l2,'RETURN_TO_L1','SOC-PRACTICE L2 return path verified; continue benign workflow exercise.')
        incident=transition(l1,'CLAIM')
        incident=transition(l1,'ESCALATE','SOC-PRACTICE re-escalation after L2 return.')
        incident=transition(l2,'CLAIM')
        try:transition(l2,'CLOSE','SOC-PRACTICE must verify response/recovery before confirmed closure.','TRUE_POSITIVE',incident);raise AssertionError('Unverified confirmed closure accepted')
        except urllib.error.HTTPError as error:assert error.code==409
        l2.request('POST','/api/siem/incidents/'+id+'/response-checks',{'request_id':str(uuid.uuid4()),'expected_version':incident['version'],'reason':'Controlled SOC-PRACTICE: protected target refusal passed; no customer response or recovery required.','response_result':'NOT_REQUIRED','recovery_result':'NOT_REQUIRED'})
        incident=transition(l2,'CLOSE','SOC-PRACTICE complete: ordinary SOC login, protected target refused, no account compromise.','BENIGN_ACTIVITY')
        assert incident['status']=='CLOSED' and incident['conclusion']=='BENIGN_ACTIVITY'
        detail=l1.request('GET','/api/siem/incidents/'+id)
        assert any('SOC-PRACTICE' in note['content'] for note in detail['notes'])
        history=l1.request('GET','/api/siem/incidents/'+id+'/history');actions={v['action'] for v in history}
        assert {'CLAIM','ESCALATE','RETURN_TO_L1','CLOSE','RESPONSE_RECOVERY_VERIFIED'}.issubset(actions)
        m.publish('live-soc-workflow-contract.json',{'status':'LIVE_L1_L2_EVIDENCE_WORKFLOW_PASS','incident_id':id,'scope':'New SOC-PRACTICE manual case only; benign role-protection exercise','manual_case_from_verified_elk_reference':True,'direct_native_source_equal':True,'stale_version_rejected':True,'l1_escalation_and_l2_return_verified':True,'soc_account_isolation_rejected':True,'confirmed_close_requires_checks':True,'notes_and_history_retained':True,'reserved_demo_cases_modified':False,'customer_accounts_modified':False})
    finally:
        for connection in (l1,l2):
            try:connection.request('POST','/api/auth/logout',{})
            except Exception:pass

if __name__=='__main__':main()
