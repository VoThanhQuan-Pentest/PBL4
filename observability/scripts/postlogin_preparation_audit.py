"""Read verified real lab captures; emit measurement-only shards, never training input."""
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import lzma
import math
from pathlib import Path
import re
import shutil
import os
import tempfile

from ueba_research_artifacts import private_directory, digest, commit, canonical


def checked(root, phase):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,100}',phase):raise ValueError('bounded artifact phase required')
    path=root/(phase+'.receipt.private.json');marker=root/(phase+'.commit.private.json')
    if path.is_symlink() or marker.is_symlink():raise ValueError('no symlink evidence')
    if path.stat().st_size>4*1024*1024 or marker.stat().st_size>8192:raise ValueError('bounded evidence bytes required')
    proof=json.loads(marker.read_text())
    if proof['receipt']!=path.name or proof['receipt_sha256']!=digest(path):raise ValueError('capture checksum changed')
    return json.loads(path.read_text())


def instant(value):
    at=datetime.fromisoformat(value.replace('Z','+00:00'))
    if at.utcoffset() is None or at.utcoffset().total_seconds()!=0:raise ValueError('UTC observations required')
    return at


def verify_pipeline(root):
    protocol=checked(root,'preparation-pipeline-protocol-v5')
    if protocol['new_fit_cap']!=0 or protocol['quota_policy']!='NOT_USED':
        raise ValueError('explicit zero-fit preparation protocol required')
    repo=Path(__file__).resolve().parents[2]
    for name,expected in protocol['code_sha256'].items():
        if digest(repo/name)!=expected:raise ValueError('PREPARATION_PIPELINE_CHANGED_AFTER_FREEZE: '+name)
    return protocol


def cases(child):
    from app.postlogin_contract import validate_snapshot
    child=private_directory(child)
    result=checked(child,'preparation-capture-result-v1')
    if result.get('status') not in ('COLD_READINESS_SMOKE_ONLY','REAL_TIME_PREPARATION_CAPTURE_COMPLETE'):
        raise ValueError('completed real capture result required')
    if result['new_fits'] or result['new_model_jobs'] or result['external_mail']:raise ValueError('completed zero-fit local capture required')
    rows=[]
    for marker in sorted(child.glob('*-precommit.commit.private.json')):
        phase=marker.name.removesuffix('-precommit.commit.private.json')
        before=checked(child,phase+'-precommit');oracle=checked(child,phase+'-oracle');outcome=checked(child,phase+'-outcome')
        snapshot=before['snapshot'];values=validate_snapshot(snapshot)
        if (before['case_id']!=phase or outcome['case_id']!=phase or oracle['case_id']!=phase
                or before['oracle_sha256']!=digest(child/(phase+'-oracle.receipt.private.json'))
                or before['current_outcome_known'] is not False or before['account_mutation_observed_at_capture'] is not False
                or instant(oracle['sealed_at'])>=instant(snapshot['as_of'])):raise ValueError('presealed oracle/precommit binding failed')
        role=oracle['actor_role'];label=oracle['context_class']
        if role not in ('OWNER','NONOWNER') or type(label) is not int or label not in (0,1,2):raise ValueError('independent context and role fields required')
        if outcome['actor_role']!=role or outcome['valid_proof']!=oracle['valid_proof_planned'] or outcome['account_mutated']!=outcome['valid_proof']:
            raise ValueError('operation outcome differs from proof control')
        if before['attempt'].get('action')!=oracle['operation'] or before['attempt'].get('event_timestamp')!=snapshot['as_of']:
            raise ValueError('operation/time differs from real attempt')
        if not isinstance(outcome['elapsed_seconds'],(int,float)) or not math.isfinite(outcome['elapsed_seconds']) or outcome['elapsed_seconds']<0:
            raise ValueError('finite measured operation timing required')
        if any(instant(e['event_timestamp'])>=instant(snapshot['as_of']) for e in before['context']):raise ValueError('current outcome leaked into context')
        rows.append({'case_id':phase,'snapshot_id':snapshot['snapshot_id'],'features':list(values),
            'context_class':label,'actor_role':role,'family':oracle['family'],'operation':oracle['operation'],
            'as_of':snapshot['as_of'],'baseline_established':snapshot['baseline_established'],
            'trusted_window_count':snapshot['trusted_window_count'],'account_id':before['attempt']['actor_user_id'],
            'session_pseudonym':before['attempt']['session_pseudonym'],'elapsed_seconds':outcome['elapsed_seconds'],
            'shared_mailbox_limit':outcome['shared_mailbox_limit'],'account_mutated':outcome['account_mutated'],
            'precommit_sha256':digest(child/(phase+'-precommit.receipt.private.json'))})
    if len(rows)!=result['p1_target_episodes']+result['benchmark_target_episodes']:raise ValueError('exact capture count required')
    return rows


def atomically_write_xz(path, rows):
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.shard-')
    try:
        with os.fdopen(fd,'wb') as stream:
            with lzma.LZMAFile(stream,'wb',preset=3) as encoded:
                for row in rows:encoded.write((canonical(row)+'\n').encode())
            stream.flush();os.fsync(stream.fileno())
        if path.exists():
            if digest(tmp)!=digest(path):raise ValueError('immutable benchmark shard changed')
        else:os.replace(tmp,path)
        directory_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def full_population():
    normal={'READY':12250150,'UNSEEN_READY':2642900,'COLD':4321450}
    values={cohort+'/normal':n for cohort,n in normal.items()}
    for family in ('request_burst','endpoint_scan','auth_failure_burst','sensitive_action_burst','http_error_burst'):
        for cohort,n in {'READY':6020,'UNSEEN_READY':1720,'COLD':860}.items():values[cohort+'/'+family]=n
    assert sum(values.values())==19257500
    return values


def history_witnesses(root):
    witnesses={}
    phases=[f'warmup-window-{i}-db-witness' for i in range(48)]
    phases += [p.name.removesuffix('.commit.private.json') for p in sorted(root.glob('resume-history-*-db-witness.commit.private.json'))]
    for phase in phases:
        witness=checked(root,phase)
        source=root/'capture-real-v1'/(phase.removesuffix('-db-witness')+'.receipt.private.json')
        if witness['source_receipt_sha256']!=digest(source):
            raise ValueError('warmup source differs from persisted DB witness')
        for row in witness['rows']:
            identity=row['window_id_sha256']
            if identity in witnesses and witnesses[identity]!=row:
                raise ValueError('conflicting persisted history identity')
            witnesses[identity]=row
    return witnesses


def summarize(root):
    from app.postlogin_contract import source_protocol
    verify_pipeline(root)
    smoke=cases(root/'capture-smoke-v2');real=cases(root/'capture-real-v1')
    if len(smoke)!=6:raise ValueError('three committed smoke pairs required')
    benchmark=[r for r in real if r['case_id'].startswith('benchmark-')]
    p1=[r for r in smoke+real if r['case_id'].startswith('p1-')]
    if len(benchmark)!=360 or len(p1)!=24:raise ValueError('exact360benchmark and12P1pairs required')
    plan=checked(root,'benchmark-coverage-plan-v1');banks={a:c for c,accounts in plan['banks'].items() for a in accounts}
    witnesses=history_witnesses(root)
    totals=Counter();timings=defaultdict(list);coverage=[];features=defaultdict(set)
    for row in benchmark:
        cohort=banks[row['account_id']]
        if row['baseline_established']!=(cohort!='COLD'):raise ValueError('declared cohort differs from observed history')
        if instant(row['as_of'])<=instant(plan['sealed_at']):raise ValueError('benchmark bank declaration came after source')
        row['cohort']=cohort;key=cohort+'/'+row['family'];totals[key]+=1;timings[key].append(row['elapsed_seconds'])
        before=checked(root/'capture-real-v1',row['case_id']+'-precommit')
        start=instant(row['as_of']).replace(minute=instant(row['as_of']).minute//15*15,second=0,microsecond=0)
        for identity in before['history_window_ids']:
            history=witnesses.get(identity)
            if not history or history['account_id']!=row['account_id'] or instant(history['window_end'])>start:
                raise ValueError('UNVERIFIED_OR_FUTURE_HISTORY_REFERENCE')
        features[tuple(row['features'])].add(row['context_class'])
        v=row['features'];family=row['family']
        # Verify requested activity actually reached the server. These checks do
        # not generate labels or silently remove inconvenient samples.
        if (family=='request_burst' and v[57]<150 or family=='endpoint_scan' and v[58]<7
                or family=='auth_failure_burst' and v[61]<8 or family=='sensitive_action_burst' and v[62]<5
                or family=='http_error_burst' and v[60]<50):coverage.append(row['case_id'])
    expected=set(full_population())
    if set(totals)!=expected or any(n!=20 for n in totals.values()):raise ValueError('full representative18strata required')
    mixed=sum(len(v)>1 for v in features.values())
    target=root/'benchmark-shards-v1';target.mkdir(mode=0o700,exist_ok=True);private_directory(target)
    inventory=[]
    for i in range(0,len(benchmark),32):
        batch=benchmark[i:i+32];path=target/f'features-{i//32:04d}.jsonl.xz'
        numeric=[{'snapshot_id':r['snapshot_id'],'features':r['features']} for r in batch]
        atomically_write_xz(path,numeric)
        labels=target/f'labels-{i//32:04d}.jsonl.xz';atomically_write_xz(labels,[{k:v for k,v in r.items() if k!='features'} for r in batch])
        inventory.append({'features':path.name,'features_sha256':digest(path),'labels':labels.name,'labels_sha256':digest(labels),'rows':len(batch)})
    mean={k:sum(v)/len(v) for k,v in timings.items()}
    projection=sum(full_population()[k]*mean[k] for k in mean)*1.5
    numeric_upper=19257500*65*8
    report={'status':'ZERO_FIT_PREPARATION_MEASUREMENTS_COMPLETE' if not coverage and not mixed else 'SOURCE_REQUIRES_CORRECTION_BEFORE_TRAINING',
        'benchmark_rows':360,'p1_pairs':12,'strata_counts':dict(totals),'mean_capture_seconds_per_stratum':mean,
        'capture_projection_seconds_50_percent_margin':projection,'projection_includes_throttle_waits':True,
        'projection_excludes_full_scale_history_collection_and_model_fits':True,
        'raw_capture_coverage_issues':coverage,'mixed_context_vectors':mixed,
        'shared_mailbox_controls_that_committed':sum(r['shared_mailbox_limit'] and r['account_mutated'] for r in p1+benchmark),
        'schema6_uncompressed_numeric_only_bytes':numeric_upper,'full_storage_admitted':False,
        'full_storage_reason':'Need measured full-retention bound including unique raw events, history, models, scores, temporary files and5GBreserve;360row compression is not a strict upper bound.',
        'current_ssd_free_bytes':shutil.disk_usage(root).free,'shards':inventory,
        'strict_protocol':source_protocol('postlogin-lab-strict-v2-20261021'),
        'new_fits':0,'training_admitted':False,'campaign_approval':'REQUIRED_AFTER_MEASUREMENTS','source_class':'CONTROLLED_REAL_TIME_LAB',
        'benchmark_use':'MEASUREMENT_ONLY_NEVER_FIT_VALIDATION_OR_HOLDOUT','quota_policy':'NOT_USED',
        'auto_containment':False,'holdout_scored':False,'aws_changed':False}
    recovery=root/'partial-case-reconciliation-v1.commit.private.json'
    if recovery.exists():
        evidence=checked(root,'partial-case-reconciliation-v1')
        report['capture_interruption']={
            'kind':'OWNED_LAB_MYSQL_OOM','case_id':evidence['case_id'],
            'reconciliation_receipt_sha256':digest(root/'partial-case-reconciliation-v1.receipt.private.json'),
            'mysql_memory_bytes_after':evidence['mysql_memory_bytes_after'],
            'case_elapsed_includes_failed_context_and_recovery_wait':True,
            'same_presealed_oracle_retained':True,'failed_source_evidence_retained':True}
    commit(root,report,phase='measured-preparation-result-v1')
    budget=json.loads((root/'budget.private.json').read_text())
    proposal={'status':'PROPOSAL_ONLY_NOT_AUTHORIZED',
        'measurements_receipt_sha256':digest(root/'measured-preparation-result-v1.receipt.private.json'),
        'scope':'CONTROLLED_REAL_TIME_LAB_CONTEXT_ML_AND_SEPARATELY_VERIFIED_OTP',
        'additional_pilot_composite_cap':7,'additional_pilot_component_cap':14,
        'additional_strict_composite_cap':360,'additional_strict_component_cap':720,
        'first_strict_fit_included_in360':True,'preparation_new_fits':0,
        'capturing_projection_seconds_with50percent_margin':projection,
        'original_calendar_collection_seconds':99*86400,'minimum_shadow_seconds':86400,
        'strict_fit_calibration_publication_unit_cap_seconds':900,
        'fit_unit_caps_are_limits_not_measured_fit_estimates':True,
        'parent_committed_job_seconds_at_proposal':budget['elapsed_seconds'],
        'storage_admitted':False,'source_quality_screen_pass':not coverage and not mixed,
        'remaining_admission_requirements':['Verify full-retention SSD/raw/history/model/score storage bound; USB30GB alone not assumed sufficient.',
            'Validate measured producer capacity against each fixed collection window.',
            'Bind final source layout,strict runner,input fingerprints and total job/time caps before T0.',
            'Explicit single campaign approval binding all phases and contingencies.'],
        'never_reuse_benchmark_as_fit_validation_or_holdout':True,'quota_policy':'NOT_USED',
        'auto_containment':False,'holdout_scored':False,'aws_changed':False}
    commit(root,proposal,phase='campaign-budget-proposal-v1')
    return report
