import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from postlogin_preparation_audit import cases,atomically_write_xz,full_population,history_witnesses
from ueba_research_artifacts import commit,digest
from app.postlogin_contract import FEATURE_NAMES,EVALUATION_UNIT

class CaptureAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        values=[0.]*65;values[37]=values[39]=1.
        snapshot=dict(snapshot_id='capture-p1-0-0',evaluation_unit=EVALUATION_UNIT,feature_schema_version=6,
            feature_names=list(FEATURE_NAMES),features=values,as_of='2026-10-21T00:00:20Z',baseline_established=False,trusted_window_count=0)
        commit(self.root,dict(status='COLD_READINESS_SMOKE_ONLY',new_fits=0,new_model_jobs=0,external_mail=False,p1_target_episodes=1,benchmark_target_episodes=0),phase='preparation-capture-result-v1')
        oracle=dict(case_id='p1-0-0',actor_role='OWNER',context_class=0,family='normal',operation='PASSWORD_CHANGE',valid_proof_planned=True,sealed_at='2026-10-21T00:00:00Z')
        commit(self.root,oracle,phase='p1-0-0-oracle')
        before=dict(case_id='p1-0-0',snapshot=snapshot,oracle_sha256=digest(self.root/'p1-0-0-oracle.receipt.private.json'),current_outcome_known=False,account_mutation_observed_at_capture=False,
            context=[],attempt=dict(actor_user_id='owned-account',session_pseudonym='a'*64,action='PASSWORD_CHANGE',event_timestamp=snapshot['as_of']))
        commit(self.root,before,phase='p1-0-0-precommit')
        commit(self.root,dict(case_id='p1-0-0',actor_role='OWNER',valid_proof=True,account_mutated=True,elapsed_seconds=.2,shared_mailbox_limit=False),phase='p1-0-0-outcome')

    def test_labels_and_actor_roles_are_separate_from_the65_numeric_values(self):
        row=cases(self.root)[0];self.assertEqual(len(row['features']),65);self.assertEqual(row['actor_role'],'OWNER');self.assertEqual(row['context_class'],0)
        path=self.root/'p1-0-0-oracle.receipt.private.json';value=json.loads(path.read_text());value['actor_role']='NONOWNER';path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'checksum'):cases(self.root)

    def test_compressed_shard_is_idempotent_and_never_replaces_different_bytes(self):
        path=self.root/'features-0000.jsonl.xz';rows=[{'features':[1,2]}]
        atomically_write_xz(path,rows);before=digest(path);atomically_write_xz(path,rows);self.assertEqual(digest(path),before)
        with self.assertRaisesRegex(ValueError,'changed'):atomically_write_xz(path,[{'features':[3,4]}])
        self.assertEqual(digest(path),before)

    def test_full_population_preserves_training_supplement_and_independent_proof_counts(self):
        population=full_population();self.assertEqual(sum(population.values()),19257500)
        self.assertEqual(sum(v for k,v in population.items() if k.endswith('/normal')),19214500)
        for family in ('request_burst','endpoint_scan','auth_failure_burst','sensitive_action_burst','http_error_burst'):
            self.assertEqual(sum(v for k,v in population.items() if k.endswith('/'+family)),8600)

    def test_resumed_history_is_bound_without_replacing_required48_waves(self):
        child=self.root/'capture-real-v1';child.mkdir(mode=0o700)
        for i in range(48):
            phase=f'warmup-window-{i}'
            commit(child,{'observed':True},phase=phase)
            commit(self.root,{'source_receipt_sha256':digest(child/(phase+'.receipt.private.json')),
                             'rows':[{'window_id_sha256':str(i),'account_id':'owned'}]},phase=phase+'-db-witness')
        phase='resume-history-20261021141500'
        commit(child,{'observed_before_stop':True},phase=phase)
        commit(self.root,{'source_receipt_sha256':digest(child/(phase+'.receipt.private.json')),
                         'rows':[{'window_id_sha256':'paused-frame','account_id':'owned'}]},phase=phase+'-db-witness')
        self.assertEqual(len(history_witnesses(self.root)),49)
        (self.root/'warmup-window-47-db-witness.commit.private.json').unlink()
        with self.assertRaises(FileNotFoundError):history_witnesses(self.root)

if __name__=='__main__':unittest.main()
