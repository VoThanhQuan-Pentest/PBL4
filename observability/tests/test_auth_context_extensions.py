import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts';sys.path.insert(0,str(SCRIPTS))
import auth_context_extensions_source as source
import auth_context_extensions_runner as runner
import auth_context_extensions_campaign as campaign


class ExtensionSourceTest(unittest.TestCase):
    def test_all_context_families_obey_split_time_and_history_boundaries(self):
        previous_end=None
        for split,anchor in source.ANCHORS.items():
            if previous_end is not None:
                self.assertGreaterEqual((anchor-previous_end).days,14)
            previous_end=anchor+source.timedelta(days=3)
            for cohort in ('READY','COLD'):
                for family in ('routine','case3','case4','case5','operational'):
                    for stratum in range(3):
                        raw,meta=source.frame(cohort,split,17+stratum,family,'browse' if family=='routine' else family,stratum)
                        attempt=source.at(raw['attempt']['event_timestamp'])
                        self.assertLessEqual(anchor,attempt);self.assertLess(attempt,previous_end)
                        self.assertTrue(all(source.at(e['event_timestamp'])<attempt for e in raw['context']))
                        start=attempt.replace(minute=0,second=0,microsecond=0)
                        self.assertTrue(all(source.at(h['window_start'])<start for h in raw['baseline_frames']))
                        self.assertEqual(meta['family'],family)
                        self.assertNotIn('context_label',raw)

    def test_namespaces_cohorts_and_current_window_history_are_coherent(self):
        identities=set()
        for cohort in ('READY','COLD'):
            for split in source.QUOTAS:
                for stratum in range(3):
                    raw,meta=source.frame(cohort,split,stratum,'routine','browser_update',stratum)
                    self.assertNotIn(meta['account_group'],identities);identities.add(meta['account_group'])
                    self.assertEqual(raw['attempt']['actor_user_id'],meta['account_group'])
                    self.assertTrue(all(e['event_timestamp']<raw['attempt']['event_timestamp'] for e in raw['context']))
                    start=source.at(raw['attempt']['event_timestamp']).replace(minute=0,second=0,microsecond=0)
                    self.assertTrue(all(source.at(e['event_timestamp'])>=start for e in raw['context'] if e['event_type']=='HTTP_REQUEST'))
                    count=len(raw['baseline_frames'])
                    self.assertTrue(count>=30 if cohort=='READY' else count==0 if stratum==0 else 1<=count<=9 if stratum==1 else 10<=count<=29)
                    for history in raw['baseline_frames']:
                        self.assertEqual(history['account_id'],meta['account_group'])
                        self.assertLess(source.at(history['window_start']),start)
                        self.assertTrue(all(source.at(e['event_timestamp'])<start for e in history['events']))
                    self.assertNotIn('context_label',raw)

    def test_smoke_and_corpus_identities_are_distinct(self):
        _,a=source.frame('COLD','train',0,'routine','browse',0,False)
        _,b=source.frame('COLD','train',0,'routine','browse',0,True)
        self.assertNotEqual(a['episode_id'],b['episode_id']);self.assertNotEqual(a['account_group'],b['account_group'])

    def test_protocol_wire_round_trip_and_fit_budget(self):
        with patch.object(source.legacy,'classpath_fingerprint',return_value=[]):p=source.protocol('COLD','unused')
        self.assertTrue(source.legacy.same_protocol(p,json.loads(json.dumps(p))))
        self.assertEqual(p['model_width'],42);self.assertEqual(p['classifier_total_cap'],8)
        self.assertEqual(p['cold_false_positive_cap'],0);self.assertFalse(p['smoke_only'])
        for cohort in ('READY','COLD'):
            for split,n in source.QUOTAS.items():
                self.assertEqual(len(source.entries(cohort,split)),sum(n))


class ExtensionMountTest(unittest.TestCase):
    def test_campaign_windows_are_registered_and_smoke_never_fits(self):
        job=Path('/private/job')
        smoke=campaign.commands('smoke',job)
        self.assertEqual(len(smoke),9)
        self.assertFalse(any('select' in args or 'evaluate' in args for _,args in smoke))
        for cohort in ('ready','cold'):
            self.assertEqual([name for name,_ in campaign.commands(cohort,job)],
                             [s+'-'+cohort for s in ('capture','parity','select','evaluate')])
        self.assertEqual(campaign.process_identity(__import__('os').getpid()),
                         campaign.process_identity(__import__('os').getpid()))
        self.assertEqual([name for name,_ in campaign.commands('cold-resume',job)],
                         ['parity-cold','select-cold','evaluate-cold'])

    def test_stage_readmission_only_stops_remaining_elk(self):
        with tempfile.TemporaryDirectory() as folder:
            window=Path(folder);before={'id':'original','image':'pinned'}
            state={'stopped':list(campaign.ELK[:2]),'elk_before':{n:before for n in campaign.ELK}}
            with patch.object(campaign.base,'available_memory',return_value=0), \
                 patch.object(campaign,'inspect',return_value={'Id':'original','Image':'pinned'}), \
                 patch.object(campaign.subprocess,'run') as run, \
                 patch.object(campaign.time,'sleep'),patch.object(campaign.base,'resource_check') as guard:
                campaign.admit_window(Path('/private/job'),window,state)
                run.assert_called_once_with(['docker','stop','--time','30',campaign.ELK[2]],
                    check=True,timeout=45,stdout=campaign.subprocess.DEVNULL)
                guard.assert_called_once_with(Path('/private/job'),admission=True)
                self.assertEqual(state['stopped'],list(campaign.ELK))

    def test_resume_refuses_to_replay_an_attempted_cold_fit(self):
        with tempfile.TemporaryDirectory() as folder:
            job=Path(folder);(job/'corpus-cold').mkdir();(job/'ledger').mkdir()
            (job/'corpus-cold/manifest.json').write_text(json.dumps({'status':'SOURCE_CAPTURE_COMPLETE','records':100000}))
            (job/'ledger/classifier-COLD-A-42.json').write_text('{}')
            with patch.object(campaign,'inspect') as inspect:
                with self.assertRaises(RuntimeError):campaign.run_window(job,'cold-resume')
                inspect.assert_not_called()

    def test_http_review_barrier_prevents_a_queued_window(self):
        import io
        with tempfile.TemporaryDirectory() as folder:
            job=Path(folder);(job/'http-review-barrier.json').write_text('{}')
            with patch.object(campaign.base,'safe_path',return_value=job), \
                 patch.object(sys,'argv',['campaign','http','--job',str(job),'--allow-elk-maintenance']), \
                 patch.object(sys,'stderr',io.StringIO()),patch.object(campaign,'run_window') as run:
                with self.assertRaises(SystemExit) as error:campaign.main()
                self.assertEqual(error.exception.code,2);run.assert_not_called()

    def test_recovery_never_targets_an_unrelated_container(self):
        values=[{'Id':'owned','Name':'/auth-research-abc','Mounts':[{'Type':'bind','Source':'/private/job/classpath'}]},
                {'Id':'other','Name':'/auth-research-def','Mounts':[{'Type':'bind','Source':'/private/other'}]},
                {'Id':'app','Name':'/flare-otp-local-app-1','Mounts':[{'Type':'bind','Source':'/private/job'}]}]
        with patch.object(campaign.subprocess,'check_output',side_effect=[b'owned other app',json.dumps(values).encode()]):
            self.assertEqual(campaign.owned_containers(Path('/private/job')),['owned'])

    def test_watchdog_recovers_after_parent_disappears(self):
        with tempfile.TemporaryDirectory() as folder:
            window=Path(folder);(window/'maintenance.json').write_text(json.dumps({'deadline':10**20}))
            with patch.object(campaign,'process_identity',return_value=None), patch.object(campaign,'recover') as recovery:
                campaign.watchdog(Path('/private/job'),window,123,'old-start-ticks')
                recovery.assert_called_once_with(Path('/private/job'),window)

    def test_checkpoint_write_is_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'checkpoint.json'
            campaign.atomic(path,{'phase':'before'});campaign.atomic(path,{'phase':'after'})
            self.assertEqual(json.loads(path.read_bytes()),{'phase':'after'})
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(list(Path(folder).glob('*.partial-*')),[])

    def test_selection_and_evaluation_split_mounts_do_not_overlap(self):
        with tempfile.TemporaryDirectory() as folder:
            job=Path(folder);data=job/'corpus-ready';data.mkdir()
            for name in runner.base.METADATA+tuple(x+'.jsonl.gz' for x in source.QUOTAS):(data/name).write_bytes(b'fixture')
            for stage in ('select','evaluate'):
                args=runner.command(stage,'READY',job)
                mounts=' '.join(args)
                self.assertIn('--network none',mounts);self.assertIn('--memory 2g',mounts)
                if stage=='select':
                    self.assertIn('train.jsonl.gz',mounts);self.assertNotIn('evaluation.jsonl.gz',mounts)
                    self.assertNotIn('controls.jsonl.gz',mounts)
                else:
                    self.assertIn('evaluation.jsonl.gz',mounts);self.assertNotIn('train.jsonl.gz',mounts)
                    self.assertNotIn('development.jsonl.gz',mounts)
                self.assertIn('dst=/run/model,readonly',mounts)
                self.assertIn('dst=/reference,readonly',mounts)


if __name__=='__main__':unittest.main()
