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
