import asyncio
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from fastapi import HTTPException

from app import auth_extensions_core as core
from app.auth_shadow_contract import FEATURE_NAMES
from app.auth_extensions_diagnostics import DriftReference,StreamingDrift,diagnostics,calibration_metrics,BoundedMonitor
from app.auth_extensions_http import BatchService,Circuit,ModelRegistry
from app.auth_extensions_research import cold_gate


def packet(identity='test-snapshot-0001',cohort='READY'):
    values=[0.]*81;values[37]=1;values[39]=1;values[40]=1
    return {'snapshot_id':identity,'evaluation_unit':'SENSITIVE_ACTION_ATTEMPT','feature_schema_version':7,
            'feature_names':list(FEATURE_NAMES),'features':values,'as_of':'2026-01-01T00:00:00Z',
            'baseline_established':cohort=='READY','trusted_window_count':30 if cohort=='READY' else 0,
            'coverage':{'auth_source_window':True,'session_context':True,'otp_history':True}}


def cold_state():
    leaf=lambda value:{'leaf':True,'value':value,'feature':0,'threshold':0.,'left':0,'right':0}
    return {'format':core.COLD_FORMAT,'features':42,'feature_names':list(core.COLD_NAMES),
            'recipe':dict(core.RECIPES[0]),'seed':42,'intercept':[0.,0.,0.],
            'trees':[[[leaf(.01)],[leaf(0.)],[leaf(0.)]] for _ in range(100)]}


class CoreTest(unittest.TestCase):
    def test_cohort_projection_and_observed_masks(self):
        value=packet(cohort='COLD');value['features'][65]=7
        result=core.project(value,'COLD')
        self.assertEqual(result.shape,(42,));self.assertEqual(result[26],7)
        self.assertEqual(result[0],1)
        with self.assertRaises(ValueError):core.project(value,'READY')
        invalid=deepcopy(value);invalid['coverage']['otp_history']=False
        with self.assertRaises(ValueError):core.project(invalid,'COLD')
        invalid=deepcopy(value);invalid['features'][0]=float('nan')
        with self.assertRaises(ValueError):core.project(invalid,'COLD')

    def test_cold_codec_is_numeric_bounded_and_not_ready_padding(self):
        state=core.validate_state(cold_state());out=core.logits(state,np.zeros((2,42)))
        np.testing.assert_allclose(out[:,0],[1.,1.])
        with self.assertRaises(ValueError):core.logits(state,np.zeros((2,81)))
        bad=deepcopy(state);bad['trees'][0][0][0]['feature']=42
        with self.assertRaises(ValueError):core.validate_state(bad)
        bad=deepcopy(state);bad['trees'][0][0][0].update(leaf=False,left=0,right=0)
        with self.assertRaises(ValueError):core.validate_state(bad)
        bad=deepcopy(state);bad['pickle']='not allowed'
        with self.assertRaises(ValueError):core.validate_state(bad)

    def test_ledger_budget_and_reservations_are_not_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger=core.Ledger(Path(folder))
            for cohort in core.COHORTS:
                for recipe in core.RECIPES:
                    for seed in core.SEEDS:ledger.reserve('classifier',cohort,f'{recipe["name"]}-{seed}',{'source':'same'})
            self.assertEqual(len(list(Path(folder).glob('classifier-*.json'))),8)
            with self.assertRaises(ValueError):ledger.reserve('classifier','READY','A-42',{})
            ledger.reserve('calibrator','READY','reference',{})
            ledger.reserve('calibrator','READY','selected',{})
            ledger.reserve('calibrator','COLD','selected',{})
            with self.assertRaises(ValueError):ledger.reserve('calibrator','COLD','reference',{})

    def test_read_json_refuses_duplicates_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'bad.json'
            for value in ('{"a":1,"a":2}','{"a":NaN}'):
                p.write_text(value)
                with self.assertRaises(ValueError):core.read_json(p)


class HttpTest(unittest.TestCase):
    def registry(self):
        registry=ModelRegistry.__new__(ModelRegistry)
        registry.verify=lambda:None
        registry.models={'COLD':(cold_state(),{'threshold':0.,'state_sha256':'fixture'})}
        registry.monitor=BoundedMonitor();registry.drift={}
        return registry

    def test_malformed_item_never_breaks_valid_sibling_or_metrics(self):
        registry=self.registry();bad=packet('invalid-snapshot-001','COLD')
        bad['features'][37]={'bad':'type'}
        answers=registry.assess_batch([bad,packet(cohort='COLD')])
        self.assertEqual(answers[0]['recommendation'],'UNDETERMINED')
        self.assertEqual(answers[1]['recommendation'],'ROUTINE')

    def test_real_loopback_http_faults_without_any_fit(self):
        from app.auth_extensions_benchmark import fault_tests
        packets=[packet('cold-http-test-'+str(i).zfill(4),'COLD') for i in range(8)]
        result=fault_tests(self.registry(),packets)
        self.assertEqual(result['status'],'HTTP_FAULT_PASS');self.assertEqual(result['new_fits'],0)


class DiagnosticsTest(unittest.TestCase):
    def test_confidence_is_context_only_and_evidence_is_bounded(self):
        value=packet();value['features'][77]=4;value['features'][70]=1;value['features'][71]=1
        result=diagnostics(value,[0.,0.,0.])
        self.assertEqual(result['confidence_status'],'LOW_CONFIDENCE')
        self.assertEqual(result['confidence_scope'],'LAB_CONTEXT_ONLY')
        self.assertLessEqual(len(result['evidence_summary']),3)
        self.assertNotIn('recommendation',result)
        m=calibration_metrics(np.array([[4.,0.,0.],[0.,4.,0.],[0.,0.,4.]]),np.arange(3))
        self.assertLess(m['log_loss'],.1);self.assertEqual(sum(x['count'] for x in m['reliability']),3)

    def test_drift_needs_two_qualified_windows_and_no_zero_filled_coverage(self):
        rng=np.random.default_rng(8);reference=DriftReference.fit(rng.normal(size=(6000,4)),['a','b','c','d'])
        stable=rng.normal(size=(1000,4));self.assertEqual(reference.window(stable)['status'],'STABLE')
        shifted=stable+10
        self.assertEqual(reference.window(shifted)['status'],'STABLE')
        self.assertEqual(reference.window(shifted)['status'],'DRIFT')
        missing=reference.window(np.zeros((0,4)),attempted=1000)
        self.assertEqual(missing['status'],'INSUFFICIENT_DATA');self.assertTrue(missing['coverage_drop'])
        self.assertEqual(reference.window(shifted)['status'],'STABLE')

    def test_bounded_counter_labels(self):
        monitor=BoundedMonitor();monitor.observe('COLD','EMAIL_CHANGE','REVIEW')
        self.assertEqual(int(monitor.counts.sum()),1)
        with self.assertRaises(ValueError):monitor.observe('actor-id','EMAIL_CHANGE','REVIEW')
        self.assertEqual(monitor.counts.size,16)

    def test_stream_monitor_does_not_retain_raw_observations(self):
        values=np.random.default_rng(9).normal(size=(3000,4));reference=DriftReference.fit(values,['a','b','c','d'])
        stream=StreamingDrift(reference.state)
        for row in values[:1000]:stream.observe(row)
        self.assertEqual(stream.windows,1);self.assertEqual(stream.attempted,0)
        for _ in range(1000):stream.observe(None)
        self.assertEqual(stream.last['status'],'INSUFFICIENT_DATA');self.assertTrue(stream.last['coverage_drop'])
        self.assertEqual(sum(c.size for c in stream.counts),sum(len(p) for p in reference.state['probabilities']))

    def test_cold_gate_rejects_one_false_positive_and_weak_stratum(self):
        value={'false_review':0,'operational_false_review':0,'operations':100,'operational_correct':100,
               'recall_by_case':dict.fromkeys(('case3','case4','case5'),1.),'assessment_coverage':1.,
               'strata':{s:{'false_review':0,'review':100,'true_review':100,'operations':100,'operational_correct':100} for s in ('0','1-9','10-29')}}
        self.assertTrue(cold_gate(value))
        value['false_review']=1;self.assertFalse(cold_gate(value))
        value['false_review']=0;value['strata']['0']['true_review']=89
        self.assertFalse(cold_gate(value))


class FakeRegistry:
    def __init__(self):self.calls=0;self.fail=False;self.reverse=False
    def assess_batch(self,packets):
        self.calls+=1
        if self.fail:raise RuntimeError('inference unavailable')
        results=[{'snapshot_id':p['snapshot_id'],'raw_score':0.,'recommendation':'ROUTINE'} for p in packets]
        return list(reversed(results)) if self.reverse else results


class BatchTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.registry=FakeRegistry();self.service=BatchService(self.registry,wait=.001)
        await self.service.start()
    async def asyncTearDown(self):await self.service.close()

    async def test_reordered_results_map_to_original_ids(self):
        self.registry.reverse=True
        packets=[packet(f'test-snapshot-{i:04}') for i in range(8)]
        result=await self.service.submit(packets)
        self.assertEqual([r['snapshot_id'] for r in result],[p['snapshot_id'] for p in packets])
        self.assertEqual(self.service.pending,0)

    async def test_duplicate_envelope_and_overload_never_reach_inference(self):
        with self.assertRaises(HTTPException):await self.service.submit([packet(),packet()])
        self.service.capacity=1
        with self.assertRaises(HTTPException):await self.service.submit([packet(),packet('test-snapshot-0002')])
        self.assertEqual(self.registry.calls,0);self.assertEqual(self.service.pending,0)

    async def test_worker_errors_open_breaker_and_cancellation_frees_pending(self):
        self.registry.fail=True
        for _ in range(5):
            result=await self.service.submit([packet()]);self.assertEqual(result[0]['recommendation'],'UNDETERMINED')
        self.assertEqual(self.service.circuit.state(),'OPEN')
        calls=self.registry.calls;await self.service.submit([packet()]);self.assertEqual(self.registry.calls,calls)
        self.service.wait=.2
        task=asyncio.create_task(self.service.submit([packet()]));await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(self.service.pending,0)

    def test_half_open_clock(self):
        now=[0.];c=Circuit(lambda:now[0])
        for _ in range(5):c.failure()
        self.assertEqual(c.state(),'OPEN');now[0]=31
        self.assertEqual(c.state(),'HALF_OPEN');c.success();self.assertEqual(c.state(),'CLOSED')


if __name__=='__main__':unittest.main()
