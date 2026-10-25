import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import postlogin_impl_control as control
from ueba_research_artifacts import commit, digest, publish


class ImplementationControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name);self.runtime = self.root / 'runtime';self.runtime.mkdir(mode=0o750)
        self.ledger = self.root / 'fit-ledger.json';self.ledger.write_text('{"fits":0}')
        self.stack = contextlib.ExitStack();self.addCleanup(self.stack.close)
        for name, value in [('OUTPUT', self.root), ('RUNTIME', self.runtime), ('FIT_LEDGER', self.ledger)]:
            self.stack.enter_context(patch.object(control, name, value))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        publish(self.root / 'budget.private.json', {'active_unit': None, 'elapsed_seconds': 7,
            'inherited_job_seconds': 0, 'recovered_interrupted_units': 0, 'group_seconds': {}})
        publish(self.root / 'operator-state.private.json', {'status': 'READY', 'phase': 'P0'})
        commit(self.root, {'new_fit_cap': 0, 'historical_fit_ledger_sha256': digest(self.ledger)},
               phase='implementation-authorization-v1')

    def test_pause_and_resume_keep_runtime_disabled_until_revalidated(self):
        control.pause()
        self.assertTrue(control.held())
        self.assertTrue(json.loads((self.runtime / 'operator-hold.json').read_text())['hold_new_units'])
        control.resume()
        self.assertFalse(control.held())
        self.assertTrue(json.loads((self.runtime / 'operator-hold.json').read_text())['hold_new_units'])
        self.assertTrue(control.read('operator-state.private.json')['runtime_revalidation_required'])

    def test_pause_never_signals_a_reused_pid_or_other_boot(self):
        active = {'id': 'compile-v1', 'pid': 424242, 'process_start': 'expected'}
        publish(self.root / 'budget.private.json', {**control.read('budget.private.json'), 'active_unit': active})
        publish(self.root / 'current-unit.private.json', {'unit': 'compile-v1',
            'boot_id': control.boot_id(), 'pause_mode': 'interruptible'})
        with patch.object(control, 'process_start', return_value='reused'), patch.object(control.os, 'killpg') as kill:
            control.pause();kill.assert_not_called()
        with patch.object(control, 'process_start', return_value='expected'), patch.object(control.os, 'killpg') as kill:
            control.pause();kill.assert_called_once_with(424242, control.signal.SIGTERM)
        publish(self.root / 'current-unit.private.json', {'unit': 'compile-v1',
            'boot_id': 'old-boot', 'pause_mode': 'interruptible'})
        with patch.object(control, 'process_start', return_value='expected'), patch.object(control.os, 'killpg') as kill:
            control.pause();kill.assert_not_called()

    def test_interrupted_boundary_is_charged_and_cannot_be_blindly_replayed(self):
        active = {'id': 'http-case-v1', 'pid': 99999999, 'process_start': 'old', 'group': 'verification',
                  'cap_seconds': 5, 'deadline_utc': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
        publish(self.root / 'budget.private.json', {**control.read('budget.private.json'), 'active_unit': active})
        publish(self.root / 'current-unit.private.json', {'unit': active['id'], 'boot_id': 'previous-boot', 'pause_mode': 'boundary'})
        control.reconcile()
        self.assertEqual(control.read('budget.private.json')['elapsed_seconds'], 12)
        self.assertTrue(control.read('operator-state.private.json')['boundary_audit_required'])
        with self.assertRaisesRegex(RuntimeError, 'BOUNDARY_AUDIT_REQUIRED'):
            control._run_unit(SimpleNamespace(unit='retry-http-v2'))

    def test_resume_rejects_changed_fit_ledger(self):
        control.pause();self.ledger.write_text('{"fits":1}')
        with self.assertRaisesRegex(RuntimeError, 'FIT_LEDGER_CHANGED'):control.resume()

    def test_boundary_ack_requires_matching_committed_audit_and_keeps_runtime_held(self):
        state=control.read('operator-state.private.json')
        state.update(interrupted_unit_id='job-live-write-v1',boundary_audit_required=True)
        publish(self.root/'operator-state.private.json',state)
        commit(self.root,{'status':'BOUNDARY_OUTCOME_AUDIT_PASS','interrupted_unit_id':'wrong',
            'business_resolution':'NO_SIDE_EFFECTS','protected_state_verified':True,'owned_resources_verified':True},phase='wrong-audit')
        with self.assertRaisesRegex(RuntimeError,'MATCHING_DATABASE'):
            control.acknowledge_boundary(SimpleNamespace(receipt='wrong-audit'))
        commit(self.root,{'status':'BOUNDARY_OUTCOME_AUDIT_PASS','interrupted_unit_id':'job-live-write-v1',
            'business_resolution':'NO_SIDE_EFFECTS','protected_state_verified':True,'owned_resources_verified':True},phase='matching-audit')
        control.acknowledge_boundary(SimpleNamespace(receipt='matching-audit'))
        self.assertFalse(control.read('operator-state.private.json')['boundary_audit_required'])
        self.assertTrue(json.loads((self.runtime/'operator-hold.json').read_text())['hold_new_units'])


if __name__ == '__main__':unittest.main()
