import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from ueba_research_artifacts import publish,commit
spec=importlib.util.spec_from_file_location('preparation_controller',Path(__file__).resolve().parents[1]/'scripts/complete-postlogin-preparation.py')
controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)

class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        publish(self.root/'budget.private.json',{'active_unit':None})
        commit(self.root,{'code_sha256':{},'new_fit_cap':0,'quota_policy':'NOT_USED'},phase='preparation-pipeline-protocol-v5')
        self.args=SimpleNamespace(output=self.root,maximum_seconds=1)

    def test_missing_capture_cannot_launch_audit_or_train(self):
        with patch.object(controller.subprocess,'run',side_effect=AssertionError('must not spawn')):
            self.assertEqual(controller.wait_and_finish(self.args),4)

    def test_missing_process_is_not_permission_to_replay_source(self):
        publish(self.root/'budget.private.json',{'active_unit':{'id':'real-clock-history-and-capture-v1','pid':99999999,'process_start':'not-a-process'}})
        with patch.object(controller.subprocess,'run',side_effect=AssertionError('must not replay')):
            self.assertEqual(controller.wait_and_finish(self.args),3)

    def test_explicit_hold_reaches_the_live_child_guard(self):
        child=self.root/'capture-real-v1';child.mkdir(mode=0o700)
        publish(self.root/'operator-hold.private.json',{'hold_new_units':True})
        self.assertEqual(controller.wait_and_finish(self.args),2)
        self.assertTrue(json.loads((child/'operator-hold.private.json').read_text())['hold_new_units'])

    def test_final_audit_imports_workspace_modules_instead_of_image_package(self):
        child=self.root/'capture-real-v1';child.mkdir(mode=0o700)
        (child/'preparation-capture-result-v1.commit.private.json').touch()
        publish(self.root/'operator-state.private.json',{})
        publish(self.root/'measured-preparation-result-v1.receipt.private.json',
                {'status':'ZERO_FIT_PREPARATION_MEASUREMENTS_COMPLETE'})
        with patch.object(controller.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(controller.wait_and_finish(self.args),0)
        command=run.call_args.args[0]
        self.assertEqual(command[command.index('--workdir')+1],'/work')
        self.assertEqual(command[command.index('--network')+1],'none')
        state=json.loads((self.root/'preparation-controller.private.json').read_text())
        self.assertEqual(state['status'],'MEASUREMENTS_READY_AWAIT_CAMPAIGN_BUDGET')

if __name__=='__main__':unittest.main()
