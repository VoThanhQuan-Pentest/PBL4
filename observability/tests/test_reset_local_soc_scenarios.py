import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import reset_local_soc_scenarios as reset


class ResetScenarioTest(unittest.TestCase):
    def fixture(self):
        return {'id':'soc-demo-20261022-084405-50ea6e','origin':'UEBA','rule_id':'SOC_DEMO_WORKFLOW',
                'target_user_id':'soc-demo-customer','classification_reason':'DEMO_ONLY_WORKFLOW_FIXTURE: test'}

    def test_similar_prefix_does_not_authorize_deleting_real_incident(self):
        for change in [{'rule_id':'REAL_RULE'},{'target_user_id':'e2e-customer'},
                       {'classification_reason':'Real alert'},{'id':'soc-demo-not-a-fixture'},{'origin':'ELASTIC'}]:
            with self.subTest(change=change),self.assertRaisesRegex(RuntimeError,'REFUSE_NONFIXTURE'):
                reset.checked_fixtures([{**self.fixture(),**change}])
        self.assertEqual(reset.checked_fixtures([self.fixture()]),[self.fixture()])

    def test_deletes_use_exact_case_ids_and_only_dedicated_customer_scopes(self):
        selectors=reset.selectors([self.fixture()['id']])
        self.assertNotIn('LIKE',selectors['siem_incidents'])
        self.assertNotIn('e2e-customer',selectors['siem_security_events'])
        self.assertNotIn('soc-demo-l1',selectors['siem_security_events'])
        self.assertNotIn('tbl_nguoi_dung',selectors)
        with self.assertRaises(ValueError):reset.selectors([])
        with self.assertRaises(ValueError):reset.selectors(["soc-demo-x' OR 1=1"])

    def test_export_filter_removes_fixture_events_and_preserves_other_users_and_unknown_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'security-events.ndjson'
            keep=json.dumps({'user':{'id':'e2e-customer'},'event':{'id':'keep'}})+'\n'
            analyst=json.dumps({'user':{'id':'soc-demo-l1'},'event':{'id':'analyst-unrelated'}})+'\n'
            old=json.dumps({'user':{'id':'soc-demo-customer'},'event':{'id':'remove'}})+'\n'
            target=json.dumps({'target':{'user':{'id':'soc-practice-customer'}}})+'\n'
            path.write_text(old+keep+target+analyst+'unknown-format\n');path.chmod(0o640)
            program=reset.LOG_FILTER.replace('/logs',folder)
            result=subprocess.run([sys.executable,'-c',program],capture_output=True,text=True,check=True)
            stats=json.loads(result.stdout)['security-events.ndjson']
            self.assertEqual(stats,{'removed':2,'kept':3})
            self.assertEqual(path.read_text(),keep+analyst+'unknown-format\n')
            self.assertEqual(path.stat().st_mode&0o777,0o640)

    def test_export_filter_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            actual=Path(folder)/'other-file';actual.write_text('preserve')
            (Path(folder)/'security-events.ndjson').symlink_to(actual)
            result=subprocess.run([sys.executable,'-c',reset.LOG_FILTER.replace('/logs',folder)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertEqual(actual.read_text(),'preserve')


if __name__=='__main__':unittest.main()
