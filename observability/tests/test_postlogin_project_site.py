import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import postlogin_project_site as site


class ProjectSiteTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(site,'OUTPUT',self.root))
        self.release={'manifest_sha256':'a'*64,'images':{}}

    def test_partial_or_wrong_release_observation_cannot_authorize_deployment(self):
        (self.root/'project-one-hour-observe-v2.commit.private.json').write_text('{}')
        with patch.object(site,'checked',return_value={'status':'PROJECT_ONE_HOUR_OBSERVE_PASS','continuous_seconds':36,'evaluations':1}):
            with self.assertRaisesRegex(RuntimeError,'CONTINUOUS_OBSERVE'):site.selected_observe()
        with patch.object(site,'checked',return_value={'status':'PROJECT_ONE_HOUR_OBSERVE_PASS','continuous_seconds':3600,
                'evaluations':31,'release_receipt_sha256':'wrong'}),patch.object(site,'digest',return_value='expected'):
            with self.assertRaisesRegex(RuntimeError,'CONTINUOUS_OBSERVE'):site.selected_observe()

    def deployment_mocks(self):
        for name,value in {'selected_observe':'project-one-hour-observe-v2','checked':{'release_receipt_sha256':'fixed'},
                           'digest':'fixed','held':False,'owned_live':None,'protection':{'protected':'fixed'},
                           'backup':None,'commit':None,'compose':None,'validate_compose':None,'wait_health':None,'sql':'1'}.items():
            self.stack.enter_context(patch.object(site,name,return_value=value))

    def test_health_failure_preserves_runtime_hold_and_never_enforces(self):
        self.deployment_mocks()
        with (patch.object(site,'runtime_hold') as held,patch.object(site,'policy') as policy,
                patch.object(site,'verify_live',side_effect=RuntimeError('worker down'))):
            with self.assertRaisesRegex(RuntimeError,'worker down'):site.deploy(self.release)
        self.assertNotIn(False,[c.args[0] for c in held.call_args_list])
        self.assertNotIn('ENFORCE_LIMITED',[c.args[0] for c in policy.call_args_list])
        self.assertEqual(policy.call_args_list[-1].args[0],'OBSERVE')

    def test_failure_after_enable_returns_to_observe_with_same_migrated_binary(self):
        self.deployment_mocks()
        with (patch.object(site,'runtime_hold') as held,patch.object(site,'policy') as policy,
                patch.object(site,'verify_live',side_effect=[None,RuntimeError('manifest changed')])):
            with self.assertRaisesRegex(RuntimeError,'manifest changed'):site.deploy(self.release)
        self.assertEqual(held.call_args_list[-1].args,(True,))
        self.assertEqual(policy.call_args_list[-1].args[0],'OBSERVE')
        self.assertIn('ENFORCE_LIMITED',[c.args[0] for c in policy.call_args_list])
        self.assertFalse(site.compose.called and any('down' in c.args for c in site.compose.call_args_list))

    def test_explicit_pause_between_stages_prevents_app_replacement(self):
        self.deployment_mocks()
        with patch.object(site,'held',side_effect=[False,True]),patch.object(site,'runtime_hold'),patch.object(site,'policy'):
            with self.assertRaisesRegex(RuntimeError,'OPERATOR_HOLD'):site.deploy(self.release)
        self.assertEqual(site.compose.call_count,1)
        self.assertEqual(site.compose.call_args.args[-1],'postlogin-worker')

    def test_tampered_committed_backup_never_starts_a_clone(self):
        (self.root/'project-rollout-backup-v1.commit.private.json').write_text('{}')
        with patch.object(site,'checked',return_value={'sha256':'original'}),patch.object(site,'digest',return_value='changed'),patch.object(site,'docker') as docker:
            with self.assertRaisesRegex(RuntimeError,'ROLLOUT_BACKUP_CHANGED'):site.backup()
            docker.assert_not_called()

    def test_no_observe_receipt_means_no_deployment_side_effect(self):
        with patch.object(site,'runtime_hold') as hold,patch.object(site,'compose') as compose:
            with self.assertRaisesRegex(RuntimeError,'CONTINUOUS_OBSERVE'):site.deploy(self.release)
            hold.assert_not_called();compose.assert_not_called()

    def config(self):
        services={name:{'cpus':.5,'mem_limit':128*1024**2} for name in ('app','nginx','db','redis','postlogin-worker')}
        services['app']['environment']={'SIEM_UEBA_URL':'http://ueba-worker:8091','SIEM_UEBA_ENABLED':'false',
            'APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED':'true','APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST':'e2e-customer'}
        services['postlogin-worker'].update(environment={'UEBA_POSTLOGIN_SERVING_ONLY':'true'},
            networks={'flare-internal':{'aliases':['ueba-worker']}})
        return {'services':services}

    def test_compose_origin_must_satisfy_the_existing_gateway_allowlist(self):
        config=self.config();config['services']['app']['environment']['SIEM_UEBA_URL']='http://postlogin-worker:8091'
        with patch.object(site,'environment',return_value={}),patch.object(site,'docker',return_value=type('Response',(),{'stdout':json.dumps(config)})()):
            with self.assertRaisesRegex(RuntimeError,'COMPOSE_INTERNAL_ORIGIN'):site.validate_compose(self.release)

    def test_compose_worker_requires_internal_alias_and_no_public_port(self):
        for change in ({'networks':{'flare-internal':{'aliases':[]}}},{'ports':[{'published':'8091'}]}):
            config=self.config();config['services']['postlogin-worker'].update(change)
            with patch.object(site,'environment',return_value={}),patch.object(site,'docker',return_value=type('Response',(),{'stdout':json.dumps(config)})()):
                with self.assertRaisesRegex(RuntimeError,'COMPOSE_INTERNAL_ORIGIN'):site.validate_compose(self.release)

    def test_compose_valid_internal_worker_preserves_otp_and_caps(self):
        with patch.object(site,'environment',return_value={}),patch.object(site,'docker',return_value=type('Response',(),{'stdout':json.dumps(self.config())})()):
            self.assertEqual(site.validate_compose(self.release)['worker_origin'],'http://ueba-worker:8091')


if __name__=='__main__':unittest.main()
