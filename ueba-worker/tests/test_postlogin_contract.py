import copy
import unittest
from app.postlogin_contract import FEATURE_NAMES, EVALUATION_UNIT, validate_snapshot, source_protocol, require_campaign_admission
from app.contract import FEATURE_SCHEMAS
from app.hybrid_strict_protocol import validate_manifest

class PostLoginContractTest(unittest.TestCase):
    def snapshot(self):
        values=[0.]*65;values[37]=1.;values[39]=1.
        return dict(snapshot_id="owned-snapshot-0001",evaluation_unit=EVALUATION_UNIT,feature_schema_version=6,
            feature_names=list(FEATURE_NAMES),features=values,as_of="2026-10-21T00:00:00Z",
            baseline_established=False,trusted_window_count=0)

    def test_explicit_pre_attempt_contract_does_not_change_legacy_window_schemas(self):
        value=self.snapshot();self.assertEqual(len(validate_snapshot(value)),65)
        self.assertEqual(set(FEATURE_SCHEMAS),{1,2,3,4})
        for change in ({"evaluation_unit":"ACCOUNT_WINDOW"},{"feature_schema_version":4},
                       {"features":[0.]*61},{"context_class":1},{"otp":123456},
                       {"features":[float("nan")]*65},{"as_of":"2026-10-21T00:00:00"}):
            with self.subTest(change=tuple(change)),self.assertRaises(ValueError):validate_snapshot(value|change)
        names=list(FEATURE_NAMES);names[0],names[1]=names[1],names[0]
        with self.assertRaises(ValueError):validate_snapshot(value|{"feature_names":names})

    def test_readiness_is_observed_and_not_zero_filled(self):
        for count,ready in ((0,False),(3,False),(30,True),(48,True)):
            self.assertEqual(len(validate_snapshot(self.snapshot()|dict(trusted_window_count=count,baseline_established=ready))),65)
        for count,ready in ((0,True),(3,True),(30,False),(True,False)):
            with self.assertRaises(ValueError):validate_snapshot(self.snapshot()|dict(trusted_window_count=count,baseline_established=ready))

    def test_new_source_keeps_full_counts_and_is_not_authority_to_fit(self):
        protocol=source_protocol("postlogin-strict-lab-new-01")
        self.assertEqual(protocol["standard_numeric_rows"],19163000)
        self.assertEqual(len(protocol["campaign"]),360)
        self.assertEqual(protocol["required_component_fit_calls"],720)
        self.assertEqual(protocol["holdout"]["normal"],10000000)
        self.assertEqual(protocol["evaluation_unit"],EVALUATION_UNIT)
        self.assertEqual(protocol["feature_names"],list(FEATURE_NAMES))
        self.assertFalse(protocol["actor_role_is_ml_target"])
        for approval in ({},{"status":"USER_AUTHORIZED_PREPARATION_ONLY"},
                         {"status":"USER_AUTHORIZED_CAMPAIGN","protocol_sha256":"0"*64}):
            with self.assertRaises(ValueError):require_campaign_admission(protocol,approval)
        with self.assertRaises(ValueError):validate_manifest({"format":protocol["format"]},protocol)

    def test_model_refuses_preparation_authority_before_any_fit_or_reservation(self):
        from app.postlogin_model import PostLoginContextScorer
        def no_component(*args):raise AssertionError('unexpected component reservation')
        with self.assertRaisesRegex(ValueError,'cannot authorize'):
            PostLoginContextScorer().fit([],[],[],protocol=source_protocol('postlogin-strict-lab-new-02'),
                approval={'status':'USER_AUTHORIZED_PREPARATION_ONLY'},reserve_component=no_component)

if __name__=="__main__":unittest.main()
