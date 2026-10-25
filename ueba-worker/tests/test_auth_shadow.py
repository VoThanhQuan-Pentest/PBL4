import copy
import json
import unittest
import numpy as np
from app.auth_shadow_contract import FEATURE_NAMES,RECIPES,validate,pilot_protocol
from app.auth_shadow_model import fit_classifier,export_classifier,validate_state,logits
from app.normal_support import _signed_log

class AuthShadowContractTest(unittest.TestCase):
    def packet(self):
        values=[0.]*81;values[37]=1.;values[39]=1.
        return {'snapshot_id':'auth-shadow-snapshot-0001','evaluation_unit':'SENSITIVE_ACTION_ATTEMPT',
            'feature_schema_version':7,'feature_names':list(FEATURE_NAMES),'features':values,
            'as_of':'2026-10-24T00:00:00Z','baseline_established':True,'trusted_window_count':30,
            'coverage':{'auth_source_window':True,'session_context':True,'otp_history':True}}
    def test_exact81_contract_and_no_zero_padding_or_missing_coverage(self):
        self.assertEqual(len(validate(self.packet())),81)
        for change in [{'feature_schema_version':6},{'features':[0.]*96},
                       {'coverage':{'auth_source_window':True,'session_context':False,'otp_history':True}},
                       {'baseline_established':False,'trusted_window_count':0}]:
            with self.subTest(change=list(change)),self.assertRaises(ValueError):validate(self.packet()|change)
        self.assertFalse(pilot_protocol()['strict_adoption_eligible'])
        self.assertFalse(pilot_protocol()['automatic_hold_eligible'])
        self.assertEqual(pilot_protocol()['maximum_classifier_fits'],4)
    def test_future_outcome_and_raw_identity_cannot_enter_numeric_contract(self):
        for key in ['password','otp','actor_id','current_outcome','label']:
            with self.subTest(key=key),self.assertRaises(ValueError):validate(self.packet()|{key:'not permitted'})

class NumericCodecTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One small test-fixture fit, never a pilot/adoption artifact or serving-model modification.
        cls.rows=np.random.default_rng(7).uniform(0,10,(192,81))
        labels=np.digitize(cls.rows[:,0],[3.3,6.6])
        cls.model=fit_classifier(cls.rows,labels,RECIPES[0],42)
        cls.state=export_classifier(cls.model,RECIPES[0],42)
    def test_numeric_json_round_trip_matches_sklearn_logits(self):
        state=validate_state(json.loads(json.dumps(self.state,allow_nan=False)))
        np.testing.assert_allclose(logits(state,self.rows[:32]),self.model._raw_predict(_signed_log(self.rows[:32])),rtol=1e-12,atol=1e-12)
    def test_codec_refuses_cycles_unknown_fields_and_out_of_range_features(self):
        bad=copy.deepcopy(self.state);bad['trees'][0][0][0]['left']=0
        with self.assertRaises(ValueError):validate_state(bad)
        with self.assertRaises(ValueError):validate_state(self.state|{'pickle':'not allowed'})
        bad=copy.deepcopy(self.state);bad['trees'][0][0][0]['feature']=81
        with self.assertRaises(ValueError):validate_state(bad)
        with self.assertRaises(ValueError):logits(self.state,np.ones((33,81)))

if __name__=='__main__':unittest.main()
