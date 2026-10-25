"""Predeclared grid boundary tests, no measured model accuracy."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import numpy as np

P=Path(__file__).resolve().parents[1]/"scripts/diagnose-ueba-hybrid-bulk-grid.py"
S=importlib.util.spec_from_file_location("bulk_grid_test_driver",P);G=importlib.util.module_from_spec(S);sys.modules[S.name]=G;S.loader.exec_module(G)

class BulkGridTest(unittest.TestCase):
    def test_exact24_configs_include_unchanged_default(self):
        self.assertEqual(len(set(G.CONFIGURATIONS)),24);self.assertIn((200,31,1),G.CONFIGURATIONS)
    def test_host_refused_before_data_or_fit(self):
        with patch.dict(os.environ,{"UEBA_DIAGNOSTIC_IMAGE_ID":""}),patch.object(G.base,"load_inputs") as read:
            with self.assertRaises(ValueError):G.run(Path("/nonexistent-private-grid"))
            read.assert_not_called()
    def test_existing_policy_grid_is192_and_never_quality_pass(self):
        values=G.sweep(np.array([0.,100.,100.]),np.array([0,1,1]),np.array([0,1,2]),np.array([0,1,2]),np.zeros((3,3),dtype=bool),schema=4)
        self.assertEqual(len(values),192);self.assertEqual(len({x["policy"]["policy_sha256"] for x in values}),192)
        self.assertTrue(all(x["quality_gate"]=="NOT_APPLICABLE" for x in values))
    def test_private_default_source_is_not_edited(self):
        self.assertEqual(G.base.checksum(P.with_name("diagnose-ueba-hybrid-bulk.py")),"fb74756531dc6ceeeb607f34b94553cb68df20b33ebe6987104975e9423a9db9")

if __name__=="__main__":unittest.main()
