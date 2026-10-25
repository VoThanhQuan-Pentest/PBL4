"""Four focused bulk workflow contracts; small fixtures are not accuracy data."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import numpy as np

PATH=Path(__file__).resolve().parents[1]/"scripts/diagnose-ueba-hybrid-bulk.py"
SPEC=importlib.util.spec_from_file_location("bulk_default_diagnostic",PATH)
RUNNER=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=RUNNER;SPEC.loader.exec_module(RUNNER)
sys.path.insert(0,str(PATH.parents[2]/"ueba-worker/tests"))
from test_normal_support import normal


class BulkDefaultDiagnosticTest(unittest.TestCase):
    def test_host_refused_before_dataset_access(self):
        with patch.dict(os.environ,{"UEBA_DIAGNOSTIC_IMAGE_ID":""}),patch.object(RUNNER,"load_inputs") as read:
            with self.assertRaises(ValueError):RUNNER.run()
            read.assert_not_called()

    def test_real_bulk_catalog_has_actual_not_inflated_normal_fit(self):
        normal_rows,supervised,manifest,catalog,rows=RUNNER.load_inputs()
        self.assertEqual((len(normal_rows),len(supervised)),(50000,81500))
        self.assertEqual(catalog.sha256,RUNNER.CATALOG_SHA)
        self.assertEqual(catalog.split("fold1-fit")["sha256"],manifest["training_sections"]["NORMAL_COMPONENT"]["sha256"])
        self.assertEqual([len(rows["fold1-calibration-"+c]) for c in ("ready","cold")],[60000,60000])
        self.assertEqual(len(rows["fold1-validation"]),21000)

    def test_fit_audit_refuses_unexpected_or_additional_fits(self):
        audit=RUNNER.FitAudit()
        with self.assertRaises(AssertionError):audit.freeze()
        with audit:
            audit.counts.update({"composite":1,"normal":1,"classifier":1});audit.freeze()
            with self.assertRaises(AssertionError):RUNNER.HybridIncidentScorer().fit([],[],[])

    def test_actual_modelstore_numeric_save_load_and_recalibration_without_refit(self):
        fit=[normal(i) for i in range(512)];cal=[normal(i+1000) for i in range(100)]
        labeled=[];targets=[]
        for context in (0,1,2):
            for i in range(200):
                row=normal(i)
                if context==1:row[3],row[14],row[22]=10,10/11,5
                if context==2:row[2]=20
                labeled.append(row);targets.append(context)
        with tempfile.TemporaryDirectory() as directory,RUNNER.FitAudit() as audit:
            store=RUNNER.ModelStore(Path(directory))
            metadata=store.train("fixture_hybrid_initial",fit,cal,schema_version=4,config=RUNNER.HybridResearchConfig(),
                policy=RUNNER.ScorePolicy.strict(schema=4),labeled_samples=labeled,labeled_targets=targets)
            audit.freeze()
            _,payload=RUNNER.verified_load(store,metadata["model_version"],metadata["sha256"])
            original=RUNNER.fitted_state_sha(payload["model"])
            scores=np.sort(payload["model"].anomaly_scores(cal))
            updated=store.recalibrated_candidate(metadata["model_version"],"fixture_hybrid_calibrated",{"READY":scores,"COLD":scores},
                RUNNER.ScorePolicy.strict(schema=4),expected_source_sha256=metadata["sha256"],dataset_sha256="a"*64,
                split_sha256={"READY":"b"*64,"COLD":"c"*64},calibration_scope="PILOT_ONLY")
            loaded,calibrated=RUNNER.verified_load(store,updated["model_version"],updated["sha256"])
            self.assertEqual(RUNNER.fitted_state_sha(calibrated["model"]),original)
            self.assertEqual(loaded["additional_fit_calls"],0)
            self.assertEqual(dict(audit.counts),{"composite":1,"normal":1,"classifier":1})
            self.assertIsNone(store.active_version)


if __name__=="__main__":unittest.main()
