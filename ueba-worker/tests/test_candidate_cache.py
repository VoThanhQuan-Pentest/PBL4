"""Cache reuse may never hide a changed artifact or replace full validation."""
import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from app.candidate_cache import CandidateCache
from app.model import ModelStore
from app.hybrid_incident import HybridIncidentScorer
from app.normal_support import NormalSupportScorer
from app.policy import ScorePolicy
from test_hybrid_model_store import train as train_hybrid
from test_normal_support import normal as normal_v4
from test_model import normal


class CandidateCacheTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ModelStore(self.root)
        self.store.train("cache_owned_fixture", [normal(i) for i in range(600)], [normal(i) for i in range(120)])
        self.cache = CandidateCache()

    def tearDown(self): self.temporary.cleanup()

    def test_concurrent_same_candidate_restores_once_and_scores_identically(self):
        expected = self.store.score_candidate("cache_owned_fixture", [normal(1)])
        with patch.object(self.store, "load_candidate", wraps=self.store.load_candidate) as load:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                actual = list(pool.map(lambda _: self.cache.score(self.store, "cache_owned_fixture", [normal(1)]), range(16)))
            self.assertEqual(load.call_count, 1)
        self.assertTrue(all(value == expected for value in actual))
        self.assertIsNone(self.store.active_version)

    def test_binary_tamper_same_size_and_mtime_does_not_reuse_cached_model(self):
        self.cache.score(self.store, "cache_owned_fixture", [normal(1)])
        path = self.root / "cache_owned_fixture.joblib"
        before = path.stat(); body = bytearray(path.read_bytes()); body[-1] ^= 1
        path.write_bytes(body); os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.cache.score(self.store, "cache_owned_fixture", [normal(1)])
        self.assertEqual(len(self.cache._entries), 0)

    def test_metadata_tamper_revalidates_and_rejects(self):
        self.cache.score(self.store, "cache_owned_fixture", [normal(1)])
        path = self.root / "cache_owned_fixture.json"
        body = json.loads(path.read_text()); body["feature_names"] = ["wrong"] * 11
        path.write_text(json.dumps(body))
        with self.assertRaises(ValueError): self.cache.score(self.store, "cache_owned_fixture", [normal(1)])

    def test_symlink_and_bad_version_are_refused_before_loading(self):
        with self.assertRaises(ValueError): self.cache.score(self.store, "../escape", [normal(0)])
        path = self.root / "cache_owned_fixture.joblib"; moved = self.root / "saved"
        path.rename(moved); path.symlink_to(moved)
        with self.assertRaises(ValueError): self.cache.score(self.store, "cache_owned_fixture", [normal(0)])

    def test_http_getter_is_single_instance_on_concurrent_cold_access(self):
        from app import main
        from app.candidate_cache import HTTP_CANDIDATE_CACHE
        main.candidate_cache.cache_clear()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(lambda _: main.candidate_cache(), range(16)))
        self.assertTrue(all(value is HTTP_CANDIDATE_CACHE for value in values))

    def test_code_binding_change_revalidates_and_cache_is_bounded(self):
        self.cache.score(self.store, "cache_owned_fixture", [normal(1)])
        binding = self.cache._binding
        with patch.object(self.cache, "_binding", side_effect=lambda store, version: (*binding(store, version)[:2], ("new-code",))), \
                patch.object(self.store, "load_candidate", wraps=self.store.load_candidate) as load:
            self.cache.score(self.store, "cache_owned_fixture", [normal(1)])
            self.assertEqual(load.call_count, 1)
        for index in range(2):
            version = "cache_other_fixture_" + str(index)
            self.store.train(version, [normal(i) for i in range(600)], [normal(i) for i in range(120)])
            self.cache.score(self.store, version, [normal(1)])
        self.assertEqual(len(self.cache._entries), 2)
        # Touch the older of the two survivors; inserting a third must evict
        # the other entry, not whichever was initially inserted first.
        self.cache.score(self.store, "cache_other_fixture_0", [normal(1)])
        self.store.train("cache_other_fixture_2", [normal(i) for i in range(600)], [normal(i) for i in range(120)])
        self.cache.score(self.store, "cache_other_fixture_2", [normal(1)])
        self.assertEqual([key[1] for key in self.cache._entries], ["cache_other_fixture_0", "cache_other_fixture_2"])

    def test_actual_hybrid_cached_ready_cold_scores_are_exact_without_refitting(self):
        # Existing tiny fixture only: normal600, supervised180, initialcal300.
        source = train_hybrid(self.store)
        cold_rows = [normal_v4(i) for i in range(300)]
        for row in cold_rows:
            row[35] = 3
        with patch.object(HistGradientBoostingClassifier, "fit", side_effect=AssertionError("no cached fit")), \
                patch.object(NormalSupportScorer, "fit", side_effect=AssertionError("no cached fit")), \
                patch.object(HybridIncidentScorer, "fit", side_effect=AssertionError("no cached fit")):
            _, payload = self.store.load_candidate("hybrid_owned_fixture")
            ready = np.sort(-payload["model"].score_samples([normal_v4(i) for i in range(300)]))
            cold = np.sort(-payload["model"].score_samples(cold_rows))
            self.store.recalibrated_candidate("hybrid_owned_fixture", "hybrid_cached_calibrated", {"READY": ready, "COLD": cold},
                ScorePolicy.strict(schema=4), expected_source_sha256=source["sha256"], dataset_sha256="a" * 64,
                split_sha256={"READY": "b" * 64, "COLD": "c" * 64}, calibration_scope="PILOT_ONLY")
            vectors, cohorts = [normal_v4(0), cold_rows[0]], ["READY", "COLD"]
            expected = self.store.score_candidate("hybrid_cached_calibrated", vectors, 4, cohorts)
            with patch.object(self.store, "load_candidate", wraps=self.store.load_candidate) as load:
                first = self.cache.score(self.store, "hybrid_cached_calibrated", vectors, 4, cohorts)
                warm = self.cache.score(self.store, "hybrid_cached_calibrated", vectors, 4, cohorts)
                self.assertEqual(load.call_count, 1)
            self.assertEqual(first, expected)
            self.assertEqual(warm, expected)
            self.assertEqual([row["scoring_cohort"] for row in warm["results"]], cohorts)
            self.assertIsNone(self.store.active_version)
            self.assertFalse((self.root / "active.json").exists())
