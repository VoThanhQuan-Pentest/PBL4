"""Schema4 extraction/receipt invariants; fixture vectors are not accuracy proof."""

from collections import Counter
from contextlib import redirect_stdout
from datetime import timedelta
import importlib.util
import io
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch


PATH = Path(__file__).resolve().parents[1] / "scripts/prepare-ueba-schema4.py"
SPEC = importlib.util.spec_from_file_location("schema4_full_generator", PATH)
GENERATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GENERATOR
SPEC.loader.exec_module(GENERATOR)


class Schema4GeneratorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.episodes = GENERATOR.load_generator()

    def test_strict_recipe_exactly_preserves_original_population_and_dates(self):
        old_path = PATH.with_name("prepare-ueba-strict.py")
        spec = importlib.util.spec_from_file_location("schema2_recipe_only", old_path)
        original = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = original
        spec.loader.exec_module(original)
        self.assertEqual([part.__dict__ for part in original.recipe("STRICT")],
                         [part.__dict__ for part in GENERATOR.recipe("STRICT")])
        parts = GENERATOR.recipe("STRICT")
        self.assertEqual(sum(part.normal + part.positive for part in parts), 19163000)
        self.assertEqual(sum(part.positive for part in parts if part.split == "holdout"), 10000)
        self.assertEqual(sum(part.positive for part in parts if part.split == "fold1-validation"), 1000)

    def test_pilot_is_complete_but_excludes_holdout_and_fitting_labels(self):
        parts = GENERATOR.recipe("PILOT")
        self.assertEqual({part.split for part in parts}, {"fold1-fit", "fold1-calibration-ready",
                                                        "fold1-calibration-cold", "fold1-validation"})
        self.assertEqual(parts[0].normal, 2000)
        self.assertTrue(all(part.positive == 0 for part in parts if "validation" not in part.split))
        for kwargs in ({"pilot_fit": 0}, {"pilot_positive": 11}, {"pilot_normal": True}):
            with self.assertRaises(ValueError):
                GENERATOR.recipe("PILOT", **kwargs)

    def test_assignment_bounds_and_five_family_balance(self):
        parts = GENERATOR.recipe("PILOT", pilot_fit=64, pilot_calibration=1000, pilot_normal=1003, pilot_positive=15)
        totals, families = Counter(), Counter()
        for _, part, batch, offset in GENERATOR.jobs(parts, 128):
            self.assertLessEqual(len(batch), 128)
            for _, values in batch:
                if part.cohort == "COLD":
                    self.assertLessEqual(len(values) + 3, 23)
                for _, index in values:
                    totals[(part.split, part.cohort)] += 1
                    if index is not None:
                        families[GENERATOR.FAMILIES[(index + offset) % 5]] += 1
        self.assertEqual(families, Counter({family: 3 for family in GENERATOR.FAMILIES}))
        for part in parts:
            self.assertEqual(totals[(part.split, part.cohort)], part.normal + part.positive)
        with self.assertRaises(ValueError):
            list(GENERATOR.actor_batches(GENERATOR.Part("fold1-calibration-ready", "READY", 33, 3, 1000), 2))

    def test_namespaces_are_opaque_cause_independent_and_same_ready_pool(self):
        parts = GENERATOR.recipe("STRICT")
        fit = parts[0]
        calibration = parts[1]
        validation = next(part for part in parts if part.split == "fold1-validation" and part.cohort == "READY")
        holdout = next(part for part in parts if part.split == "holdout" and part.cohort == "READY")
        fold3 = next(part for part in parts if part.split == "fold3-fit")
        self.assertEqual(GENERATOR.namespace("schema4-test-opaque", fit), GENERATOR.namespace("schema4-test-opaque", calibration))
        self.assertEqual(GENERATOR.namespace("schema4-test-opaque", fit), GENERATOR.namespace("schema4-test-opaque", validation))
        self.assertEqual(GENERATOR.namespace("schema4-test-opaque", holdout), GENERATOR.namespace("schema4-test-opaque", fold3))
        self.assertNotEqual(GENERATOR.namespace("schema4-test-opaque", fit), GENERATOR.namespace("schema4-test-opaque", fold3))
        for cohort in ("READY", "UNSEEN_READY", "COLD"):
            part = GENERATOR.Part("fold1-validation", cohort, 51, 4, 100, 10)
            normal = GENERATOR.make_episode(self.episodes, "schema4-test-opaque", part, 3, 0)
            abnormal = GENERATOR.make_episode(self.episodes, "schema4-test-opaque", part, 3, 0, positive_index=2)
            self.assertEqual(normal["frame"]["account_id"], abnormal["frame"]["account_id"])
            self.assertEqual(normal["frame"]["frame_id"], abnormal["frame"]["frame_id"])
            for identity in (normal["frame"]["account_id"], normal["frame"]["frame_id"]):
                self.assertFalse(any(word in identity for word in ("ready", "cold", "unseen", *GENERATOR.FAMILIES)))
            self.assertNotIn("label", normal["frame"])
            self.assertNotIn("family", normal["frame"])
            self.assertNotIn("client_ledger", GENERATOR.transport(abnormal))

    def test_clean_past_context_is_frozen_and_cold_stays_inside_actual_bound(self):
        for cohort in ("READY", "UNSEEN_READY", "COLD"):
            part = GENERATOR.Part("fold1-validation", cohort, 51, 4, 100, 10)
            target = GENERATOR.make_episode(self.episodes, "schema4-test-context", part, 7, 0)
            count = 3 if cohort == "COLD" else 48
            for ordinal in range(count):
                context = GENERATOR.make_episode(self.episodes, "schema4-test-context", part, 7, ordinal, context=True)
                self.assertLess(context["frame"]["window_start"], target["frame"]["window_start"])
                self.assertEqual(context["frame"]["account_id"], target["frame"]["account_id"])
                self.assertEqual(context["scenario"]["label"], 0)
                self.assertTrue(context["scenario"]["plan"]["baseline_context"])
                self.assertEqual(context["scenario"]["plan"]["failed_logins"], 0)
                self.assertLess(len(context["frame"]["events"]), 4096)
                self.assertGreaterEqual(context["frame"]["day"], 1)
            self.assertEqual(target["frame"]["day"], 51)
            end = GENERATOR.make_episode(self.episodes, "schema4-test-context", part, 7, 47 if cohort != "COLD" else 19)
            self.assertLessEqual(end["frame"]["day"], part.day + part.days - 1)

    def test_real_frozen_java_workspace_and_endpoint_identity(self):
        classpath, package = GENERATOR.workspace_identity(GENERATOR.DEFAULT_WORKSPACE, GENERATOR.DEFAULT_WORKSPACE_SHA256)
        self.assertEqual((len(package["classes"]), len(package["jars"])), (322, 141))
        self.assertNotIn(str(GENERATOR.ROOT / "backend/target/classes") + ":", classpath)
        proof = GENERATOR.endpoint_identity(GENERATOR.DEFAULT_ENDPOINT_PROOF, GENERATOR.DEFAULT_ENDPOINT_SHA256,
                                            GENERATOR.DEFAULT_WORKSPACE_SHA256, package, self.episodes)
        self.assertEqual(proof["sha256"], GENERATOR.DEFAULT_ENDPOINT_SHA256)
        with self.assertRaises(ValueError):
            GENERATOR.workspace_identity(GENERATOR.DEFAULT_WORKSPACE, "0" * 64)
        with patch.object(GENERATOR, "GENERATOR_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                GENERATOR.load_generator()

    @staticmethod
    def fixture_export(episodes, dataset, part, batch, offset, classpath, output, writer, timeout):
        """Only receipt plumbing: deliberately synthetic zero-vector fixture."""
        count = 0
        for account, values in batch:
            for ordinal, index in values:
                episode = GENERATOR.make_episode(episodes, dataset, part, account, ordinal,
                                                  positive_index=None if index is None else index + offset)
                row = {key: episode["frame"][key] for key in ("frame_id", "account_id", "window_start")}
                row.update(label=episode["scenario"]["label"], family=episode["scenario"]["family"], cohort=part.cohort,
                           baseline_established=part.cohort != "COLD", trusted_window_count=3 if part.cohort == "COLD" else 48,
                           features=[0] * 37)
                writer.append(row)
                count += 1
        writer.flush()
        return {"raw_frames": count + len(batch) * (3 if part.cohort == "COLD" else 48), "evaluated_rows": count,
                "raw_stream_sha256": "1" * 64, "planned_scenarios_sha256": "2" * 64, "elapsed_seconds": 0.1,
                "java_sampled_peak_rss_kib": 1, "python_sampled_peak_rss_kib": 1}

    def fixture_options(self, output):
        return dict(output=output, pilot_fit=2, pilot_calibration=10, pilot_normal=10, pilot_positive=5, batch_accounts=1)

    def test_stopped_job_resumes_receipts_even_when_stale_lock_file_exists(self):
        with tempfile.TemporaryDirectory(prefix="schema4-receipts-") as root:
            output = Path(root) / "catalogue"
            options = self.fixture_options(output)
            with patch.object(GENERATOR, "export_batch", side_effect=self.fixture_export) as exported, redirect_stdout(io.StringIO()):
                stopped = GENERATOR.prepare("schema4-receipt-pilot", maximum_batches=1, **options)
                self.assertEqual(stopped["status"], "STOPPED_AT_BATCH_BOUNDARY")
                self.assertFalse((output / "manifest.json").exists())
                original = next((output / "shards").iterdir())
                checksum = GENERATOR.digest(original)
                abandoned = output / "pending" / "stopped-uncommitted-batch"
                abandoned.mkdir()
                GENERATOR.write_new(abandoned / "untrusted.json", {"not": "a receipt"})
                result = GENERATOR.prepare("schema4-receipt-pilot", resume=True, **options)
                self.assertEqual(result["status"], "COMPLETED")
                self.assertEqual(result["quality_gate"], "NOT_APPLICABLE")
                self.assertEqual(result["fit_or_score_calls"], 0)
                self.assertEqual(GENERATOR.digest(original), checksum)
                self.assertTrue(list((output / "abandoned").iterdir()))
                self.assertEqual(exported.call_count, result["completed_batches"])
            catalogue = GENERATOR.ShardedDataset(output)
            self.assertEqual(catalogue.manifest["feature_schema_version"], 4)
            self.assertEqual(catalogue.manifest["telemetry_contract_version"], 3)
            self.assertEqual(catalogue.split("fold1-validation")["families"], {"normal": 10, **{family: 1 for family in GENERATOR.FAMILIES}})
            self.assertNotIn("holdout", catalogue.manifest["splits"])
            for name in catalogue.manifest["splits"]:
                list(catalogue.iter_shards(name))
            with self.assertRaisesRegex(ValueError, "unpublished"):
                GENERATOR.prepare("schema4-receipt-pilot", resume=True, **options)

    def test_changed_numeric_shard_or_source_binding_refuses_resume(self):
        with tempfile.TemporaryDirectory(prefix="schema4-corruption-") as root:
            output = Path(root) / "catalogue"
            options = self.fixture_options(output)
            with patch.object(GENERATOR, "export_batch", side_effect=self.fixture_export), redirect_stdout(io.StringIO()):
                GENERATOR.prepare("schema4-corrupt-pilot", maximum_batches=1, **options)
                binding = GENERATOR.source_binding()
                binding["sha256"] = "0" * 64
                with patch.object(GENERATOR, "source_binding", return_value=binding):
                    with self.assertRaisesRegex(ValueError, "identity changed"):
                        GENERATOR.prepare("schema4-corrupt-pilot", resume=True, **options)
                shard = next((output / "shards").iterdir())
                rows = GENERATOR.parse_json(GENERATOR.read_file(shard, GENERATOR.MAX_SHARD_BYTES))
                rows[0]["features"][0] = 1
                GENERATOR.replace_progress(shard, rows)
                with self.assertRaisesRegex(ValueError, "projected shard differs"):
                    GENERATOR.prepare("schema4-corrupt-pilot", resume=True, **options)
                self.assertFalse((output / "manifest.json").exists())

    def test_symlink_output_is_refused_without_external_write(self):
        with tempfile.TemporaryDirectory(prefix="schema4-path-") as root:
            target = Path(root) / "external"
            target.mkdir()
            link = Path(root) / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                GENERATOR.prepare("schema4-symlink-pilot", **self.fixture_options(link))
            self.assertEqual(list(target.iterdir()), [])

    def test_unlisted_receipt_refuses_resume_before_starting_java(self):
        with tempfile.TemporaryDirectory(prefix="schema4-unknown-receipt-") as root:
            output = Path(root) / "catalogue"
            options = self.fixture_options(output)
            with patch.object(GENERATOR, "export_batch", side_effect=self.fixture_export), redirect_stdout(io.StringIO()):
                GENERATOR.prepare("schema4-unlisted-pilot", maximum_batches=1, **options)
            original = next((output / "batches").iterdir())
            unknown = output / "batches" / "part99-batch999999"
            unknown.mkdir()
            receipt = GENERATOR.parse_json(GENERATOR.read_file(original / "receipt.json", GENERATOR.MAX_RECEIPT_BYTES))
            receipt["batch_id"] = unknown.name
            GENERATOR.write_new(unknown / "receipt.json", receipt)
            with patch.object(GENERATOR, "export_batch") as exported:
                with self.assertRaisesRegex(ValueError, "outside the frozen recipe"):
                    GENERATOR.prepare("schema4-unlisted-pilot", resume=True, **options)
                exported.assert_not_called()


if __name__ == "__main__":
    unittest.main()
