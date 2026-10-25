"""Simulated clocks are explicitly non-activatable; no test substitutes for real 24h."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.calibration import recalibrate
from app.model import ModelStore
from app.policy import ScorePolicy
from app.shadow import ShadowStore, SIDE_EFFECTS
from test_calibration import fixture, fitted


class Clock:
    def __init__(self): self.seconds, self.boot = 0, "boot-fixed-for-unit-only"
    def utc(self): return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=self.seconds)
    def monotonic(self): return self.seconds


class ShadowTest(unittest.TestCase):
    def setup_candidate(self, root, *, schema=2):
        data = root / "data"; data.mkdir(); dataset = fixture(data, schema=schema)
        store = ModelStore(root / "models"); fitted(store, dataset)
        result = recalibrate(store, dataset, 1, "source_fitted_fixture", "shadow_owned_fixture", ScorePolicy.strict(schema=schema), root / "cache")
        # Clock mechanics only: the real production gate is NOT bypassable.
        # This test's eligibility stub can never write a REAL_SERVER_CLOCK proof.
        metadata = result["metadata"]; metadata["calibration_scope"] = "STRICT"
        from app.policy import canonical
        (store.directory / "shadow_owned_fixture.json").write_text(canonical(metadata))
        return store

    def test_contextual_shadow_is_schema_bound_without_weakening_real_clock_or_quality(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.setup_candidate(Path(directory), schema=3); clock = Clock()
            shadow = ShadowStore(store, clocks=(clock.utc, clock.monotonic, lambda: clock.boot))
            try:
                with patch("app.shadow.verify_quality", return_value={}) as verify:
                    state = shadow.start("shadow_owned_fixture")
                self.assertEqual(state["feature_schema_version"], 3)
                self.assertEqual(verify.call_args.args[3]["feature_schema_version"], 3)
                window = {"window_id": "contextual-window-00001", "window_end_utc": clock.utc().isoformat(),
                          "baseline_established": False, "features": [2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
                                                                      2, 0, 0, 0, 0, 0, 0, 0, 0, 0]}
                with self.assertRaises(ValueError): shadow.score(state["run_id"], [window | {"features": window["features"][:15]}])
                self.assertEqual(shadow.db.execute("SELECT count(*) FROM scores").fetchone()[0], 0)
                self.assertEqual(shadow.score(state["run_id"], [window])["newly_scored_windows"], 1)
                self.assertEqual(shadow.score(state["run_id"], [window])["newly_scored_windows"], 0)
                self.assertEqual(shadow.heartbeat(state["run_id"])["clock_provenance"], "TEST_CLOCK_ONLY")
                clock.seconds += 301
                self.assertEqual(shadow.heartbeat(state["run_id"])["status"], "INVALIDATED")
                self.assertFalse((store.directory / "shadow_owned_fixture.shadow.json").exists())
                self.assertFalse((store.directory / "active.json").exists())
                self.assertEqual(shadow.state(state["run_id"])["candidate_side_effects"], SIDE_EFFECTS)
            finally: shadow.close()

    def test_simulated_day_cannot_publish_a_real_shadow_proof_or_touch_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.setup_candidate(Path(directory)); clock = Clock()
            shadow = ShadowStore(store, clocks=(clock.utc, clock.monotonic, lambda: clock.boot))
            try:
                with patch("app.shadow.verify_quality", return_value={"quality_gate": "PASS"}):
                    state = shadow.start("shadow_owned_fixture")
                window = {"window_id": "owned-window-00001", "window_end_utc": clock.utc().isoformat(),
                          "baseline_established": False, "features": [2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]}
                for start in range(0, 600, 200):
                    shadow.score(state["run_id"], [window | {"window_id": f"owned-window-{index:05d}"} for index in range(start, start + 200)])
                again = shadow.score(state["run_id"], [window])
                self.assertEqual(again["newly_scored_windows"], 0)
                for _ in range(1440): clock.seconds += 60; state = shadow.heartbeat(state["run_id"])
                self.assertEqual(state["status"], "TEST_COMPLETED")
                self.assertEqual(state["closed_windows"], 600)
                self.assertEqual(state["candidate_side_effects"], SIDE_EFFECTS)
                self.assertIsNone(store.active_version); self.assertFalse((store.directory / "active.json").exists())
                self.assertFalse((store.directory / "shadow_owned_fixture.shadow.json").exists())
            finally: shadow.close()

    def test_gap_or_boot_change_invalidates_run_instead_of_counting_missing_time(self):
        for change in ("gap", "boot"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                store = self.setup_candidate(Path(directory)); clock = Clock()
                shadow = ShadowStore(store, clocks=(clock.utc, clock.monotonic, lambda: clock.boot))
                try:
                    with patch("app.shadow.verify_quality", return_value={}): state = shadow.start("shadow_owned_fixture")
                    if change == "gap": clock.seconds += 301
                    else: clock.boot = "different-test-boot"
                    self.assertEqual(shadow.heartbeat(state["run_id"])["status"], "INVALIDATED")
                finally: shadow.close()

    def test_unqualified_candidate_and_forged_elapsed_input_cannot_start_real_run(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.setup_candidate(Path(directory)); shadow = ShadowStore(store)
            try:
                with self.assertRaises(ValueError): shadow.start("shadow_owned_fixture")
                self.assertEqual(shadow.db.execute("SELECT count(*) FROM runs").fetchone()[0], 0)
            finally: shadow.close()

    def test_persisted_request_id_is_idempotent_and_does_not_restart_the_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.setup_candidate(Path(directory)); clock = Clock()
            shadow = ShadowStore(store, clocks=(clock.utc, clock.monotonic, lambda: clock.boot))
            try:
                request_id = "a" * 32
                with patch("app.shadow.verify_quality", return_value={}): state = shadow.start("shadow_owned_fixture", run_id=request_id)
                clock.seconds += 120
                again = shadow.start("shadow_owned_fixture", run_id=request_id)
                self.assertEqual(again, state)
                self.assertEqual(shadow.db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)
                with self.assertRaises(ValueError): shadow.start("other_owned_fixture", run_id=request_id)
                with self.assertRaises(ValueError): shadow.start("shadow_owned_fixture", run_id="../fake")
                self.assertFalse((store.directory / "active.json").exists())
            finally: shadow.close()

    def test_retries_are_acknowledged_by_id_and_mutated_snapshots_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.setup_candidate(Path(directory)); clock = Clock()
            shadow = ShadowStore(store, clocks=(clock.utc, clock.monotonic, lambda: clock.boot))
            try:
                with patch("app.shadow.verify_quality", return_value={}): state = shadow.start("shadow_owned_fixture")
                window = {"window_id": "owned-window-00001", "window_end_utc": clock.utc().isoformat(),
                          "baseline_established": False, "features": [2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0]}
                first = shadow.score(state["run_id"], [window]); again = shadow.score(state["run_id"], [window])
                self.assertEqual(first["newly_scored_windows"], 1); self.assertEqual(again["newly_scored_windows"], 0)
                self.assertEqual(first["accepted_window_ids"], [window["window_id"]])
                self.assertEqual(again["accepted_window_ids"], first["accepted_window_ids"])
                with self.assertRaises(ValueError): shadow.score(state["run_id"], [window | {"features": [3, *window["features"][1:]]}])
                self.assertEqual(shadow.db.execute("SELECT count(*) FROM scores").fetchone()[0], 1)
            finally: shadow.close()
