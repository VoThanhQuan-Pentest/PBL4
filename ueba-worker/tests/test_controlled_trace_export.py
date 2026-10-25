"""Sanitized capture adapter contracts; no source rewrite or quality proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from app.controlled_trace_export import source_frames


def fixture(root, *, fault=None):
    alias = "owned-capture-account"; at = "2026-10-02T11:01:00Z"
    auth = {"account_alias": alias, "event_sequence": 0, "event_timestamp": at, "event_type": "AUTH",
            "action": "LOGIN", "outcome": "SUCCESS", "source_ip": "127.0.0.1", "route_group": "auth", "user_agent_family": "OTHER"}
    http = {**auth, "event_sequence": 1, "event_timestamp": "2026-10-02T11:01:01Z", "event_type": "HTTP_REQUEST",
            "action": "API_REQUEST", "route_group": "products", "http_method": "GET", "http_status": 200,
            "telemetry_contract_version": 3, "endpoint_category": "PRODUCT_LIST", "session_pseudonym": "a" * 64,
            "session_issued_at": "2026-10-02T11:00:30Z"}
    rows = [auth, http]
    if fault: fault(rows)
    raw = b"".join((json.dumps(value) + "\n").encode() for value in rows)
    (root / "trace-events.ndjson").write_bytes(raw)
    scenarios = {"scenarios": [{"account_alias": alias, "expected_label": "BENIGN", "observed_event_count": 2}]}
    scenario_bytes = json.dumps(scenarios).encode(); (root / "scenarios.json").write_bytes(scenario_bytes)
    evidence = {"passed": True, "provenance": "CONTROLLED_OWNED_LOCAL_HTTP", "source_event_conservation": True,
                "labels_present_in_event_records": False, "event_count": 2, "http_request_count": 1, "successful_login_count": 1,
                "capture_started_at": at, "capture_finished_at": "2026-10-02T11:01:02Z",
                "trace_events_sha256": hashlib.sha256(raw).hexdigest(), "scenarios_sha256": hashlib.sha256(scenario_bytes).hexdigest()}
    (root / "capture-evidence.json").write_text(json.dumps(evidence))
    return raw


class ControlledTraceExportTest(unittest.TestCase):
    def test_actual_timestamps_labels_and_auth_http_population_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = fixture(root)
            frames, expected, evidence = source_frames(root)
            self.assertEqual(len(frames), 1); self.assertEqual(list(expected.values()), [1])
            self.assertEqual(frames[0]["window_start"], "2026-10-02T11:00:00Z")
            self.assertEqual(frames[0]["events"][0]["event_timestamp"], "2026-10-02T11:01:00Z")
            self.assertEqual(frames[0]["events"][1]["session_issued_at"], "2026-10-02T11:00:30Z")
            self.assertNotIn("telemetry_contract_version", frames[0]["events"][1])
            self.assertEqual(frames[0]["telemetry_contract_version"], 3)
            self.assertEqual(evidence["event_count"], 2); self.assertEqual((root / "trace-events.ndjson").read_bytes(), original)

    def test_private_fields_future_sessions_foreign_ip_and_duplicate_sequence_refused_even_with_updated_hash(self):
        faults = (lambda rows: rows[1].update(token="must-not-export"),
                  lambda rows: rows[1].update(session_verified=True),
                  lambda rows: rows[1].update(session_issued_at="2026-10-02T12:00:00Z"),
                  lambda rows: rows[1].update(source_ip="198.51.100.1"),
                  lambda rows: rows[1].update(event_sequence=0))
        for fault in faults:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); fixture(root, fault=fault)
                with self.assertRaises(ValueError): source_frames(root)

    def test_source_tampering_missing_records_and_unreviewed_scenarios_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            path = root / "trace-events.ndjson"; path.write_bytes(path.read_bytes() + b"{}\n")
            with self.assertRaises(ValueError): source_frames(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fixture(root)
            path = root / "capture-evidence.json"; evidence = json.loads(path.read_text()); evidence["event_count"] = 999
            path.write_text(json.dumps(evidence))
            with self.assertRaises(ValueError): source_frames(root)


if __name__ == "__main__": unittest.main()
