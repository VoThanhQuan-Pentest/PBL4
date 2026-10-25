"""Capture-v2 contract tests; simulated fixtures never establish actual capture."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from app.controlled_trace_export_v2 import digest, export, source_frames
from app.contract import FEATURE_NAMES_V4


ALIAS = "account-" + "a" * 32
START = "2026-10-02T11:01:00Z"
END = "2026-10-02T11:01:30Z"


def save(path, value, *, ndjson=False):
    data = ("".join(json.dumps(row) + "\n" for row in value) if ndjson else json.dumps(value)).encode()
    path.write_bytes(data)
    path.chmod(0o600)
    return data


def fixture(directory, *, auth_failure=False, missing_session=False):
    directory.chmod(0o700)
    common = {"account_alias": ALIAS, "event_sequence": 0, "event_timestamp": START, "event_type": "AUTH",
              "action": "LOGIN", "outcome": "FAILURE" if auth_failure else "SUCCESS", "route_group": "auth",
              "source_ip": "127.0.0.1", "user_agent_family": "FIREFOX"}
    rows = [common]
    family = "OWNED_AUTH_FAILURE_GUESSTEST" if auth_failure else "CONTROLLED_PASSWORD_CHANGE_SEQUENCE"
    label = "OWNED_AUTH_FAILURE" if auth_failure else "UNSCORED_CONTROLLED_SEQUENCE"
    if auth_failure:
        rows = [{**common, "event_sequence": number} for number in range(4)]
    else:
        http = {**common, "event_sequence": 1, "event_timestamp": "2026-10-02T11:01:01Z", "event_type": "HTTP_REQUEST",
                "action": "API_REQUEST", "route_group": "profile", "http_method": "PUT", "http_status": 204,
                "telemetry_contract_version": 3, "endpoint_category": "PROFILE_PASSWORD"}
        if not missing_session:
            http.update(session_pseudonym="b" * 64, session_issued_at=START)
        rows += [http, {**common, "event_sequence": 2, "event_timestamp": "2026-10-02T11:01:01Z", "event_type": "DOMAIN_ACTION",
                        "action": "PASSWORD_CHANGE", "route_group": "account", "source_ip": None, "user_agent_family": None}]
    scenario = {"account_alias": ALIAS, "family": family, "expected_label": label, "observed_event_count": len(rows)}
    if auth_failure:
        scenario.update(attribution_kind="TARGET_ASSOCIATED_UNAUTHENTICATED", authenticated_actor_claimed=False)
    scenarios = {"capture_contract_version": 2, "provenance": "CONTROLLED_OWNED_LOCAL_HTTP",
                 "labels_separate_from_events": True, "scenarios": [scenario]}
    # Include a real-shaped denied stale-token client observation with no server
    # account event. Its existence must not fabricate a session or fourth event.
    ledger = [{"client_attempt_sequence": number, "intended_account_alias": ALIAS, "attempted_at": "2026-10-02T11:01:02Z",
               "attempt_kind": kind, "http_method": method, "route_group": group, "http_status": status,
               "provenance": "CLIENT_OBSERVED_NOT_SERVER_ATTRIBUTION"}
              for number, (kind, method, group, status) in enumerate([
                  ("CSRF_READ", "GET", "auth", 200), ("LOGIN", "POST", "auth", 200), ("CSRF_REFRESH", "GET", "auth", 200),
                  ("CURRENT_SESSION_REQUEST", "PUT", "profile", 204), ("REVOKED_SESSION_ATTEMPT", "GET", "profile", 401)])]
    ledger_file = "client-attempts.ndjson"
    if auth_failure:
        ledger_file = "client-http-attempts.json"
        ledger = {"capture_contract_version": 2, "scope": "OWNED_LOCAL_AUTH_HTTP_CLIENT_OBSERVATIONS", "attempts": [
            {"attempt_sequence": number, "request_timestamp": START, "response_timestamp": START,
             "operation": "CSRF_READ" if number == 0 else "LOGIN_POST", "http_status": 200 if number == 0 else 429 if number == 6 else 401}
            for number in range(7)]}
    raw_events = save(directory / "trace-events.ndjson", rows, ndjson=True)
    raw_scenarios = save(directory / "scenarios.json", scenarios)
    raw_ledger = save(directory / ledger_file, ledger, ndjson=not auth_failure)
    evidence = {"capture_contract_version": 2, "passed": True, "provenance": "CONTROLLED_OWNED_LOCAL_HTTP",
                "source_event_conservation": True, "labels_present_in_event_records": False, "timestamps_rewritten": False,
                "elapsed_window_closure_proven": False, "capture_started_at": START, "capture_finished_at": END,
                "client_ledger_file": ledger_file, "client_request_count": 7 if auth_failure else 5, "event_count": len(rows),
                "event_type_counts": {"AUTH": 4} if auth_failure else {"AUTH": 1, "HTTP_REQUEST": 1, "DOMAIN_ACTION": 1},
                "trace_events_sha256": digest(raw_events), "scenarios_sha256": digest(raw_scenarios), "client_ledger_sha256": digest(raw_ledger)}
    if auth_failure:
        evidence.update(captured_auth_event_count=6, unattributable_auth_outcome_counts={"FAILURE": 1, "RATE_LIMITED": 1}, unattributable_auth_event_count=2)
    save(directory / "capture-evidence.json", evidence)
    return rows, scenarios, evidence


def operational_fixture(directory):
    directory.chmod(0o700)
    auth = {"account_alias": ALIAS, "event_sequence": 0, "event_timestamp": "2026-10-02T11:01:01Z", "event_type": "AUTH",
            "action": "LOGIN", "outcome": "SUCCESS", "route_group": "auth",
            "source_ip": "127.0.0.1", "user_agent_family": "FIREFOX"}
    rows = [auth]
    plan = ["CSRF_READ", "LOGIN"] + ["NORMAL_READ"] * 5 + ["CONTROLLED_FAULT"] * 10 + ["AFTER_FAULT_NORMAL_READ"]
    ledger = []
    for number, kind in enumerate(plan):
        status = 503 if kind == "CONTROLLED_FAULT" else 200
        at = f"2026-10-02T11:01:{number:02d}Z"
        ledger.append({"client_sequence": number, "account_alias": ALIAS, "sent_at": at,
                       "request_kind": kind, "http_method": "POST" if kind == "LOGIN" else "GET",
                       "expected_status": status, "observed_status": status})
        if kind not in {"CSRF_READ", "LOGIN"}:
            rows.append({**auth, "event_sequence": len(rows), "event_timestamp": at, "event_type": "HTTP_REQUEST",
                         "action": "API_REQUEST", "outcome": "FAILURE" if status == 503 else "SUCCESS",
                         "route_group": "other_api" if status == 503 else "products", "http_method": "GET",
                         "http_status": status, "telemetry_contract_version": 3,
                         "endpoint_category": "OTHER_MATCHED" if status == 503 else "PRODUCT_LIST",
                         "session_pseudonym": "b" * 64, "session_issued_at": auth["event_timestamp"]})
    scenarios = {"capture_contract_version": 2, "provenance": "CONTROLLED_OWNED_LOCAL_HTTP",
                 "labels_separate_from_events": True, "scenarios": [{"account_alias": ALIAS,
                 "family": "OPERATIONAL_FAULT", "expected_label": "CONTROLLED_OPERATIONAL_ANOMALY",
                 "observed_event_count": len(rows)}]}
    evidence = {"capture_contract_version": 2, "passed": True, "provenance": "CONTROLLED_OWNED_LOCAL_HTTP",
                "source_event_conservation": True, "labels_present_in_event_records": False,
                "timestamps_rewritten": False, "elapsed_window_closure_proven": False,
                "capture_started_at": START, "capture_finished_at": END,
                "client_ledger_file": "client-ledger.ndjson", "client_request_count": len(ledger),
                "event_count": len(rows), "event_type_counts": {"AUTH": 1, "HTTP_REQUEST": 16},
                "trace_events_sha256": digest(save(directory / "trace-events.ndjson", rows, ndjson=True)),
                "scenarios_sha256": digest(save(directory / "scenarios.json", scenarios)),
                "client_ledger_sha256": digest(save(directory / "client-ledger.ndjson", ledger, ndjson=True))}
    save(directory / "capture-evidence.json", evidence)


def alter(directory, filename, transform, checksum_key=None, *, ndjson=False):
    path = directory / filename
    value = [json.loads(line) for line in path.read_bytes().splitlines()] if ndjson else json.loads(path.read_bytes())
    transform(value)
    data = save(path, value, ndjson=ndjson)
    if checksum_key:
        evidence_path = directory / "capture-evidence.json"
        evidence = json.loads(evidence_path.read_bytes())
        evidence[checksum_key] = digest(data)
        save(evidence_path, evidence)


class CaptureV2Test(unittest.TestCase):
    def test_unscored_sequence_domain_nulls_client_denial_stay_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            original = (root / "trace-events.ndjson").read_bytes()
            frames, expected, attribution, evidence = source_frames(root)
            self.assertEqual(len(frames), 1)
            self.assertEqual(len(frames[0]["events"]), 3)
            self.assertIsNone(frames[0]["events"][2]["source_ip"])
            self.assertEqual(attribution[0]["scenario_label"], "UNSCORED_CONTROLLED_SEQUENCE")
            self.assertFalse(attribution[0]["attack_quality_eligible"])
            self.assertEqual(list(expected.values())[0]["session_count"], 1)
            self.assertEqual(evidence["client_request_count"], 5)
            self.assertEqual((root / "trace-events.ndjson").read_bytes(), original)

    def test_missing_session_is_not_fabricated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root, missing_session=True)
            frames, expected, _, _ = source_frames(root)
            self.assertNotIn("session_pseudonym", frames[0]["events"][1])
            self.assertEqual(list(expected.values())[0]["session_count"], 0)

    def test_failed_auth_has_target_attribution_and_no_http_or_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root, auth_failure=True)
            frames, expected, attribution, _ = source_frames(root)
            self.assertEqual(attribution[0]["attribution_kind"], "TARGET_ASSOCIATED_UNAUTHENTICATED")
            self.assertEqual(list(expected.values())[0]["request_count"], 0)
            self.assertEqual(list(expected.values())[0]["session_count"], 0)
            self.assertEqual(frames[0]["events"][0]["outcome"], "FAILURE")

    def test_source_hashes_and_ledger_population_are_verified(self):
        for filename, mutation in (("trace-events.ndjson", lambda data: data + b"{}\n"),
                                   ("scenarios.json", lambda data: data + b" "),
                                   ("client-attempts.ndjson", lambda data: data + b" ")):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root)
                path = root / filename
                path.write_bytes(mutation(path.read_bytes()))
                with self.assertRaises(ValueError):
                    source_frames(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            alter(root, "capture-evidence.json", lambda value: value.update(client_request_count=2))
            with self.assertRaises(ValueError):
                source_frames(root)

    def test_privacy_future_session_and_missing_pair_refused_with_rebound_hashes(self):
        faults = [lambda rows: rows[1].update(jwt="secret"), lambda rows: rows[1].pop("session_issued_at"),
                  lambda rows: rows[1].update(session_issued_at="2026-10-03T00:00:00Z"),
                  lambda rows: rows[2].update(source_ip="127.0.0.1"),
                  lambda rows: rows[1].update(endpoint_category="RAW_ENDPOINT"),
                  lambda rows: rows[1].update(source_ip="198.51.100.1"),
                  lambda rows: rows[1].update(event_sequence=0)]
        for fault in faults:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root)
                alter(root, "trace-events.ndjson", fault, "trace_events_sha256", ndjson=True)
                with self.assertRaises(ValueError):
                    source_frames(root)

    def test_attack_relabel_and_authenticated_target_claim_refused(self):
        for fault in (lambda value: value["scenarios"][0].update(expected_label="ATTACK"),
                      lambda value: value["scenarios"][0].update(authenticated_actor_claimed=True)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root, auth_failure=True)
                alter(root, "scenarios.json", fault, "scenarios_sha256")
                with self.assertRaises(ValueError):
                    source_frames(root)

    def test_arbitrary_attribution_and_promoted_stale_denial_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            alter(root, "scenarios.json", lambda value: value["scenarios"][0].update(attribution_kind="private-arbitrary-value"), "scenarios_sha256")
            with self.assertRaises(ValueError):
                source_frames(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            alter(root, "trace-events.ndjson", lambda rows: rows[1].update(http_status=401, outcome="FAILURE"), "trace_events_sha256", ndjson=True)
            with self.assertRaises(ValueError):
                source_frames(root)

    def test_client_alias_must_belong_to_separate_scenarios(self):
        for operational in (False, True):
            with self.subTest(operational=operational), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (operational_fixture if operational else fixture)(root)
                filename = "client-ledger.ndjson" if operational else "client-attempts.ndjson"
                key = "account_alias" if operational else "intended_account_alias"
                alter(root, filename, lambda rows: rows[-1].update({key: "account-" + "c" * 32}),
                      "client_ledger_sha256", ndjson=True)
                with self.assertRaisesRegex(ValueError, "client ledger account"):
                    source_frames(root)

    def test_rebound_password_ledger_must_reconcile_each_observed_population(self):
        faults = {
            "http": lambda rows: rows[3].update(http_method="GET", http_status=200),
            "login": lambda rows: rows[1].update(attempt_kind="CSRF_READ", http_method="GET"),
            "csrf": lambda rows: rows[0].update(attempt_kind="LOGIN", http_method="POST"),
            "revoked": lambda rows: rows[4].update(attempt_kind="CURRENT_SESSION_REQUEST", http_status=200),
            "refresh": lambda rows: rows[2].update(attempt_kind="CSRF_READ"),
        }
        for population, fault in faults.items():
            with self.subTest(population=population), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root)
                alter(root, "client-attempts.ndjson", fault, "client_ledger_sha256", ndjson=True)
                with self.assertRaisesRegex(ValueError, "HTTP/AUTH/DOMAIN conservation"):
                    source_frames(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            alter(root, "trace-events.ndjson", lambda rows: rows.pop(), "trace_events_sha256", ndjson=True)
            alter(root, "scenarios.json", lambda value: value["scenarios"][0].update(observed_event_count=2), "scenarios_sha256")
            alter(root, "capture-evidence.json", lambda value: value.update(event_count=2, event_type_counts={"AUTH": 1, "HTTP_REQUEST": 1}))
            with self.assertRaisesRegex(ValueError, "HTTP/AUTH/DOMAIN conservation"):
                source_frames(root)

    def test_operational_fault_preserves_separate_actual_counts_and_nonattack_label(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operational_fixture(root)
            frames, expected, attribution, evidence = source_frames(root)
            self.assertEqual(sum(frame["event_count"] for frame in expected.values()), 17)
            self.assertEqual(sum(frame["request_count"] for frame in expected.values()), 16)
            self.assertEqual(sum(frame["session_count"] for frame in expected.values()), 16)
            self.assertEqual(evidence["client_request_count"], 18)
            self.assertEqual(sum(event.get("http_status") == 503 for frame in frames for event in frame["events"]), 10)
            self.assertEqual(attribution[0]["scenario_label"], "CONTROLLED_OPERATIONAL_ANOMALY")
            self.assertFalse(attribution[0]["attack_quality_eligible"])

    def test_server_and_client_faults_cannot_move_to_resource_probe_family(self):
        for mutate_server in (False, True):
            with self.subTest(mutate_server=mutate_server), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                operational_fixture(root)
                alter(root, "scenarios.json", lambda value: value["scenarios"][0].update(
                    family="OWNED_RESOURCE_PROBE", expected_label="OBSERVATIONAL_AMBIGUOUS"), "scenarios_sha256")
                if mutate_server:
                    alter(root, "trace-events.ndjson", lambda rows: [row.update(http_status=200, outcome="SUCCESS",
                          route_group="products", endpoint_category="PRODUCT_LIST")
                          for row in rows if row.get("http_status") == 503], "trace_events_sha256", ndjson=True)
                message = "service fault" if mutate_server else "503 must remain"
                with self.assertRaisesRegex(ValueError, message):
                    source_frames(root)

    def test_target_only_auth_refuses_success_http_domain_and_session_claims(self):
        faults = (
            (lambda row: row.update(outcome="SUCCESS"), {"AUTH": 4}),
            (lambda row: row.update(event_type="HTTP_REQUEST", action="API_REQUEST", outcome="SUCCESS",
             route_group="profile", http_method="GET", http_status=200, telemetry_contract_version=3,
             endpoint_category="PROFILE_READ", session_pseudonym="b" * 64, session_issued_at=START),
             {"AUTH": 3, "HTTP_REQUEST": 1}),
            (lambda row: row.update(event_type="DOMAIN_ACTION", action="PASSWORD_CHANGE", outcome="SUCCESS",
             route_group="account", source_ip=None, user_agent_family=None), {"AUTH": 3, "DOMAIN_ACTION": 1}),
            (lambda row: row.update(session_pseudonym="b" * 64, session_issued_at=START), {"AUTH": 4}),
        )
        for fault, counts in faults:
            with self.subTest(counts=counts), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root, auth_failure=True)
                alter(root, "trace-events.ndjson", lambda rows: fault(rows[0]), "trace_events_sha256", ndjson=True)
                alter(root, "capture-evidence.json", lambda value: value.update(event_type_counts=counts))
                with self.assertRaises(ValueError):
                    source_frames(root)

    def test_auth_status_histogram_cannot_hide_swapped_csrf_login_responses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root, auth_failure=True)

            def swap_statuses(value):
                value["attempts"][0]["http_status"] = 401
                value["attempts"][1]["http_status"] = 200

            alter(root, "client-http-attempts.json", swap_statuses, "client_ledger_sha256")
            with self.assertRaises(ValueError):
                source_frames(root)

    def test_private_modes_symlinks_and_duplicate_json_fields_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            (root / "trace-events.ndjson").chmod(0o644)
            with self.assertRaises(ValueError):
                source_frames(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            alias = root / "alias.json"
            alias.symlink_to(root / "capture-evidence.json")
            (root / "capture-evidence.json").rename(root / "original-evidence.json")
            (root / "capture-evidence.json").symlink_to(root / "original-evidence.json")
            with self.assertRaises(OSError):
                source_frames(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            path = root / "capture-evidence.json"
            path.write_bytes(b'{"capture_contract_version":2,"capture_contract_version":2}')
            with self.assertRaises(ValueError):
                source_frames(root)

    def test_export_strips_transport_label_and_preserves_unscored_attribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture"
            capture.mkdir()
            fixture(capture)
            frames, _, _, _ = source_frames(capture)
            vector = [0] * 37
            for index in (0, 4, 5, 6, 7, 15, 23, 25, 26, 29, 30, 31, 32, 33):
                vector[index] = 1
            row = {"frame_id": frames[0]["frame_id"], "account_id": ALIAS, "window_start": frames[0]["window_start"],
                   "feature_schema_version": 4, "telemetry_contract_version": 3, "feature_names": list(FEATURE_NAMES_V4),
                   "data_provenance": "DEMO_ONLY", "label": 0, "family": "normal", "features": vector}
            result = subprocess.CompletedProcess([], 0, stdout=(json.dumps(row) + "\n").encode())
            with patch("app.controlled_trace_export_v2.workspace_identity", return_value=("fixed", {"classes": {"test": "bound"}})), \
                    patch("app.controlled_trace_export_v2.subprocess.run", return_value=result):
                evidence = export(capture, root / "workspace", "bound", root / "output")
            numeric = json.loads((root / "output/numeric-unlabelled-captured-windows.private.json").read_bytes())
            self.assertNotIn("label", numeric[0])
            self.assertNotIn("family", numeric[0])
            self.assertEqual(evidence["quality_gate"], "NOT_APPLICABLE")
            self.assertFalse(evidence["client_observations_promoted_to_server_events"])


if __name__ == "__main__":
    unittest.main()
