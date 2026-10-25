"""Causal simulator invariants; simulated fixtures never establish capture/quality."""

from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

from app.contract import FEATURE_NAMES_V4, feature_array
from app.schema4_episodes import (
    AccountProfile, BLIND_SEEDS, COUNTERPARTS, DATA_PROVENANCE, FAMILIES,
    HANDLER_PATTERNS, LEGITIMATE_CAUSES, MAX_EVENTS, PROTOCOL_ANCHOR,
    account_profile, build_scenario, context_frames, make_frame, protocol_document,
)


START = PROTOCOL_ANCHOR + timedelta(days=14)
ROOT = Path(__file__).resolve().parents[2]
JAVA_ROOT = Path(os.environ.get("UEBA_BENCHMARK_WORKSPACE", ROOT))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def timestamp(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def episode(cause="normal", account=0, ordinal=0, cohort="READY"):
    return make_frame("schema4-owned-pilot", account, ordinal, START, planned_cause=cause, cohort=cohort)


class Schema4EpisodeTest(unittest.TestCase):
    def test_frozen_protocol_and_producer_source_binding(self):
        doc = protocol_document()
        self.assertEqual(doc["data_provenance"], DATA_PROVENANCE)
        self.assertEqual(doc["families"], list(FAMILIES))
        self.assertEqual(len(FAMILIES), 5)
        self.assertEqual(doc["blind_seeds"], list(BLIND_SEEDS))
        self.assertEqual(doc["maximum_events_per_frame"], 4096)
        self.assertEqual(doc["baseline_context_windows"], {"READY": 48, "UNSEEN_READY": 48, "COLD": 3})
        self.assertIn("NO_RESULT_BASED_RESELECTION", doc["blind_seed_policy"])
        for relative, checksum in doc["source_sha256"].items():
            self.assertEqual(checksum, hashlib.sha256((ROOT / relative).read_bytes()).hexdigest())
        self.assertEqual(len(doc["handler_patterns"]), len(HANDLER_PATTERNS))
        self.assertEqual(len(doc["endpoint_recipes"]), len(HANDLER_PATTERNS))
        self.assertTrue(all("method" in row for row in doc["endpoint_recipes"]))

    def test_no_label_or_cause_inside_java_feature_input(self):
        for cause in (*LEGITIMATE_CAUSES, *FAMILIES):
            with self.subTest(cause=cause):
                value = episode(cause)
                self.assertEqual(set(value), {"frame", "scenario", "client_ledger", "evidence"})
                frame, scenario = value["frame"], value["scenario"]
                self.assertEqual(set(frame), {"frame_id", "account_id", "day", "cohort", "window_start", "telemetry_contract_version", "events"})
                self.assertEqual(scenario["label"], int(cause in FAMILIES))
                self.assertEqual(scenario["family"], cause if cause in FAMILIES else "normal")
                for event in frame["events"]:
                    self.assertFalse(set(event) & {"label", "family", "planned_cause", "data_provenance", "jwt", "password", "request_path", "user_agent"})
                for identity in (frame["frame_id"], frame["account_id"]):
                    self.assertFalse(any(cause_name in identity for cause_name in (*LEGITIMATE_CAUSES, *FAMILIES)))
                self.assertFalse(value["evidence"]["authentic_capture"])
                self.assertFalse(value["evidence"]["quality_proof"])
                self.assertFalse(value["evidence"]["captured_sources_replayed_or_relabelled"])
                self.assertTrue(value["evidence"]["labels_assigned_before_events"])

    def test_determinism_plan_hash_and_frame_hash(self):
        first, second = episode("sensitive_action_burst", 17, 2), episode("sensitive_action_burst", 17, 2)
        self.assertEqual(first, second)
        checksum = hashlib.sha256(canonical(first["scenario"]["plan"]).encode()).hexdigest()
        self.assertEqual(first["scenario"]["plan_sha256"], checksum)
        self.assertEqual(first["evidence"]["plan_sha256"], checksum)
        self.assertEqual(first["evidence"]["frame_sha256"], hashlib.sha256(canonical(first["frame"]).encode()).hexdigest())
        plan = first["scenario"]["plan"]
        recreated = build_scenario(plan["execution_seed"], account_profile("schema4-owned-pilot", 17),
                                   "sensitive_action_burst", START, account_id=first["frame"]["account_id"], frame_id=first["frame"]["frame_id"])
        self.assertEqual(first, recreated)

    def test_profile_identity_and_nuisance_stream_are_truth_independent(self):
        values = [episode(cause, 31, 11) for cause in ("normal", *FAMILIES)]
        for value in values[1:]:
            for field in ("account_id", "frame_id", "window_start", "cohort"):
                self.assertEqual(value["frame"][field], values[0]["frame"][field])
            for field in ("profile", "capture_mode", "initial_session_age_seconds", "parallel_session", "novel_client"):
                self.assertEqual(value["scenario"]["plan"][field], values[0]["scenario"]["plan"][field])

    def test_explicit_legitimate_counterparts_preserve_exact_observational_ambiguity(self):
        for normal, abnormal in COUNTERPARTS.items():
            if normal == "benign_login_only_retries":
                continue
            for account in (0, 9, 17):
                with self.subTest(normal=normal, account=account):
                    left, right = episode(normal, account), episode(abnormal, account)
                    self.assertEqual(left["frame"], right["frame"])
                    self.assertEqual(left["client_ledger"], right["client_ledger"])
                    self.assertEqual(left["scenario"]["label"], 0)
                    self.assertEqual(right["scenario"]["label"], 1)
                    self.assertNotEqual(left["scenario"]["plan_sha256"], right["scenario"]["plan_sha256"])

    def test_past_only_clean_context_counts_and_shared_account(self):
        for cohort, count in (("READY", 48), ("UNSEEN_READY", 48), ("COLD", 3)):
            values = context_frames("schema4-owned-pilot", 33, START, cohort=cohort)
            self.assertEqual(len(values), count)
            self.assertEqual(values, context_frames("schema4-owned-pilot", 33, START, cohort=cohort))
            starts = [timestamp(value["frame"]["window_start"]) for value in values]
            self.assertEqual(starts, [START - timedelta(hours=count - index) for index in range(count)])
            self.assertEqual(len({value["frame"]["frame_id"] for value in values}), count)
            for value in values:
                self.assertEqual(value["frame"]["account_id"], episode("request_burst", 33, cohort=cohort)["frame"]["account_id"])
                self.assertEqual(value["scenario"]["label"], 0)
                self.assertEqual(value["scenario"]["plan"]["failed_logins"], 0)
                self.assertEqual(value["scenario"]["plan"]["password_changes"], 0)
                self.assertFalse(value["scenario"]["plan"]["novel_client"])
                self.assertTrue(all(event.get("http_status", 200) < 400 for event in value["frame"]["events"]))

    def test_failed_auth_is_target_associated_without_http_session_or_rate_limit_attribution(self):
        for cause, limits in (("auth_failure_burst", (8, 45)), ("benign_retries", (8, 45)), ("benign_login_only_retries", (1, 7))):
            for account in range(8):
                value = episode(cause, account, cohort="COLD")
                events = value["frame"]["events"]
                self.assertTrue(limits[0] <= len(events) <= limits[1])
                self.assertTrue(all(event["event_type"] == "AUTH" and event["outcome"] == "FAILURE" for event in events))
                self.assertEqual(value["scenario"]["attribution_kind"], "TARGET_ASSOCIATED_UNAUTHENTICATED")
                self.assertFalse(value["scenario"]["authenticated_actor_claimed"])
                self.assertEqual(value["evidence"]["observed_request_count"], 0)
                self.assertEqual(value["evidence"]["observed_session_metadata_count"], 0)
                for event in events:
                    self.assertFalse(set(event) & {"http_status", "endpoint_category", "session_pseudonym", "session_issued_at"})
                rate_limits = [row for row in value["client_ledger"] if row["http_status"] == 429]
                self.assertEqual(len(rate_limits), len(events) // 5)
                self.assertTrue(all(row["server_event_indexes"] == [] for row in rate_limits))

    def test_all_accepted_login_attempts_respect_both_default_quotas(self):
        for cause in (*LEGITIMATE_CAUSES, *FAMILIES):
            for account in range(12):
                value = episode(cause, account)
                times = sorted(timestamp(row["attempted_at"]) for row in value["client_ledger"] if row["attempt_kind"] == "LOGIN")
                self.assertTrue(all((times[index] - times[index - 5]).total_seconds() >= 60 for index in range(5, len(times))))
                self.assertTrue(value["evidence"]["per_world_login_quota_checked"])
                self.assertFalse(value["evidence"]["global_deployment_stream_quota_claimed"])

    def test_password_mutations_require_put_revocation_and_relogin(self):
        for cause in ("sensitive_action_burst", "benign_password_maintenance"):
            value = episode(cause, 9)
            events, ledger = value["frame"]["events"], value["client_ledger"]
            domain = [event for event in events if event["event_type"] == "DOMAIN_ACTION"]
            self.assertTrue(5 <= len(domain) <= 25)
            puts = [row for row in ledger if row["attempt_kind"] == "AUTHENTICATED_REQUEST" and row["http_method"] == "PUT"]
            stale = [row for row in ledger if row["attempt_kind"] == "REVOKED_SESSION_ATTEMPT"]
            self.assertEqual(len(puts), len(domain))
            self.assertEqual(len(stale), len(domain))
            self.assertTrue(all(row["http_status"] == 401 and not row["server_event_indexes"] for row in stale))
            for row in puts:
                self.assertEqual(row["handler_pattern"], "/api/profile/password")
                self.assertEqual(len(row["server_event_indexes"]), 2)
                request, action = [events[index] for index in row["server_event_indexes"]]
                self.assertEqual(request["http_status"], 204)
                self.assertEqual(action["action"], "PASSWORD_CHANGE")
                self.assertIsNone(action["source_ip"])
                self.assertIsNone(action["user_agent_family"])
                if "session_pseudonym" in request:
                    revoked = request["session_pseudonym"]
                    # Filter completion may retain the principal/session for
                    # the very PUT whose service revoked it before completion.
                    after = timestamp(request["event_timestamp"])
                    self.assertFalse(any(event.get("session_pseudonym") == revoked and timestamp(event["event_timestamp"]) > after for event in events))
            plan = value["scenario"]["plan"]
            self.assertEqual(value["evidence"]["observed_request_count"], plan["background_requests"] + 2 * len(domain))
            relogins = [row for row in ledger if row["attempt_kind"] == "LOGIN" and row["http_status"] == 200]
            self.assertEqual(len(relogins), plan["successful_logins"] + len(domain))

    def test_csrf_prerequisites_precede_each_password_put_and_login(self):
        value = episode("sensitive_action_burst", 9)
        ledger = sorted(value["client_ledger"], key=lambda row: (timestamp(row["attempted_at"]), row["attempt_sequence"]))
        previous = None
        authenticated_refresh = None
        for row in ledger:
            if row["attempt_kind"] == "CSRF_REFRESH":
                authenticated_refresh = timestamp(row["attempted_at"])
            if row["attempt_kind"] == "LOGIN":
                self.assertEqual(previous["attempt_kind"], "CSRF_READ")
                self.assertLess(timestamp(previous["attempted_at"]), timestamp(row["attempted_at"]))
                if row["http_status"] == 200:
                    authenticated_refresh = None
            if row["http_method"] == "PUT":
                self.assertIsNotNone(authenticated_refresh)
                self.assertLess(authenticated_refresh, timestamp(row["attempted_at"]))
            previous = row

    def test_main_normal_mixture_has_rare_lowcount_login_only_retries(self):
        found = []
        for account in range(200):
            value = episode("normal", account)
            if value["scenario"]["plan"]["execution_recipe"] == "auth_failure_burst":
                found.append(value)
                self.assertTrue(1 <= len(value["frame"]["events"]) <= 7)
                self.assertEqual(value["evidence"]["observed_request_count"], 0)
                self.assertEqual(value["scenario"]["label"], 0)
        self.assertTrue(found)

    def test_transient_operational_errors_are_legitimate_and_not_claimed_attacks(self):
        value = episode("benign_operational_errors", 12)
        self.assertTrue(1 <= value["scenario"]["plan"]["server_errors"] <= 4)
        self.assertEqual(value["scenario"]["label"], 0)
        positive = episode("http_error_burst", 12)
        self.assertEqual(positive["scenario"]["label"], 1)
        self.assertIn("NOT_MALICIOUSNESS", positive["scenario"]["causal_estimand"])

    def test_client_server_population_conservation_and_session_bounds(self):
        for cause in (*LEGITIMATE_CAUSES, *FAMILIES):
            value = episode(cause, 17)
            events = value["frame"]["events"]
            indexes = [index for row in value["client_ledger"] for index in row["server_event_indexes"]]
            self.assertEqual(sorted(indexes), list(range(len(events))))
            for event in events:
                at = timestamp(event["event_timestamp"])
                self.assertTrue(START <= at < START + timedelta(minutes=15))
                self.assertEqual("session_pseudonym" in event, "session_issued_at" in event)
                if "session_pseudonym" in event:
                    self.assertRegex(event["session_pseudonym"], r"^[a-f0-9]{64}$")
                    self.assertTrue(0 <= (at - timestamp(event["session_issued_at"])).total_seconds() < 86400)

    def test_missing_metadata_stays_absent_and_sentinels_have_handler_evidence(self):
        absent = episode("benign_missing_metadata", 11)
        for event in absent["frame"]["events"]:
            self.assertFalse(set(event) & {"endpoint_category", "session_pseudonym", "session_issued_at"})
        seen = set()
        for cause in ("request_burst", "endpoint_scan", "benign_endpoint_traversal"):
            value = episode(cause, 11)
            for row in value["client_ledger"]:
                if row["attempt_kind"] != "AUTHENTICATED_REQUEST":
                    continue
                category = row["server_endpoint_category"]
                if category == "UNMATCHED":
                    self.assertEqual(row["handler_resolution"], "RESOURCE_HANDLER")
                    self.assertEqual(row["http_status"], 404)
                    seen.add(category)
                elif category == "UNRESOLVED":
                    self.assertEqual(row["handler_resolution"], "PRE_MVC_AUTHORIZATION_DENIAL")
                    self.assertEqual(row["http_status"], 403)
                    seen.add(category)
                else:
                    key = row["http_method"], row["route_group"], category
                    self.assertEqual(row["handler_pattern"], HANDLER_PATTERNS[key])
        self.assertEqual(seen, {"UNMATCHED", "UNRESOLVED"})

    def test_family_count_ranges_and_raw_bounds_over_fixed_blind_seeds(self):
        profile = AccountProfile(130, 7, 12, "198.51.100.1", "FIREFOX")
        for seed in BLIND_SEEDS:
            for family in FAMILIES:
                value = build_scenario(seed, profile, family, START)
                plan = value["scenario"]["plan"]
                self.assertTrue(1 <= len(value["frame"]["events"]) <= MAX_EVENTS)
                if family == "request_burst":
                    self.assertTrue(120 <= plan["background_requests"] <= 1600)
                elif family == "endpoint_scan":
                    self.assertTrue(50 <= plan["background_requests"] <= 240)
                elif family == "http_error_burst":
                    self.assertTrue(40 <= plan["background_requests"] <= 240)

    def test_boundary_inputs_refuse_unbounded_or_truth_bearing_data(self):
        profile = account_profile("schema4-owned-pilot", 0)
        for invalid in (-1, True, 2**64, "42"):
            with self.subTest(seed=invalid), self.assertRaises(ValueError):
                build_scenario(invalid, profile, "normal", START)
        for invalid in ("2026-04-15T00:01:00Z", "2026-04-15T00:00:00", "2026-04-15T00:00:00+07:00", "2026-03-31T00:00:00Z", "2026-07-20T00:00:00Z"):
            with self.subTest(start=invalid), self.assertRaises(ValueError):
                build_scenario(42, profile, "normal", invalid)
        for kwargs in ({"planned_cause": "attack"}, {"cohort": "PRODUCTION"}, {"account_id": "auth_failure_burst-account"}, {"frame_id": "normal-frame-id"}, {"context": True, "planned_cause": "request_burst"}):
            values = {"planned_cause": "normal", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                build_scenario(42, profile, window_start=START, **values)
        for kwargs in ({"requests": True}, {"requests": 801}, {"routes": 8}, {"first_hour": 13}, {"ip": "127.0.0.1"}, {"ua": "SCANNER"}):
            values = {"requests": 10, "routes": 2, "first_hour": 0, "ip": "198.51.100.1", "ua": "FIREFOX", **kwargs}
            with self.subTest(profile=kwargs), self.assertRaises(ValueError):
                AccountProfile(**values)
        with self.assertRaises(ValueError):
            context_frames("schema4-owned-pilot", 0, PROTOCOL_ANCHOR)
        with self.assertRaises(ValueError):
            make_frame("schema4-owned-pilot", 0, 1344, START)


@unittest.skipUnless(shutil.which("java") and (JAVA_ROOT / "backend/target/ueba-experiment.classpath").is_file(),
                     "compiled schema4 Java workspace required")
class Schema4EpisodeJavaTest(unittest.TestCase):
    def test_real_java_consumes_label_free_frame_with_only_external_transport_label(self):
        values = context_frames("schema4-java-pilot", 0, START)
        values.append(make_frame("schema4-java-pilot", 0, 0, START, planned_cause="sensitive_action_burst"))
        transport = []
        for value in values:
            frame = {**value["frame"], "demo_label": "ABNORMAL" if value["scenario"]["label"] else "NORMAL", "family": value["scenario"]["family"]}
            transport.append(canonical(frame))
        classpath = str(JAVA_ROOT / "backend/target/classes") + ":" + (JAVA_ROOT / "backend/target/ueba-experiment.classpath").read_text().strip()
        result = subprocess.run(["java", "-Xmx256m", "-cp", classpath, "com.flarefitness.backend.ops.UebaFeatureExport", "--demo-only", "--schema4"],
                                input="\n".join(transport) + "\n", text=True, capture_output=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 49)
        final = rows[-1]
        self.assertEqual(final["feature_names"], list(FEATURE_NAMES_V4))
        self.assertEqual(feature_array([final["features"]], 1, 4).shape, (1, 37))
        self.assertEqual(final["trusted_window_count"], 48)
        self.assertTrue(final["baseline_established"])
        self.assertEqual(final["features"][5], values[-1]["scenario"]["plan"]["password_changes"])
        self.assertTrue(final["data_provenance"] == "DEMO_ONLY")


if __name__ == "__main__":
    unittest.main()
