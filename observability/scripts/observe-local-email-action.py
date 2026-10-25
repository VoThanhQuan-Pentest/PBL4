#!/usr/bin/env python3
"""Observe the human storefront email change without reading either OTP."""
import json
from pathlib import Path
import subprocess
import time

from ueba_research_artifacts import publish

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "observability/runtime/local-otp-rollout-20261020-r1"


def query(sql):
    result = subprocess.run(["docker", "exec", "-i", "flare-otp-local-db-1", "sh", "-ceu",
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B'],
        input=sql, capture_output=True, text=True, check=True)
    return [row.split("\t") for row in result.stdout.strip().splitlines()]


def main():
    baseline_path = OUTPUT / "email-action-baseline.private.json"
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text())
    else:
        row, = query("SELECT SHA2(password,256),auth_version,(email='qvo1312@gmail.com'),"
            "(email_verified_at IS NOT NULL) FROM tbl_nguoi_dung WHERE id='e2e-customer';\n")
        if row[1:] == ["2", "1", "1"]:
            baseline = {"password_hash_digest": row[0], "auth_version": 2}
            publish(baseline_path, baseline)
        else:
            # A human can finish before this observer starts. Never turn the
            # post-commit password digest into a purported pre-commit snapshot.
            baseline = None
    deadline = time.monotonic() + 300
    while True:
        row, = query("SELECT COUNT(*),COALESCE(SUM(password_hash IS NULL AND profile_name IS NULL "
            "AND target_email IS NULL AND phone IS NULL AND completed_at<=expires_at "
            "AND auth_version=2 AND contact_email='qvo1312@gmail.com' "
            "AND policy_id='email-otp-every-sensitive-action-v1' AND LENGTH(session_pseudonym)>0),0) "
            "FROM sensitive_action_confirmations WHERE user_id='e2e-customer' "
            "AND operation='EMAIL_CHANGE' AND state='COMMITTED';\n")
        if int(row[0]):
            assert row == ["1", "1"], "EMAIL_ACTION_NOT_SINGLE_BOUND_SCRUBBED_COMMIT"
            user, = query("SELECT SHA2(password,256),auth_version,"
                "(email='qvo1312+flare-rollout@gmail.com'),(email_verified_at IS NOT NULL) "
                "FROM tbl_nguoi_dung WHERE id='e2e-customer';\n")
            assert user[1:] == ["2", "1", "1"], "UNEXPECTED_EMAIL_TRANSITION"
            if baseline is not None:
                assert user[0] == baseline["password_hash_digest"], "PASSWORD_CHANGED_WITH_EMAIL"
            publish(OUTPUT / "email-action-observation.private.json", {
                "status": "LOCAL_EMAIL_ACTION_COMMITTED", "account_id": "e2e-customer",
                "target": "qvo1312+flare-rollout@gmail.com", "contact_verified": True,
                "committed_count": 1, "bound_and_scrubbed_count": 1,
                "auth_version_after": 2,
                "password_unchanged_measured": True if baseline is not None else None,
                "pre_email_snapshot_available": baseline is not None, "otp_read_by_observer": False,
                "human_entered_both_codes": True})
            print("LOCAL_EMAIL_ACTION_COMMITTED")
            return
        if time.monotonic() >= deadline:
            publish(OUTPUT / "email-action-wait.private.json", {
                "status": "WAITING_FOR_HUMAN_EMAIL_ACTION", "site_kept_running": True})
            print("WAITING_FOR_HUMAN_EMAIL_ACTION")
            return
        time.sleep(5)


if __name__ == "__main__":
    main()
