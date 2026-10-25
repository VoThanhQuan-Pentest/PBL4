#!/usr/bin/env python3
"""Observe one human password change; never read the new password or OTP."""
import http.cookiejar
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

from ueba_research_artifacts import publish

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "observability/runtime/local-otp-rollout-20261020-r1"
BASE = "http://localhost:8088"


def database():
    sql = """SELECT auth_version,(email='qvo1312@gmail.com'),(email_verified_at IS NOT NULL)
FROM tbl_nguoi_dung WHERE id='e2e-customer';
SELECT COUNT(*),COALESCE(SUM(password_hash IS NULL AND profile_name IS NULL AND target_email IS NULL AND phone IS NULL),0)
FROM sensitive_action_confirmations WHERE user_id='e2e-customer' AND operation='PASSWORD_CHANGE' AND state='COMMITTED';
"""
    result = subprocess.run(["docker", "exec", "-i", "flare-otp-local-db-1", "sh", "-ceu",
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B'],
        input=sql, capture_output=True, text=True, check=True)
    user, actions = result.stdout.strip().splitlines()
    version, mailbox, verified = map(int, user.split("\t"))
    committed, scrubbed = map(int, actions.split("\t"))
    return dict(auth_version=version, owned_mailbox_unchanged=bool(mailbox),
                contact_verified=bool(verified), committed=committed, scrubbed=scrubbed)


def main():
    cookies = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    def request(method, path, data=None, headers=None):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(BASE + path, data=body, method=method, headers=headers or {})
        try:
            response = client.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read()
            return response.code, json.loads(payload) if payload else None

    status, csrf = request("GET", "/api/auth/csrf")
    assert status == 200
    login_status, _ = request("POST", "/api/auth/login",
        {"username": "e2e_customer", "password": "CustomerE2E#1"},
        {"Content-Type": "application/json", "X-XSRF-TOKEN": csrf["token"], "Origin": BASE})
    assert login_status in (200, 401), "UNEXPECTED_LOGIN_STATUS"
    deadline = time.monotonic() + 300
    while True:
        state = database()
        if state["committed"]:
            assert state == dict(auth_version=2, owned_mailbox_unchanged=True,
                                 contact_verified=True, committed=1, scrubbed=1), "UNEXPECTED_ACCOUNT_TRANSITION"
            session_status = None
            if login_status == 200:
                session_status, _ = request("GET", "/api/auth/me")
                assert session_status == 401, "OLD_SESSION_NOT_REVOKED"
            result = {"status": "LOCAL_PASSWORD_ACTION_COMMITTED", "account_id": "e2e-customer",
                "database": state, "old_session_http_status": session_status,
                "old_session_created_before_mutation": login_status == 200,
                "old_session_probe_scope": "ACTUAL_PRE_MUTATION_SESSION" if login_status == 200 else "UNAVAILABLE_ACTION_ALREADY_COMMITTED",
                "human_entered_password_and_otp": True, "new_password_or_otp_read": False}
            publish(OUTPUT / "password-action-observation.private.json", result)
            print(result["status"])
            return
        if time.monotonic() >= deadline:
            publish(OUTPUT / "password-action-wait.private.json", {
                "status": "WAITING_FOR_HUMAN_PASSWORD_ACTION", "last_database_state": state,
                "site_kept_running": True, "emails_sent_by_observer": 0})
            print("WAITING_FOR_HUMAN_PASSWORD_ACTION")
            return
        time.sleep(5)


if __name__ == "__main__":
    main()
