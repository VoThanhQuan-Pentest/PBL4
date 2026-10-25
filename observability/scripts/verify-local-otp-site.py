#!/usr/bin/env python3
"""Check the selected persistent local account without sending mail or mutating it."""
import hashlib
import http.cookiejar
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

from ueba_research_artifacts import publish

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "observability/runtime/local-otp-rollout-20261020-r1"
BASE = "http://localhost:8088"


def account_digest():
    result = subprocess.run(["docker", "exec", "-i", "flare-otp-local-db-1", "sh", "-ceu",
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B'],
        input="SELECT password,email,email_verified_at,auth_version FROM tbl_nguoi_dung WHERE id='e2e-customer';\n",
        capture_output=True, text=True, check=True)
    if not result.stdout.strip():
        raise RuntimeError("SELECTED_ACCOUNT_MISSING")
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def main():
    cookies = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    def request(method, path, body=None):
        headers = {"Origin": BASE}
        if body is not None:
            csrf_status, csrf = request("GET", "/api/auth/csrf")
            assert csrf_status == 200
            headers.update({"Content-Type": "application/json", "X-XSRF-TOKEN": csrf["token"]})
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
        try:
            response = client.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read()
            return response.code, json.loads(content) if content else None

    status, _ = request("POST", "/api/auth/login", {"username": "e2e_customer", "password": "CustomerE2E#1"})
    assert status == 200, "LOCAL_FIXTURE_LOGIN_FAILED"
    status, profile = request("GET", "/api/profile")
    assert status == 200 and profile["id"] == "e2e-customer" and profile["email"] == "qvo1312@gmail.com"
    status, policy = request("GET", "/api/profile/action-confirmations/policy")
    assert status == 200 and policy["required"] and policy["contact_available"]
    before = account_digest()
    results = {}
    probes = {
        "PASSWORD_CHANGE": ("/api/profile/password", {"current_password": "CustomerE2E#1",
            "new_password": "DeniedLocalProbe#2026", "confirm_password": "DeniedLocalProbe#2026"}),
        "EMAIL_CHANGE": ("/api/profile", {"ho_ten": profile["ho_ten"], "sdt": profile.get("sdt", ""),
            "email": "qvo1312+flare-rollout@gmail.com", "otp_code": ""}),
    }
    for operation, (path, payload) in probes.items():
        status, error = request("PUT", path, payload)
        assert status == 409 and error["code"] == "ACTION_CONFIRMATION_REQUIRED", operation
        assert account_digest() == before, "DENIED_REQUEST_CHANGED_ACCOUNT"
        results[operation] = {"status": status, "code": error["code"], "account_unchanged": True}
    runtime = subprocess.run(["docker", "inspect", "flare-otp-local-app-1"], capture_output=True, text=True, check=True)
    environment = dict(value.split("=", 1) for value in json.loads(runtime.stdout)[0]["Config"]["Env"] if "=" in value)
    assert environment["APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"] == "true"
    assert environment["APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST"] == "e2e-customer"
    receipt = {"status": "LOCAL_OTP_ACTIVATED_BYPASS_CHECKS_PASS", "url": BASE,
        "account_id": "e2e-customer", "username": "e2e_customer", "policy": policy,
        "runtime_allowlist": ["e2e-customer"], "legacy_bypass_probes": results,
        "account_before_after_sha256": before, "emails_sent_by_verifier": 0,
        "sensitive_mutations_by_verifier": 0, "new_fits": 0, "aws_changed": False,
        "positive_website_action_tests": "PENDING_HUMAN_OTP_AND_PASSWORD_ENTRY"}
    publish(OUTPUT / "activation-verification.private.json", receipt)
    print(receipt["status"])


if __name__ == "__main__":
    main()
