#!/usr/bin/env python3
"""Operate the persistent loopback-only OTP site without printing credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

from postlogin_mail_config import load

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "observability/runtime/local-otp-rollout-20261020-r1"
PROJECT = "flare-otp-local"


def private_json(path, document):
    temporary = path.with_suffix(".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(document, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "build", "start", "restart-check", "bootstrap-account", "enable", "status", "stop"])
    args = parser.parse_args()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings_path = STATE / "site-settings.private.json"
    if not settings_path.exists():
        if args.action != "prepare":
            raise RuntimeError("PREPARE_REQUIRED")
        private_json(settings_path, {
            "MYSQL_USER": "flare_local", "MYSQL_PASSWORD": secrets.token_urlsafe(32),
            "MYSQL_ROOT_PASSWORD": secrets.token_urlsafe(32),
            "REDIS_PASSWORD": secrets.token_urlsafe(32), "APP_JWT_SECRET": secrets.token_urlsafe(48),
            "APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED": "false",
        })
    info = settings_path.lstat()
    if settings_path.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError("OWNER_PRIVATE_SITE_SETTINGS_REQUIRED")
    settings = json.loads(settings_path.read_text())
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR")}
    env.update(settings)
    env.update(load("/home/quan/.config/flare-lab/mail.env"))
    env.update(SPRING_DATASOURCE_USERNAME=settings["MYSQL_USER"],
               SPRING_DATASOURCE_PASSWORD=settings["MYSQL_PASSWORD"],
               FLARE_INTERNAL_SUBNET="172.31.90.0/24", MYSQL_HOST_PORT="13307",
               APP_CORS_ALLOWED_ORIGINS="http://localhost:8088,http://127.0.0.1:8088",
               OTP_LOCAL_FLYWAY_IGNORE_MIGRATION_PATTERNS="repeatable:missing",
               APP_SENSITIVE_ACTION_CONFIRMATION_ACCOUNT_ALLOWLIST="e2e-customer")
    command = ["docker", "compose", "--env-file", "/dev/null", "-p", PROJECT,
               "-f", "docker-compose.yml", "-f", "docker-compose.otp-local.yml"]

    def compose(*argv, **kwargs):
        return subprocess.run([*command, *argv], env=env, cwd=ROOT, check=True, **kwargs)

    if args.action == "prepare":
        backup = STATE / "source-database.private.sql"
        if not backup.exists():
            pending_backup = backup.with_suffix(".pending")
            fd = os.open(pending_backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                subprocess.run(["docker", "exec", "flare-local-elk-db-1", "sh", "-ceu",
                    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysqldump --single-transaction --no-tablespaces --skip-lock-tables -u "$MYSQL_USER" "$MYSQL_DATABASE"'],
                    check=True, stdout=stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending_backup, backup)
        marker = STATE / "database-copy.private.json"
        if not marker.exists():
            compose("up", "-d", "--wait", "--wait-timeout", "180", "db", "redis")
            # Never import over a nonempty destination, including a partial prior import.
            query = compose("exec", "-T", "db", "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()"',
                capture_output=True, text=True)
            if query.stdout.strip() != "0":
                raise RuntimeError("DESTINATION_NOT_EMPTY_REFUSE_REIMPORT")
            with backup.open("rb") as stream:
                compose("exec", "-T", "db", "sh", "-ceu",
                    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"', stdin=stream)
            private_json(marker, {"source": "flare-local-elk-db-1", "project": PROJECT,
                                  "original_database_modified": False, "copy_complete": True})
        print("LOCAL_DATABASE_COPY_READY")
    elif args.action == "build":
        compose("build", "app", "nginx")
    elif args.action == "restart-check":
        if settings["APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"] != "true":
            raise RuntimeError("RESTART_CHECK_REQUIRES_ENABLED_POLICY")

        def persisted_digest():
            sql = ("SELECT id,password,email,email_verified_at,auth_version FROM tbl_nguoi_dung "
                   "WHERE id='e2e-customer'; SELECT id,operation,state,password_hash,profile_name,"
                   "target_email,phone,completed_at FROM sensitive_action_confirmations "
                   "WHERE user_id='e2e-customer' ORDER BY id;\n")
            result = compose("exec", "-T", "db", "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B',
                input=sql, capture_output=True, text=True)
            if not result.stdout.strip():
                raise RuntimeError("ACCOUNT_MISSING_FOR_RESTART_CHECK")
            return hashlib.sha256(result.stdout.encode()).hexdigest()

        before = persisted_digest()
        compose("stop", "app", "nginx", "db", "redis")
        compose("up", "-d", "--wait", "--wait-timeout", "180", "db", "redis")
        compose("up", "-d", "--wait", "--wait-timeout", "240", "app", "nginx")
        if persisted_digest() != before:
            raise RuntimeError("ACCOUNT_OR_ACTIONS_CHANGED_ACROSS_RESTART")
        private_json(STATE / "restart-verification.private.json", {
            "status": "LOCAL_STACK_RESTART_PERSISTENCE_PASS", "account_id": "e2e-customer",
            "account_and_actions_before_after_sha256": before, "policy_enabled": True,
            "restarted_services": ["app", "nginx", "db", "redis"], "aws_changed": False,
            "proof_scope": "GRACEFUL_RESTART_NOT_POWER_LOSS_OR_SIGKILL"})
        print("LOCAL_STACK_RESTART_PERSISTENCE_PASS")
    elif args.action == "bootstrap-account":
        marker = STATE / "test-account-bootstrap.private.json"
        if marker.exists() or settings["APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"] != "false":
            raise RuntimeError("TEST_ACCOUNT_BOOTSTRAP_NOT_REPEATABLE")
        seed = (ROOT / "backend/src/main/resources/db/seed/e2e/R__e2e_fixture_data.sql").read_text()
        encoded = re.search(r"\('e2e-customer', 'e2e_customer', '([^']+)'", seed).group(1)
        if not re.fullmatch(r"\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}", encoded):
            raise RuntimeError("EXPECTED_PUBLIC_TEST_FIXTURE_HASH_REQUIRED")
        sql = ("UPDATE tbl_nguoi_dung SET password='" + encoded + "',auth_version=auth_version+1 "
               "WHERE id='e2e-customer' AND username='e2e_customer' AND role='customer' "
               "AND email='customer.e2e@flarefitness.test' AND email_verified_at IS NULL AND is_deleted=0; "
               "SELECT ROW_COUNT();\n")
        result = compose("exec", "-T", "db", "sh", "-ceu",
            'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B',
            input=sql, capture_output=True, text=True)
        if result.stdout.strip() != "1":
            raise RuntimeError("UNVERIFIED_TEST_ACCOUNT_GUARD_REJECTED")
        private_json(marker, {"account_id": "e2e-customer", "source": "VERSIONED_PUBLIC_E2E_FIXTURE",
                              "scope": PROJECT, "original_database_modified": False})
        print("ISOLATED_TEST_ACCOUNT_INITIALIZED")
    elif args.action in ("start", "enable"):
        # This copy retains the historical E2E seed receipt, but never loads the
        # seed profile again (it would overwrite the chosen account on restart).
        # Versioned schema migrations still validate normally. Refuse any other
        # unresolved repeatable before using the local-only missing-seed exception.
        seeds = compose("exec", "-T", "db", "sh", "-ceu",
            'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B -e "SELECT DISTINCT description FROM flyway_schema_history WHERE version IS NULL AND success=1"',
            capture_output=True, text=True)
        if seeds.stdout.strip() != "e2e fixture data":
            raise RuntimeError("UNEXPECTED_REPEATABLE_HISTORY_REFUSE_IGNORE")
        if args.action == "enable":
            proof = compose("exec", "-T", "db", "sh", "-ceu",
                'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE" -N -B -e "SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id=\'e2e-customer\' AND email=\'qvo1312@gmail.com\' AND email_verified_at IS NOT NULL AND is_deleted=0"',
                capture_output=True, text=True)
            if proof.stdout.strip() != "1":
                raise RuntimeError("CURRENT_MAILBOX_NOT_VERIFIED_VIA_APPLICATION")
            from postlogin_action_lab_gate import checked
            gate = checked(ROOT / "observability/runtime/postlogin-risk-context-20261020-r1", "lab-action-gate-result-v1")
            if gate["status"] != "LAB_ACTION_GATE_PASS":
                raise RuntimeError("LAB_GATE_REQUIRED")
            settings["APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"] = "true"
            private_json(settings_path, settings)
            env["APP_SENSITIVE_ACTION_CONFIRMATION_ENABLED"] = "true"
        compose("up", "-d", "--wait", "--wait-timeout", "240", "app", "nginx")
        print("LOCAL_SITE_READY http://localhost:8088")
    elif args.action == "status":
        compose("ps")
    else:
        compose("stop")


if __name__ == "__main__":
    main()
