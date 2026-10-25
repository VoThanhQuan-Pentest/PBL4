#!/usr/bin/env python3
"""Emit deterministic, local-only SQL for clearly labelled UEBA demo data.

This program only writes SQL to stdout. The guarded local-lab wrapper owns the
database connection; no production credentials or endpoint live here.
"""

from __future__ import annotations

import argparse
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone


NAMESPACE = uuid.UUID("65651336-ff66-43a7-90cd-2168df8a4a0e")
DATASET_RE = re.compile(r"[a-z0-9][a-z0-9_-]{3,23}\Z")
HASH_RE = re.compile(r"\{bcrypt-sha256\}\$2[aby]\$12\$[./A-Za-z0-9]{53}\Z")


def quote(value: str | None) -> str:
    if value is None:
        return "NULL"
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def stable_id(*parts: object) -> str:
    return str(uuid.uuid5(NAMESPACE, ":".join(map(str, parts))))


def account_id(dataset: str, index: int) -> str:
    return f"ueba-demo-{dataset}-{index}"


def emit_user(dataset: str, index: int, password_hash: str, now: datetime) -> None:
    identifier = account_id(dataset, index)
    username = f"ueba_demo_{dataset}_{index}"
    phone_suffix = int(stable_id(dataset, "phone", index).replace("-", "")[:10], 16) % 10_000_000
    phone = f"098{phone_suffix:07d}"
    email = f"{username}@example.test"
    print("INSERT IGNORE INTO tbl_nguoi_dung "
          "(id, username, password, role, ho_ten, email, trang_thai, is_deleted, auth_version, ngay_tao) "
          "VALUES (" + ", ".join(map(quote, [identifier, username, password_hash, "Khach hang",
                                f"UEBA demo customer {index}", email, "Hoat dong"]))
          + f", 0, 0, {quote(stamp(now))});")
    print("INSERT IGNORE INTO tbl_khach_hang "
          "(id, user_id, ten_khach, sdt, email, kenh, nhan, ngay_tao) VALUES ("
          + ", ".join(map(quote, [f"ueba-demo-customer-{dataset}-{index}", identifier,
                                 f"UEBA demo customer {index}", phone, email, "Demo", "Synthetic",
                                 stamp(now)])) + ");")


def emit_event(dataset: str, mode: str, account: int, index: int, when: datetime,
               actor: str | None, target: str | None, ip: str, event_type: str,
               action: str, outcome: str, route: str | None, status: int | None,
               agent: str) -> None:
    identifier = stable_id(dataset, mode, account, index)
    fields = [identifier, stamp(when), actor, target, ip, event_type, action, outcome,
              route, "GET" if status is not None else None,
              str(status) if status is not None else None, agent,
              "NORMAL" if mode == "normal" else "ABNORMAL", stamp(when)]
    values = [quote(value) if field != 10 or value is None else value
              for field, value in enumerate(fields)]
    print("INSERT IGNORE INTO siem_security_events "
          "(id, event_timestamp, actor_user_id, target_user_id, source_ip, event_type, "
          "action, outcome, route_group, http_method, http_status, user_agent_family, demo_label, ngay_tao) "
          "VALUES (" + ", ".join(values) + ");")


def emit_normal(dataset: str, password_hash: str | list[str], now: datetime) -> None:
    base = now.replace(minute=0, second=0, microsecond=0) - timedelta(days=5)
    for account in range(1, 5):
        emit_user(dataset, account, password_hash if isinstance(password_hash, str) else password_hash[account - 1], now)
    for window in range(240):
        when = base + timedelta(minutes=15 * window)
        for account in range(1, 5):
            identifier = account_id(dataset, account)
            request_count = 1 + (window + account) % 4
            for request in range(request_count):
                status = 404 if window % 17 == 0 and request == 0 else 200
                emit_event(dataset, "normal", account, window * 10 + request,
                           when + timedelta(seconds=request), identifier, None,
                           f"198.51.100.{10 + account}", "HTTP_REQUEST", "API_REQUEST",
                           "FAILURE" if status >= 400 else "SUCCESS",
                           "orders" if request % 3 == 0 else "products", status, "CHROMIUM")
            if window % 11 == 0:
                emit_event(dataset, "normal", account, window * 10 + 8,
                           when + timedelta(seconds=8), identifier, identifier,
                           f"198.51.100.{10 + account}", "AUTH", "LOGIN", "SUCCESS",
                           "auth", None, "CHROMIUM")
            if window % 23 == 0:
                emit_event(dataset, "normal", account, window * 10 + 9,
                           when + timedelta(seconds=9), None, identifier,
                           f"198.51.100.{10 + account}", "AUTH", "LOGIN", "FAILURE",
                           "auth", None, "CHROMIUM")


def emit_abnormal(dataset: str, now: datetime) -> None:
    base = (now - timedelta(hours=1)).replace(
        minute=((now - timedelta(hours=1)).minute // 15) * 15,
        second=0, microsecond=0)
    target = account_id(dataset, 1)
    for index in range(130):
        status = 403 if index < 11 else 200
        emit_event(dataset, "abnormal", 1, index, base + timedelta(seconds=index),
                   target, None, "203.0.113.55", "HTTP_REQUEST", "API_REQUEST",
                   "FAILURE" if status >= 400 else "SUCCESS", "profile", status, "FIREFOX")
    for index in range(6):
        emit_event(dataset, "abnormal", 1, 130 + index, base + timedelta(minutes=5, seconds=index),
                   None, target, "203.0.113.55", "AUTH", "LOGIN", "FAILURE",
                   "auth", None, "FIREFOX")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("normal", "abnormal"))
    parser.add_argument("--dataset-id", default="ueba-" + datetime.now(timezone.utc).strftime("%Y%m%d"))
    parser.add_argument("--password-hash", help="bcrypt-sha256 hash for synthetic customer accounts")
    parser.add_argument("--now", help="fixed UTC instant for deterministic contract tests")
    args = parser.parse_args()
    if not DATASET_RE.fullmatch(args.dataset_id):
        parser.error("dataset ID must be 4-24 lowercase ASCII letters, digits, hyphens or underscores")
    if args.mode == "normal" and (not args.password_hash or not HASH_RE.fullmatch(args.password_hash)):
        parser.error("normal mode requires a valid bcrypt-sha256 demo password hash")
    try:
        now = datetime.fromisoformat(args.now.replace("Z", "+00:00")) if args.now else datetime.now(timezone.utc)
    except ValueError:
        parser.error("--now must be an ISO-8601 instant")
    if now.tzinfo is None:
        parser.error("--now must include a UTC offset")
    now = now.astimezone(timezone.utc)
    print("START TRANSACTION;")
    if args.mode == "normal":
        emit_normal(args.dataset_id, args.password_hash, now)
    else:
        emit_abnormal(args.dataset_id, now)
    print("COMMIT;")
    print(f"Generated {args.mode} UEBA demo SQL for {args.dataset_id}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
