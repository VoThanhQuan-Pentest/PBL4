#!/usr/bin/env python3
"""Verify TLS/authentication without sending mail or printing SMTP credentials."""
import argparse
import smtplib
import ssl
import time
from pathlib import Path

from postlogin_mail_config import load
from ueba_research_artifacts import commit, private_directory


def run(config, output):
    started = time.monotonic()
    document = {"external_mail_sent": False, "credentials_printed": False}
    try:
        settings = load(config)
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(settings["APP_MAIL_USERNAME"], settings["APP_MAIL_PASSWORD"])
            document.update(status="SMTP_TLS_AUTH_PASS", tls_version=smtp.sock.version())
    except Exception as error:
        document.update(status="SMTP_PREFLIGHT_FAILED", error_type=type(error).__name__)
        if isinstance(error, smtplib.SMTPResponseException):
            document["smtp_status_code"] = error.smtp_code
    document["elapsed_seconds"] = time.monotonic() - started
    proof = commit(output, document, phase="smtp-tls-auth-preflight-v1")
    print({"status": document["status"], "receipt": proof}, flush=True)
    return 0 if document["status"] == "SMTP_TLS_AUTH_PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.config, private_directory(args.output)))
