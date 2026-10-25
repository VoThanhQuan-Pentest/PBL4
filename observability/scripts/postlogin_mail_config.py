"""Load only literal owner-private lab mail settings; never shell-source a file."""
import os
from pathlib import Path
import re
import stat

KEYS = {"APP_MAIL_USERNAME", "APP_MAIL_PASSWORD", "APP_MAIL_FROM", "SPRING_MAIL_HOST", "SPRING_MAIL_PORT"}


def load(path):
    path = Path(path).absolute()
    for ancestor in [*path.parents, path]:
        if ancestor.is_symlink():
            raise ValueError("MAIL_CONFIG_SYMLINK_REFUSED")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 8192:
            raise ValueError("MAIL_CONFIG_OWNER_PRIVATE_BOUNDED_FILE_REQUIRED")
        values = {}
        for line in stream:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if separator != "=" or key not in KEYS or key in values:
                raise ValueError("MAIL_CONFIG_ONLY_UNIQUE_ALLOWLISTED_ASSIGNMENTS_ALLOWED")
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if not value or any(x in value for x in ("\r", "\n", "\x00", "`", "$")):
                raise ValueError("MAIL_CONFIG_LITERAL_NONEMPTY_VALUES_REQUIRED")
            values[key] = value
    if not {"APP_MAIL_USERNAME", "APP_MAIL_PASSWORD", "APP_MAIL_FROM"} <= values.keys():
        raise ValueError("MAIL_CONFIG_REQUIRED_KEYS_MISSING")
    if not re.fullmatch(r"[a-zA-Z0-9._%+-]+@gmail\.com", values["APP_MAIL_USERNAME"]):
        raise ValueError("MAIL_CONFIG_THIS_LAB_USES_GMAIL_ONLY")
    if values["APP_MAIL_FROM"].lower() != values["APP_MAIL_USERNAME"].lower():
        raise ValueError("MAIL_CONFIG_FROM_MUST_MATCH_AUTHENTICATED_SENDER")
    if values.get("SPRING_MAIL_HOST", "smtp.gmail.com") != "smtp.gmail.com" or values.get("SPRING_MAIL_PORT", "587") != "587":
        raise ValueError("MAIL_CONFIG_EXPECTED_GMAIL_STARTTLS_ENDPOINT")
    if values["APP_MAIL_PASSWORD"] in ("THAY_BANG_APP_PASSWORD", "THAY_BANG_MA_16_KY_TU"):
        raise ValueError("MAIL_CONFIG_PLACEHOLDER_NOT_REPLACED")
    return {**values, "SPRING_MAIL_HOST": "smtp.gmail.com", "SPRING_MAIL_PORT": "587"}
