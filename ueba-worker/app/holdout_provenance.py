"""Metadata-only holdout refusal; no numeric resources or override admission."""
import json
import os
from pathlib import Path
import re
import stat

MARKER = 'holdout-access-audit.private.json'
MAX_AUDIT_BYTES = 32768
FIELDS = {'audit_schema_version', 'status', 'dataset_id', 'affected_split', 'reason',
          'acceptance_allowed', 'audit_id', 'recorded_at_utc'}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate holdout audit field')
        result[key] = value
    return result


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def holdout_audit_resources(dataset_or_path):
    """Only two exact private metadata files are inspected; absence is not trust."""
    value = dataset_or_path if isinstance(dataset_or_path, (str, os.PathLike)) else dataset_or_path.root
    root = Path(value).absolute()
    if '..' in root.parts: raise ValueError('canonical holdout audit root required')
    resources = []
    for directory in (root, root.parent):
        path = directory / MARKER
        try:
            initial = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise ValueError('holdout audit unavailable; acceptance refused') from None
        if (any(parent.is_symlink() for parent in (path, *path.parents))
                or not stat.S_ISREG(initial.st_mode) or initial.st_uid != os.geteuid()
                or stat.S_IMODE(initial.st_mode) != 0o600 or initial.st_nlink != 1
                or not 0 < initial.st_size <= MAX_AUDIT_BYTES):
            raise ValueError('bounded private holdout audit required; acceptance refused')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            held = os.fstat(source.fileno())
            raw = source.read(MAX_AUDIT_BYTES + 1)
            if (_signature(initial) != _signature(held) or len(raw) != held.st_size
                    or _signature(held) != _signature(os.fstat(source.fileno()))
                    or _signature(held) != _signature(path.lstat())):
                raise ValueError('holdout audit changed; acceptance refused')
        try:
            audit = json.loads(raw, object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite holdout audit')))
        except (ValueError, UnicodeError):
            raise ValueError('malformed holdout audit; acceptance refused') from None
        if (type(audit) is not dict or set(audit) != FIELDS
                or type(audit['audit_schema_version']) is not int or audit['audit_schema_version'] != 1
                or audit['status'] != 'BLOCKED' or audit['affected_split'] != 'holdout'
                or audit['acceptance_allowed'] is not False
                or audit['reason'] not in {'INDETERMINATE_HOLDOUT_EXPOSURE', 'CONFIRMED_HOLDOUT_EXPOSURE'}
                or type(audit['dataset_id']) is not str or re.fullmatch(r'[a-z0-9_-]{8,96}', audit['dataset_id']) is None
                or type(audit['audit_id']) is not str or re.fullmatch(r'[a-z0-9_-]{8,96}', audit['audit_id']) is None
                or type(audit['recorded_at_utc']) is not str or not 1 <= len(audit['recorded_at_utc']) <= 64):
            raise ValueError('unsupported holdout audit; acceptance refused')
        resources.append((path, raw))
    return tuple(resources)


def require_unblocked_holdout(dataset_or_path, expected_audit_sha256=None):
    if expected_audit_sha256 is not None:
        if type(expected_audit_sha256) is not str or re.fullmatch(r'[a-f0-9]{64}', expected_audit_sha256) is None:
            raise ValueError('invalid private holdout audit pin; acceptance refused')
        # This format only ever registers BLOCKED audits; absence cannot turn a
        # previously pinned refusal into an acceptance authorization.
        raise ValueError('holdout provenance BLOCKED by private audit pin; acceptance refused')
    if holdout_audit_resources(dataset_or_path):
        raise ValueError('holdout provenance BLOCKED; cannot use affected holdout for acceptance')
