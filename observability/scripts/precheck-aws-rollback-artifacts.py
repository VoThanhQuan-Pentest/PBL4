#!/usr/bin/env python3
"""Read-only integrity precheck of a supplied private AWS rollback checkpoint.

This does not discover or authenticate AWS origin, unpack/load executable artifacts,
call Docker/AWS, restore a database, or prove an old version-34 application can start on schema 36.
It always leaves release_ready false. Exit 0 means only every required artifact hash
and local file protection matched the supplied manifest; exit 1 means incomplete or
failed artifact checks; exit 2 means invalid input. Supply trusted checkpoint hashes,
not freshly computed hashes of an untrusted replacement.

Manifest format AWS_ROLLBACK_ARTIFACTS_V1: source_environment="AWS",
source_schema_version="27", target_schema_version="36", artifacts={role: {
path: "relative/private/file", sha256: "lowercase SHA-256", source_environment:
"AWS", image_id: "sha256:..." (image roles only)}}. Required roles are declared below.
The complete worker data archive must include the original models AND calibrations;
hashing that archive alone does not inspect or prove its semantic completeness.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
PRIVATE_ROOT = ROOT / 'observability/runtime/private-backups'
FORMAT = 'AWS_ROLLBACK_ARTIFACTS_V1'
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
ROLES = ('database', 'source', 'models_and_calibrations', 'configuration',
         'image_app', 'image_nginx', 'image_gateway', 'image_ueba_worker')
IMAGE_ROLES = frozenset(role for role in ROLES if role.startswith('image_'))
SHA256 = re.compile(r'[0-9a-f]{64}')


@dataclass(frozen=True)
class Artifact:
    path: str
    sha256: str
    image_id: str | None = None


@dataclass(frozen=True)
class Checkpoint:
    artifacts: dict[str, Artifact]


class PrecheckError(ValueError):
    """Machine-readable errors never include private paths or artifact contents."""


def parse_manifest_json(body):
    """Reject ambiguous or non-standard JSON before interpreting checkpoint roles."""
    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise PrecheckError('DUPLICATE_MANIFEST_FIELD')
            value[key] = item
        return value

    def no_constants(_value):
        raise PrecheckError('NONFINITE_MANIFEST_VALUE')

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise PrecheckError('NONFINITE_MANIFEST_VALUE')
        return value

    def bounded_integer(text):
        if len(text.lstrip('-')) > 64:
            raise PrecheckError('MANIFEST_INTEGER_LIMIT_EXCEEDED')
        return int(text)

    try:
        value = json.loads(body, object_pairs_hook=unique_fields, parse_constant=no_constants,
                           parse_float=finite_float, parse_int=bounded_integer)
    except (UnicodeDecodeError, RecursionError, OverflowError):
        raise PrecheckError('INVALID_MANIFEST_JSON') from None
    except ValueError as failure:
        if isinstance(failure, PrecheckError):
            raise
        raise PrecheckError('INVALID_MANIFEST_JSON') from None
    # Python JSON recursion limits vary by runtime; bound the decoded structure
    # explicitly rather than assuming deeply nested input always raises.
    pending, visited = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if depth > 8 or visited > 10000:
            raise PrecheckError('INVALID_MANIFEST_JSON')
        if isinstance(node, dict):
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
    return value


def parse_manifest(value):
    if (not isinstance(value, dict)
            or set(value) != {'format', 'source_environment', 'source_schema_version',
                              'target_schema_version', 'artifacts'}
            or value.get('format') != FORMAT or value.get('source_environment') != 'AWS'
            or value.get('source_schema_version') != '27' or value.get('target_schema_version') != '36'):
        raise PrecheckError('INVALID_CHECKPOINT_CONTRACT')
    artifacts = value['artifacts']
    if not isinstance(artifacts, dict) or set(artifacts) - set(ROLES):
        raise PrecheckError('INVALID_ARTIFACT_ROLES')
    parsed, paths = {}, set()
    for role, raw in artifacts.items():
        fields = {'path', 'sha256', 'source_environment'} | ({'image_id'} if role in IMAGE_ROLES else set())
        if not isinstance(raw, dict) or set(raw) != fields or raw.get('source_environment') != 'AWS':
            raise PrecheckError('INVALID_ORIGIN_OR_ARTIFACT_CONTRACT')
        path, digest = raw['path'], raw['sha256']
        if (not isinstance(path, str) or not path or '\\' in path or '\x00' in path
                or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts
                or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            raise PrecheckError('INVALID_ARTIFACT_IDENTITY')
        image_id = raw.get('image_id')
        if role in IMAGE_ROLES and (not isinstance(image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)):
            raise PrecheckError('IMMUTABLE_IMAGE_ID_REQUIRED')
        canonical_path = str(PurePosixPath(path))
        if canonical_path in paths:
            raise PrecheckError('DUPLICATE_ARTIFACT_PATH')
        paths.add(canonical_path)
        parsed[role] = Artifact(path, digest, image_id)
    return Checkpoint(parsed)


def private_path(path, root):
    """Reject traversal and symlinked ancestors, not just symlinked final files."""
    root = root.absolute()
    path = path.absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise PrecheckError('OUTSIDE_PRIVATE_BACKUP_ROOT') from None
    if '..' in relative.parts:
        raise PrecheckError('OUTSIDE_PRIVATE_BACKUP_ROOT')
    # Check root ancestors too: an ignored private tree must not be redirected.
    for candidate in reversed((path, *path.parents)):
        if candidate.is_symlink():
            raise PrecheckError('SYMLINK_PATH_REJECTED')
    for candidate in (root, *path.parents):
        if candidate == root or candidate.is_relative_to(root):
            metadata = candidate.stat()
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077
                    or metadata.st_uid != os.geteuid()):
                raise PrecheckError('PRIVATE_DIRECTORY_PROTECTION_REQUIRED')
    return path


def read_private_file(path, maximum, *, content=False):
    # Pin the same descriptor for protection checks and hashing; never follow a
    # raced final symlink or block on a FIFO. No file bodies enter diagnostics.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum
                or metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid()):
            raise PrecheckError('BOUNDED_PRIVATE_REGULAR_FILE_REQUIRED')
        digest, body, total = hashlib.sha256(), bytearray(), 0
        while block := stream.read(min(65536, maximum - total + 1)):
            total += len(block)
            if total > maximum:
                raise PrecheckError('ARTIFACT_SIZE_LIMIT_EXCEEDED')
            digest.update(block)
            if content:
                body.extend(block)
        after = os.fstat(stream.fileno())
        if (total != metadata.st_size or metadata.st_size != after.st_size
                or metadata.st_mtime_ns != after.st_mtime_ns or metadata.st_ctime_ns != after.st_ctime_ns):
            raise PrecheckError('ARTIFACT_CHANGED_DURING_PRECHECK')
        return digest.hexdigest(), bytes(body) if content else None


def precheck(checkpoint, directory, private_root=PRIVATE_ROOT):
    checks = {}
    for role in ROLES:
        artifact = checkpoint.artifacts.get(role)
        if artifact is None:
            checks[role] = {'verified': False, 'code': 'MISSING_AWS_ORIGIN_BOUND_ARTIFACT'}
            continue
        try:
            path = private_path(directory / artifact.path, private_root)
            digest, _ = read_private_file(path, MAX_ARTIFACT_BYTES)
            if digest != artifact.sha256:
                raise PrecheckError('CHECKPOINT_SHA256_MISMATCH')
            checks[role] = {'verified': True, 'code': 'PRIVATE_FILE_SHA256_MATCHED', 'sha256': digest}
            if artifact.image_id is not None:
                checks[role]['declared_image_id'] = artifact.image_id
        except PrecheckError as failure:
            checks[role] = {'verified': False, 'code': str(failure)}
        except OSError:
            checks[role] = {'verified': False, 'code': 'ARTIFACT_UNAVAILABLE'}
    verified = all(check['verified'] for check in checks.values())
    return {'format': FORMAT, 'scope': 'LOCAL_READ_ONLY_SUPPLIED_CHECKPOINT_INTEGRITY_ONLY',
            'observed_at': datetime.now(timezone.utc).isoformat(), 'artifacts_verified': verified,
            'status': ('ARTIFACTS_VERIFIED_BACKWARD_VALIDATION_REQUIRED' if verified else 'CHECKPOINT_INCOMPLETE'),
            'checks': checks, 'release_ready': False, 'aws_origin_independently_authenticated': False,
            'image_archive_contents_inspected': False, 'model_calibration_completeness_inspected': False,
            'legacy_app_v34_on_schema36_verified': False, 'database_rollback_verified': False,
            'database_rollback_performed': False, 'aws_calls': False, 'docker_calls': False,
            'deployment': False, 'source_artifacts_modified': False,
            'required_next_validation': 'ISOLATED_ACTUAL_LEGACY_AWS_APP_STARTUP_ON_UPGRADED_BACKUP_WITHOUT_FLYWAY_BYPASS'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New private evidence file beside the checkpoint manifest')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        manifest = private_path(args.manifest, PRIVATE_ROOT)
        manifest_sha, body = read_private_file(manifest, MAX_MANIFEST_BYTES, content=True)
        checkpoint = parse_manifest(parse_manifest_json(body))
        output = private_path(args.output, PRIVATE_ROOT)
        if output.parent != manifest.parent:
            raise PrecheckError('OUTPUT_MUST_BE_BESIDE_MANIFEST')
        if output.exists():
            raise PrecheckError('NEW_OUTPUT_REQUIRED')
        result = precheck(checkpoint, manifest.parent, PRIVATE_ROOT)
        result['manifest_sha256'] = manifest_sha
        result['helper_source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        with output.open('x') as stream:
            json.dump(result, stream, indent=2)
    except (PrecheckError, OSError, json.JSONDecodeError, UnicodeDecodeError) as failure:
        code = str(failure) if isinstance(failure, PrecheckError) else 'INVALID_OR_UNAVAILABLE_PRIVATE_INPUT'
        print(json.dumps({'artifacts_verified': False, 'release_ready': False, 'code': code}))
        return 2
    print(json.dumps({'artifacts_verified': result['artifacts_verified'], 'release_ready': False,
                      'status': result['status'], 'missing_or_failed_roles':
                      [role for role, check in result['checks'].items() if not check['verified']]}))
    return 0 if result['artifacts_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
