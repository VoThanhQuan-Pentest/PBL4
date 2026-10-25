#!/usr/bin/env python3
"""Capture source and running images on the AWS lab host BEFORE a deployment.

Run locally on the intended EC2 instance, not on a workstation. The CLI always
uses /opt/flare, its exact .env marker FLARE_ENVIRONMENT=aws-lab, Compose project
flare, and the local Docker socket. It requires independently supplied expected
instance/account/region and compares them to the fixed IMDSv2 identity document.
Metadata matching is NOT cryptographic AWS-origin authentication. No IAM
credentials are fetched. Only Docker ps, selected-field inspect, and image save
are used; no image tags, build, pull, load, stop, restart, or deployment.

A successful exit means PARTIAL_SOURCE_AND_IMAGES_ONLY, never release readiness.
Active configuration/secrets, database, model/calibration data, Redis and WAF
state are NOT backed up or restored. Source configuration templates are source,
not a backup of effective runtime configuration. Images may themselves contain
sensitive embedded build-time data: keep all artifacts private. Nothing is
unpacked or executed. Failures retain private partial files and a failure record.
CLI exit 0: partial capture completed; 1: capture failed; 2: invalid CLI identity.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.request

AWS_ROOT = Path('/opt/flare')
PRIVATE_COMPONENTS = ('observability', 'runtime', 'private-backups')
PROJECT = 'flare'
SERVICES = ('app', 'nginx', 'gateway', 'ueba-worker')
FORMAT = 'AWS_CODE_IMAGE_CHECKPOINT_V1'
STATUS = 'PARTIAL_SOURCE_AND_IMAGES_ONLY'
DOCKER = ('docker', '--host', 'unix:///var/run/docker.sock')
IMDS_TOKEN_URL = 'http://169.254.169.254/latest/api/token'
IMDS_IDENTITY_URL = 'http://169.254.169.254/latest/dynamic/instance-identity/document'
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_IMAGE_BYTES = MAX_IMAGE_BYTES * len(SERVICES)
DISK_RESERVE_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILES = 20000
SOURCE_MEMBER_OVERHEAD_BYTES = 8192
MAX_SOURCE_ENTRIES = 100000
MAX_COMMAND_BYTES = 65536
DEFAULT_DEADLINE_SECONDS = 900
SOURCE_TREES = ('backend/src', 'backend/.mvn', 'frontend/src', 'frontend/public',
                'nginx', 'gateway', 'ueba-worker/app', 'observability/scripts',
                'observability/tests', 'observability/filebeat', 'observability/logstash',
                'observability/elasticsearch', 'observability/kibana')
SOURCE_FILES = ('docker-compose.yml', 'docker-compose.e2e.yml', '.dockerignore',
                'backend/Dockerfile', 'backend/pom.xml', 'backend/mvnw', 'backend/mvnw.cmd',
                'frontend/package.json', 'frontend/package-lock.json', 'frontend/index.html',
                'frontend/vite.config.js', 'frontend/vite.config.ts',
                'ueba-worker/Dockerfile', 'ueba-worker/requirements.txt',
                'ueba-worker/requirements.lock', 'ueba-worker/pyproject.toml',
                'observability/docker-compose.web-aws.yml',
                'observability/docker-compose.monitor-aws.yml',
                'observability/docker-compose.monitor.yml',
                'observability/docker-compose.local.yml')
EXCLUDED_COMPONENTS = frozenset(('.git', '.secrets', 'runtime', 'target', 'build',
                                'dist', 'node_modules', '__pycache__', '.pytest_cache',
                                '.venv', 'venv', 'certs', 'certificates', 'keys',
                                'models', 'calibrations', 'model-data', 'logs', 'coverage'))
CODE_SUFFIXES = frozenset(('.java', '.properties', '.sql', '.xml', '.json', '.js',
                           '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.css', '.html',
                           '.svg', '.png', '.jpg', '.jpeg', '.webp', '.ico', '.sh',
                           '.py', '.go', '.sum', '.mod', '.yml', '.yaml', '.conf',
                           '.txt', '.md', '.toml', '.lock', '.ndjson'))
EXCLUDED_SUFFIXES = frozenset(('.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks',
                               '.pkl', '.pickle', '.joblib', '.onnx', '.db', '.sqlite',
                               '.jar', '.class', '.pyc', '.zip', '.tar', '.gz'))
CONTAINER_ID = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')
INSPECT_FORMAT = ('{"id":{{json .Id}},"image_id":{{json .Image}},'
                  '"running":{{json .State.Running}},'
                  '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                  '"project":{{json (index .Config.Labels "com.docker.compose.project")}}}')
NOT_CAPTURED = ('effective_configuration_and_secrets', 'database',
                'model_and_calibration_data', 'redis_state', 'waf_state')


class CaptureError(ValueError):
    """Only constant, non-sensitive error codes cross the diagnostic boundary."""


def selected_json(body, code):
    # Python versions differ in whether deeply nested JSON raises RecursionError.
    # Bound lexical nesting before parsing, while ignoring brackets in strings.
    if isinstance(body, bytes):
        try:
            body = body.decode('utf-8')
        except UnicodeDecodeError:
            raise CaptureError(code) from None
    if not isinstance(body, str) or len(body) > MAX_COMMAND_BYTES:
        raise CaptureError(code)
    depth, quoted, escaped = 0, False, False
    for character in body:
        if quoted:
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in '{[':
            depth += 1
            if depth > 32:
                raise CaptureError(code)
        elif character in '}]':
            depth -= 1

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CaptureError(code)
            result[key] = value
        return result

    def reject_constant(value):
        raise CaptureError(code)

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise CaptureError(code)
        return number

    def bounded_integer(value):
        if len(value.lstrip('-')) > 64:
            raise CaptureError(code)
        return int(value)

    try:
        return json.loads(body, object_pairs_hook=unique, parse_constant=reject_constant,
                          parse_float=finite_float, parse_int=bounded_integer)
    except (ValueError, RecursionError):
        raise CaptureError(code) from None


@dataclass(frozen=True)
class ExpectedIdentity:
    instance_id: str
    account_id: str
    region: str

    def validate(self):
        if (not isinstance(self.instance_id, str)
                or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', self.instance_id)
                or not isinstance(self.account_id, str)
                or not re.fullmatch(r'[0-9]{12}', self.account_id)
                or not isinstance(self.region, str)
                or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]', self.region)):
            raise CaptureError('INVALID_EXPECTED_AWS_IDENTITY')


class Deadline:
    def __init__(self, seconds=DEFAULT_DEADLINE_SECONDS):
        if type(seconds) is not int or not 1 <= seconds <= 3600:
            raise CaptureError('INVALID_DEADLINE')
        self.end = time.monotonic() + seconds

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise CaptureError('CAPTURE_DEADLINE_EXCEEDED')
        return remaining


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CaptureError('IMDS_REDIRECT_REJECTED')


def bounded_imds_body(response, maximum, deadline):
    body = bytearray()
    while True:
        deadline.remaining()
        # read1 returns a currently available chunk instead of waiting to fill
        # the entire limit, so a trickling response cannot bypass deadline checks.
        block = response.read1(min(4096, maximum - len(body) + 1))
        if not block:
            break
        body.extend(block)
        if len(body) > maximum:
            raise CaptureError('IMDS_RESPONSE_SIZE_LIMIT_EXCEEDED')
    deadline.remaining()
    return bytes(body)


def observe_identity(expected, deadline):
    expected.validate()
    # Fixed IMDSv2 paths only. Disable proxy routing and redirects; never request
    # meta-data/iam or retain/print the token or the complete identity document.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        token_request = urllib.request.Request(IMDS_TOKEN_URL, method='PUT',
                                              headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'})
        with opener.open(token_request, timeout=min(3, deadline.remaining())) as response:
            token = bounded_imds_body(response, 4096, deadline)
        if not 0 < len(token) <= 4096 or any(byte < 33 or byte > 126 for byte in token):
            raise CaptureError('INVALID_IMDS_TOKEN')
        request = urllib.request.Request(IMDS_IDENTITY_URL,
                                         headers={'X-aws-ec2-metadata-token': token.decode('ascii')})
        with opener.open(request, timeout=min(3, deadline.remaining())) as response:
            body = bounded_imds_body(response, 32768, deadline)
        if len(body) > 32768:
            raise CaptureError('IMDS_IDENTITY_SIZE_LIMIT_EXCEEDED')
        value = selected_json(body, 'INVALID_IMDS_IDENTITY_DOCUMENT')
        if not isinstance(value, dict) or any(value.get(key) != wanted for key, wanted in (
                ('instanceId', expected.instance_id), ('accountId', expected.account_id),
                ('region', expected.region))):
            raise CaptureError('AWS_IDENTITY_MISMATCH')
    except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError):
        raise CaptureError('IMDS_IDENTITY_UNAVAILABLE') from None
    deadline.remaining()
    return {'instance_id': expected.instance_id, 'account_id': expected.account_id,
            'region': expected.region, 'method': 'FIXED_IMDSV2_IDENTITY_DOCUMENT_MATCH_ONLY',
            'cryptographic_origin_authenticated': False}


def open_directory(path):
    """Reject symlinked ancestors, including /opt, then pin the directory FD."""
    path = Path(path).absolute()
    if '..' in path.parts:
        raise CaptureError('SYMLINK_OR_TRAVERSAL_ROOT_REJECTED')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        readable = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        os.close(descriptor)
        return readable
    except OSError:
        os.close(descriptor)
        raise CaptureError('SOURCE_ROOT_UNAVAILABLE_OR_SYMLINKED') from None


def marker_matches(root_fd, deadline):
    descriptor = os.open('.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024:
            raise CaptureError('BOUNDED_REGULAR_ENV_MARKER_REQUIRED')
        count, matches, consumed = 0, 0, 0
        while line := stream.readline(8193):
            deadline.remaining()
            consumed += len(line)
            if len(line) > 8192 or consumed > 1024 * 1024:
                raise CaptureError('ENV_MARKER_SIZE_LIMIT_EXCEEDED')
            candidate = line.rstrip(b'\r\n')
            if candidate.strip().startswith((b'FLARE_ENVIRONMENT=', b'export FLARE_ENVIRONMENT=')):
                count += 1
                matches += candidate == b'FLARE_ENVIRONMENT=aws-lab'
        after = os.fstat(stream.fileno())
        if signature(before) != signature(after) or consumed != before.st_size:
            raise CaptureError('ENV_MARKER_CHANGED')
        if count != 1 or matches != 1:
            raise CaptureError('AWS_LAB_MARKER_REQUIRED')


def signature(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def excluded(name):
    lowered = name.lower()
    return (lowered in EXCLUDED_COMPONENTS or lowered.startswith('.env')
            or lowered.endswith('.env') or Path(lowered).suffix in EXCLUDED_SUFFIXES)


def source_file_allowed(path):
    return (not any(excluded(part) for part in Path(path).parts)
            and (path in SOURCE_FILES or Path(path).name.startswith('Dockerfile')
                 or Path(path).name == '.dockerignore' or Path(path).suffix.lower() in CODE_SUFFIXES))


def open_relative(root_fd, relative):
    """All directory components and the final file are opened without symlinks."""
    parts = Path(relative).parts
    if not parts or any(part in ('..', '/') for part in parts):
        raise CaptureError('INVALID_SOURCE_PATH')
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = following
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def read_source(root_fd, relative, deadline):
    descriptor = open_relative(root_fd, relative)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_SOURCE_FILE_BYTES:
            raise CaptureError('BOUNDED_REGULAR_SOURCE_FILE_REQUIRED')
        digest, total = hashlib.sha256(), 0
        while block := stream.read(65536):
            deadline.remaining()
            total += len(block)
            if total > MAX_SOURCE_FILE_BYTES:
                raise CaptureError('SOURCE_FILE_SIZE_LIMIT_EXCEEDED')
            digest.update(block)
        after = os.fstat(stream.fileno())
        if signature(before) != signature(after) or total != before.st_size:
            raise CaptureError('SOURCE_CHANGED_DURING_CAPTURE')
        return {'size': total, 'sha256': digest.hexdigest(), 'signature': signature(before),
                'executable': bool(before.st_mode & 0o111)}


def snapshot_source(root_fd, deadline):
    paths, entries = set(), 0

    def walk(directory_fd, prefix):
        nonlocal entries
        with os.scandir(directory_fd) as directory:
            for entry in directory:
                deadline.remaining()
                entries += 1
                if entries > MAX_SOURCE_ENTRIES:
                    raise CaptureError('SOURCE_ENTRY_LIMIT_EXCEEDED')
                if excluded(entry.name):
                    continue
                metadata = entry.stat(follow_symlinks=False)
                relative = prefix + '/' + entry.name
                if ('\\' in entry.name or any(ord(character) < 32 or ord(character) == 127 for character in entry.name)
                        or len(relative.encode('utf-8', errors='surrogateescape')) > 4096):
                    raise CaptureError('UNSAFE_SOURCE_NAME_REJECTED')
                if stat.S_ISLNK(metadata.st_mode):
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    if relative.count('/') > 32:
                        raise CaptureError('SOURCE_DIRECTORY_DEPTH_LIMIT_EXCEEDED')
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory_fd)
                    try:
                        walk(child, relative)
                    finally:
                        os.close(child)
                elif source_file_allowed(relative):
                    if not stat.S_ISREG(metadata.st_mode):
                        raise CaptureError('NON_REGULAR_SOURCE_REJECTED')
                    paths.add(relative)
                    if len(paths) > MAX_SOURCE_FILES:
                        raise CaptureError('SOURCE_FILE_COUNT_LIMIT_EXCEEDED')

    for relative in SOURCE_TREES:
        try:
            descriptor = open_relative(root_fd, relative)
        except FileNotFoundError:
            continue
        except OSError:
            raise CaptureError('SOURCE_TREE_UNAVAILABLE_OR_SYMLINKED') from None
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise CaptureError('SOURCE_DIRECTORY_REQUIRED')
            walk(descriptor, relative)
        finally:
            os.close(descriptor)
    for relative in SOURCE_FILES:
        try:
            descriptor = open_relative(root_fd, relative)
        except FileNotFoundError:
            continue
        except OSError:
            raise CaptureError('SOURCE_FILE_UNAVAILABLE_OR_SYMLINKED') from None
        with os.fdopen(descriptor, 'rb') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise CaptureError('NON_REGULAR_SOURCE_REJECTED')
        paths.add(relative)
    if not paths or len(paths) > MAX_SOURCE_FILES:
        raise CaptureError('EMPTY_OR_OVERSIZED_SOURCE_INVENTORY')
    result, total = {}, 0
    for relative in sorted(paths):
        record = read_source(root_fd, relative, deadline)
        total += record['size']
        if total > MAX_SOURCE_BYTES:
            raise CaptureError('SOURCE_TOTAL_SIZE_LIMIT_EXCEEDED')
        result[relative] = record
    # Required build contracts prevent an accidentally empty/irrelevant source
    # tree from being represented as a source checkpoint.
    required = ('docker-compose.yml', 'backend/pom.xml', 'backend/Dockerfile',
                'frontend/package.json', 'nginx/Dockerfile', 'gateway/Dockerfile',
                'ueba-worker/Dockerfile', 'observability/docker-compose.web-aws.yml')
    if any(path not in result for path in required):
        raise CaptureError('REQUIRED_SOURCE_BUILD_FILE_MISSING')
    for prefix in ('backend/src/', 'frontend/src/', 'gateway/', 'ueba-worker/app/', 'observability/scripts/'):
        if not any(path.startswith(prefix) and not Path(path).name.startswith('Dockerfile') for path in result):
            raise CaptureError('REQUIRED_SOURCE_CODE_TREE_MISSING')
    return result


def private_checkpoint(root_fd, name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise CaptureError('INVALID_CHECKPOINT_NAME')
    descriptor = os.dup(root_fd)
    try:
        for index, part in enumerate(PRIVATE_COMPONENTS):
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
            metadata = os.fstat(descriptor)
            if metadata.st_mode & 0o022:
                raise CaptureError('WRITABLE_BACKUP_PARENT_DIRECTORY_REJECTED')
            if index == len(PRIVATE_COMPONENTS) - 1 and (
                    metadata.st_mode & 0o077 or metadata.st_uid != os.geteuid()):
                raise CaptureError('PRIVATE_BACKUP_DIRECTORY_PROTECTION_REQUIRED')
        try:
            os.mkdir(name, mode=0o700, dir_fd=descriptor)
        except FileExistsError:
            raise CaptureError('NEW_CHECKPOINT_DIRECTORY_REQUIRED') from None
        following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        os.close(descriptor)
        descriptor = following
        os.fchmod(descriptor, 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def new_private_file(directory_fd, name):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, 'wb')


def write_json(directory_fd, name, value):
    with new_private_file(directory_fd, name) as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())


def stream_docker(arguments, sink, maximum, deadline):
    """Bound pipe reads, elapsed time and output; keep stderr out of evidence."""
    process = subprocess.Popen((*DOCKER, *arguments), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               close_fds=True, start_new_session=True,
                               env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                    'LANG': 'C.UTF-8'})
    total, digest = 0, hashlib.sha256()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                events = selector.select(min(1, deadline.remaining()))
                if not events:
                    continue
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    raise CaptureError('DOCKER_OUTPUT_SIZE_LIMIT_EXCEEDED')
                if tuple(arguments[:2]) == ('image', 'save'):
                    disk_headroom(sink.fileno(), len(block))
                sink.write(block)
                digest.update(block)
        if process.wait(timeout=deadline.remaining()) != 0:
            raise CaptureError('DOCKER_COMMAND_FAILED')
        if not total:
            raise CaptureError('EMPTY_DOCKER_OUTPUT')
        return {'size': total, 'sha256': digest.hexdigest()}
    except subprocess.TimeoutExpired:
        raise CaptureError('CAPTURE_DEADLINE_EXCEEDED') from None
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()


def docker_text(arguments, deadline):
    sink = io.BytesIO()
    stream_docker(arguments, sink, MAX_COMMAND_BYTES, deadline)
    try:
        return sink.getvalue().decode('utf-8')
    except UnicodeDecodeError:
        raise CaptureError('INVALID_DOCKER_SELECTED_OUTPUT') from None


def running_images(deadline):
    result = {}
    for service in SERVICES:
        output = docker_text(('ps', '--no-trunc', '--filter',
                              'label=com.docker.compose.project=' + PROJECT,
                              '--filter', 'label=com.docker.compose.service=' + service,
                              '--format', '{{.ID}}'), deadline)
        ids = output.splitlines()
        if len(ids) != 1 or not CONTAINER_ID.fullmatch(ids[0]):
            raise CaptureError('SINGLE_EXACT_RUNNING_SERVICE_REQUIRED')
        value = selected_json(docker_text(('inspect', '--type', 'container', '--format',
                                          INSPECT_FORMAT, ids[0]), deadline),
                              'INVALID_DOCKER_SELECTED_OUTPUT')
        if (not isinstance(value, dict)
                or set(value) != {'id', 'image_id', 'running', 'service', 'project'}
                or value.get('id') != ids[0] or value.get('running') is not True
                or value.get('service') != service or value.get('project') != PROJECT
                or not isinstance(value.get('image_id'), str)
                or not IMAGE_ID.fullmatch(value['image_id'])):
            raise CaptureError('RUNNING_IMMUTABLE_IMAGE_CONTRACT_MISMATCH')
        result[service] = value
    if len({record['id'] for record in result.values()}) != len(SERVICES):
        raise CaptureError('DISTINCT_RUNNING_CONTAINERS_REQUIRED')
    return result


def image_sizes(containers, deadline):
    sizes = {}
    for service, container in containers.items():
        size = selected_json(docker_text(('image', 'inspect', '--format', '{{json .Size}}',
                                         container['image_id']), deadline), 'INVALID_DOCKER_IMAGE_SIZE')
        if type(size) is not int or not 0 < size <= MAX_IMAGE_BYTES:
            raise CaptureError('IMAGE_SIZE_LIMIT_EXCEEDED')
        sizes[service] = size
    if sum(sizes.values()) > MAX_TOTAL_IMAGE_BYTES:
        raise CaptureError('TOTAL_IMAGE_SIZE_LIMIT_EXCEEDED')
    return sizes


def disk_headroom(directory_fd, expected_bytes):
    # Docker Size is an estimate, not an archive-size guarantee. Add explicit
    # per-image overhead and leave >=1GiB free; stream limits remain authoritative.
    capacity = os.fstatvfs(directory_fd)
    available = capacity.f_bavail * capacity.f_frsize
    if available < expected_bytes + DISK_RESERVE_BYTES:
        raise CaptureError('INSUFFICIENT_PRIVATE_BACKUP_DISK_HEADROOM')


def image_budget(size):
    return size + max(64 * 1024 * 1024, size // 10)


class CheckedSourceReader:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline
        self.digest, self.total = hashlib.sha256(), 0

    def read(self, size):
        self.deadline.remaining()
        block = self.stream.read(size)
        self.total += len(block)
        self.digest.update(block)
        return block


def pack_source(root_fd, output_fd, inventory, deadline):
    with new_private_file(output_fd, 'source.tar') as destination:
        with tarfile.open(fileobj=destination, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for relative, record in inventory.items():
                deadline.remaining()
                with os.fdopen(open_relative(root_fd, relative), 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or signature(before) != record['signature']:
                        raise CaptureError('SOURCE_CHANGED_DURING_CAPTURE')
                    member = tarfile.TarInfo(relative)
                    member.size, member.mode, member.mtime = record['size'], (0o700 if record['executable'] else 0o600), 0
                    reader = CheckedSourceReader(stream, deadline)
                    archive.addfile(member, reader)
                    if (reader.total != record['size'] or reader.digest.hexdigest() != record['sha256']
                            or signature(os.fstat(stream.fileno())) != record['signature']):
                        raise CaptureError('SOURCE_CHANGED_DURING_CAPTURE')
        destination.flush()
        os.fsync(destination.fileno())
    descriptor = os.open('source.tar', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=output_fd)
    with os.fdopen(descriptor, 'rb') as stream:
        total, digest = 0, hashlib.sha256()
        maximum = MAX_SOURCE_BYTES + MAX_SOURCE_FILES * SOURCE_MEMBER_OVERHEAD_BYTES + 10240
        while block := stream.read(65536):
            deadline.remaining()
            total += len(block)
            if total > maximum:
                raise CaptureError('SOURCE_ARCHIVE_SIZE_LIMIT_EXCEEDED')
            digest.update(block)
    return {'path': 'source.tar', 'size': total, 'sha256': digest.hexdigest()}


def capture(expected, name, deadline_seconds=DEFAULT_DEADLINE_SECONDS, *,
            root=AWS_ROOT, isolated_test_fixture=False):
    """Internal root injection supports isolated tests, never a CLI root override.

    Non-production roots cannot yield a manifest labelled AWS. Test fixtures must
    explicitly opt in and are permanently labelled ISOLATED_TEST_FIXTURE_NOT_AWS.
    """
    expected.validate()
    if Path(root) != AWS_ROOT and not isolated_test_fixture:
        raise CaptureError('FIXED_AWS_ROOT_REQUIRED')
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise CaptureError('INVALID_CHECKPOINT_NAME')
    deadline = Deadline(deadline_seconds)
    root_fd, output_fd = open_directory(root), None
    try:
        marker_matches(root_fd, deadline)
        identity = observe_identity(expected, deadline)
        containers = running_images(deadline)
        sizes = image_sizes(containers, deadline)
        inventory = snapshot_source(root_fd, deadline)
        output_fd = private_checkpoint(root_fd, name)
        source_budget = (sum(record['size'] for record in inventory.values())
                         + len(inventory) * SOURCE_MEMBER_OVERHEAD_BYTES + 10240)
        disk_headroom(output_fd, source_budget + sum(image_budget(size) for size in sizes.values()))
        source = pack_source(root_fd, output_fd, inventory, deadline)
        artifacts = {'source': source}
        total_images = 0
        for service in SERVICES:
            disk_headroom(output_fd, image_budget(sizes[service]))
            image_id = containers[service]['image_id']
            filename = 'image_' + service.replace('-', '_') + '.tar'
            with new_private_file(output_fd, filename) as destination:
                saved = stream_docker(('image', 'save', image_id), destination,
                                      MAX_IMAGE_BYTES, deadline)
                destination.flush()
                os.fsync(destination.fileno())
            artifacts['image_' + service.replace('-', '_')] = {
                'path': filename, 'image_id': image_id, 'docker_reported_size': sizes[service], **saved}
            total_images += saved['size']
            if total_images > MAX_TOTAL_IMAGE_BYTES:
                raise CaptureError('TOTAL_IMAGE_SIZE_LIMIT_EXCEEDED')
        if running_images(deadline) != containers:
            raise CaptureError('RUNNING_CONTAINERS_CHANGED_DURING_CAPTURE')
        try:
            after_inventory = snapshot_source(root_fd, deadline)
        except (CaptureError, OSError) as failure:
            if isinstance(failure, CaptureError) and str(failure) == 'CAPTURE_DEADLINE_EXCEEDED':
                raise
            raise CaptureError('SOURCE_CHANGED_DURING_CAPTURE') from None
        if after_inventory != inventory:
            raise CaptureError('SOURCE_CHANGED_DURING_CAPTURE')
        marker_matches(root_fd, deadline)
        if observe_identity(expected, deadline) != identity:
            raise CaptureError('AWS_IDENTITY_CHANGED_DURING_CAPTURE')
        checked_root_fd = open_directory(root)
        try:
            original, current = os.fstat(root_fd), os.fstat(checked_root_fd)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise CaptureError('SOURCE_ROOT_CHANGED_DURING_CAPTURE')
        finally:
            os.close(checked_root_fd)
        deadline.remaining()
        manifest = {'format': FORMAT, 'status': STATUS, 'capture_completed': True,
                    'source_environment': ('ISOLATED_TEST_FIXTURE_NOT_AWS' if isolated_test_fixture else 'AWS'),
                    'observed_at': datetime.now(timezone.utc).isoformat(), 'identity_observation': identity,
                    'aws_origin_independently_authenticated': False, 'project': PROJECT,
                    'running_containers': containers, 'artifacts': artifacts,
                    'source_inventory': {path: {key: value for key, value in record.items() if key != 'signature'}
                                         for path, record in inventory.items()},
                    'source_policy': {'trees': list(SOURCE_TREES), 'files': list(SOURCE_FILES),
                                      'symlinks_excluded': True, 'unknown_extensions_excluded': True},
                    'source_and_running_image_ids_unchanged': True,
                    'image_archive_contents_inspected': False,
                    'source_matches_saved_image_build': False,
                    'not_backed_up_or_restored': list(NOT_CAPTURED),
                    'release_ready': False, 'deployment': False, 'restore_performed': False,
                    'private_artifact_writes': True, 'source_files_modified': False,
                    'running_services_modified': False, 'iam_credentials_requested': False,
                    'complete_rollback_checkpoint': False,
                    'legacy_application_on_upgraded_schema_verified': False}
        write_json(output_fd, 'manifest.json', manifest)
        os.fsync(output_fd)
        return manifest
    except (CaptureError, OSError, tarfile.TarError, KeyboardInterrupt) as failure:
        code = (str(failure) if isinstance(failure, CaptureError) else
                'CAPTURE_CANCELLED' if isinstance(failure, KeyboardInterrupt) else 'CAPTURE_IO_FAILED')
        if output_fd is not None:
            try:
                write_json(output_fd, 'failure.json', {'format': FORMAT, 'status': 'CAPTURE_FAILED_PARTIAL_FILES_RETAINED',
                                                     'capture_completed': False, 'release_ready': False, 'code': code})
                os.fsync(output_fd)
            except OSError:
                pass  # Disk-full may prevent even the failure record; retain everything.
        raise CaptureError(code) from None
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(root_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-instance-id', required=True)
    parser.add_argument('--expected-account-id', required=True)
    parser.add_argument('--expected-region', required=True)
    parser.add_argument('--checkpoint-name', required=True,
                        help='New directory under /opt/flare/observability/runtime/private-backups')
    parser.add_argument('--deadline-seconds', type=int, default=DEFAULT_DEADLINE_SECONDS,
                        help='Entire capture deadline, 1..3600 seconds (default 900)')
    args = parser.parse_args()
    expected = ExpectedIdentity(args.expected_instance_id, args.expected_account_id, args.expected_region)
    try:
        expected.validate()
        if not NAME.fullmatch(args.checkpoint_name) or not 1 <= args.deadline_seconds <= 3600:
            raise CaptureError('INVALID_CHECKPOINT_NAME_OR_DEADLINE')
    except CaptureError as failure:
        print(json.dumps({'capture_completed': False, 'release_ready': False, 'code': str(failure)}))
        return 2
    try:
        result = capture(expected, args.checkpoint_name, args.deadline_seconds)
    except CaptureError as failure:
        print(json.dumps({'capture_completed': False, 'release_ready': False, 'code': str(failure)}))
        return 1
    print(json.dumps({'capture_completed': True, 'status': result['status'],
                      'release_ready': False, 'complete_rollback_checkpoint': False,
                      'aws_origin_independently_authenticated': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
