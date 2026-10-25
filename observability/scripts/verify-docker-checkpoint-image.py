#!/usr/bin/env python3
"""Read-only immutable identity check of one private Docker image-save archive.

Supported: uncompressed ustar/GNU tar with one Docker manifest.json image, either
classic <sha256>.json + <hex>/layer.tar references, or an OCI 1.0 hybrid with
blobs/sha256 references and a consistent index -> single image manifest -> config
and layers graph. A single-platform built-image index may also include bounded
non-runnable BuildKit attestation manifests linked to that runnable image.
All referenced blob SHA-256/size values are checked, including
opaque compressed layer blobs. Optional legacy metadata is bounded and checked.
Ordinary regular files/directories only. GNU/PAX extensions, external URLs, parent
exports, compressed outer archives, pure OCI archives without Docker manifest,
deeper or multi-image/platform indexes, and unknown media types fail closed.

The expected immutable ID must be the exact config, runnable manifest, or built
index digest on the checked graph; attestations are never runnable identities.
Obtain that ID separately from trusted operator inventory: this tool does not
authenticate its source or the contents claimed by provenance statements.
Layers are bounded opaque members, not decoded or
compared to config rootfs.diff_ids. Successful verification therefore does NOT
prove rootfs integrity, loadability, AWS origin, rollback or release readiness.
Nothing is loaded, extracted, unpickled, executed, uploaded or changed.

Format reference: https://github.com/moby/docker-image-spec/blob/main/spec.md
Exit 0: config identity/reference checks passed; 1: verification failed;
2: invalid CLI/expected identity. JSON output never contains config values/paths.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_ROOT = ROOT / 'observability/runtime/private-backups'
FORMAT = 'DOCKER_CHECKPOINT_IMAGE_VERIFICATION_V1'
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_LAYERS = 128
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 20000
BLOCK_BYTES = 512
COPY_BYTES = 65536
HEX = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
CONFIG_NAME = re.compile(r'([0-9a-f]{64})\.json')
LAYER_NAME = re.compile(r'([0-9a-f]{64})/layer\.tar')
LEGACY_MEMBER = re.compile(r'([0-9a-f]{64})/(json|VERSION)')
BLOB_NAME = re.compile(r'blobs/sha256/([0-9a-f]{64})')
TAG_TEXT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,511}')
EXTENSION_TYPES = frozenset((b'L', b'K', b'x', b'g', b'X'))
OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST_TYPES = frozenset(('application/vnd.oci.image.manifest.v1+json',
                            'application/vnd.docker.distribution.manifest.v2+json'))
CONFIG_TYPES = frozenset(('application/vnd.oci.image.config.v1+json',
                          'application/vnd.docker.container.image.v1+json'))
LAYER_TYPES = frozenset(('application/vnd.oci.image.layer.v1.tar',
                         'application/vnd.oci.image.layer.v1.tar+gzip',
                         'application/vnd.oci.image.layer.v1.tar+zstd',
                         'application/vnd.docker.image.rootfs.diff.tar',
                         'application/vnd.docker.image.rootfs.diff.tar.gzip'))
ATTESTATION_LAYER_TYPES = frozenset(('application/vnd.in-toto+json',))


class VerificationError(ValueError):
    """Stable allowlisted codes only; no private values in diagnostics."""


@dataclass(frozen=True)
class Member:
    offset: int
    size: int
    directory: bool


def _metadata_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


@contextmanager
def _private_archive(path, private_root):
    """Open each component relative to pinned descriptors; never follow symlinks.

    Ancestors outside the private root need not be 0700, but must be directories.
    The root and every descendant directory must be owned, exactly 0700. No
    resolve()/stat()-then-open pathname race redirects the read outside that tree.
    """
    path, private_root = Path(path).absolute(), Path(private_root).absolute()
    if '..' in path.parts or '..' in private_root.parts:
        raise VerificationError('OUTSIDE_PRIVATE_BACKUP_ROOT')
    try:
        relative = path.relative_to(private_root)
    except ValueError:
        raise VerificationError('OUTSIDE_PRIVATE_BACKUP_ROOT') from None
    if not relative.parts or private_root == Path('/') or len(path.parts) > 128:
        raise VerificationError('INVALID_PRIVATE_ARCHIVE_PATH')
    if not all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK')):
        raise VerificationError('UNSUPPORTED_PRIVATE_FILE_PLATFORM')
    # Search-only ancestors (0711, e.g. an operator's temp parent) are legitimate;
    # Linux O_PATH pins them without demanding directory-listing permission.
    directory_flags = getattr(os, 'O_PATH', os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open('/', directory_flags)
    try:
        components, root_depth = path.parts[1:-1], len(private_root.parts) - 1
        for depth, component in enumerate(components, 1):
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if depth >= root_depth and (metadata.st_uid != os.geteuid()
                                        or stat.S_IMODE(metadata.st_mode) != 0o700):
                raise VerificationError('PRIVATE_DIRECTORY_PROTECTION_REQUIRED')
        archive_descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=descriptor)
    finally:
        os.close(descriptor)
    with os.fdopen(archive_descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid() or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_ARCHIVE_BYTES):
            raise VerificationError('BOUNDED_0600_OWNED_REGULAR_ARCHIVE_REQUIRED')
        yield stream, before


def _hash_archive(stream, metadata):
    digest, total = hashlib.sha256(), 0
    while block := stream.read(min(COPY_BYTES, MAX_ARCHIVE_BYTES - total + 1)):
        total += len(block)
        if total > MAX_ARCHIVE_BYTES:
            raise VerificationError('ARCHIVE_SIZE_LIMIT_EXCEEDED')
        digest.update(block)
    if total != metadata.st_size:
        raise VerificationError('ARCHIVE_CHANGED_DURING_VERIFICATION')
    stream.seek(0)
    return digest.hexdigest()


def _tar_number(field, maximum):
    # Positive GNU base-256 or NUL/space-padded octal. Negative/overflow refused.
    if field[0] == 0x80:
        number = int.from_bytes(field[1:], 'big')
    else:
        value, _, padding = field.partition(b'\0')
        value = value.strip(b' ')
        if any(byte not in b'01234567' for byte in value) or padding.strip(b'\0 '):
            raise VerificationError('INVALID_TAR_HEADER_NUMBER')
        number = int(value or b'0', 8)
    if number > maximum:
        raise VerificationError('TAR_HEADER_NUMBER_LIMIT_EXCEEDED')
    return number


def _header_text(field):
    value, _, padding = field.partition(b'\0')
    if padding.strip(b'\0'):
        raise VerificationError('INVALID_TAR_HEADER_TEXT')
    try:
        return value.decode('ascii')
    except UnicodeDecodeError:
        raise VerificationError('INVALID_TAR_HEADER_TEXT') from None


def _safe_member_name(name, directory=False):
    if directory and name.endswith('/'):
        name = name[:-1]
    if (not name or len(name) > 256 or name.startswith('/') or '\\' in name
            or any(part in ('', '.', '..') for part in name.split('/'))
            or any(ord(character) < 33 or ord(character) > 126 for character in name)):
        raise VerificationError('UNSAFE_TAR_MEMBER_PATH')
    return name


def _scan_tar(stream, archive_size):
    """Bound raw headers before any JSON parsing; never invoke tarfile.

    Reject all extended headers before reading their declared bodies, including
    small path/size overrides and huge GNU/PAX allocations. Bodies and padding
    are consumed in constant memory; member metadata is capped by MAX_MEMBERS.
    """
    if archive_size % BLOCK_BYTES:
        raise VerificationError('INCOMPLETE_TAR_BLOCKS')
    members = {}
    while stream.tell() < archive_size:
        header = stream.read(BLOCK_BYTES)
        if len(header) != BLOCK_BYTES:
            raise VerificationError('INCOMPLETE_TAR_HEADER')
        if header == bytes(BLOCK_BYTES):
            if stream.read(BLOCK_BYTES) != bytes(BLOCK_BYTES):
                raise VerificationError('INCOMPLETE_TAR_END_MARKER')
            while block := stream.read(COPY_BYTES):
                if any(block):
                    raise VerificationError('HIDDEN_DATA_AFTER_TAR_END')
            return members
        if len(members) >= MAX_MEMBERS:
            raise VerificationError('TAR_MEMBER_LIMIT_EXCEEDED')
        checksum = _tar_number(header[148:156], 512 * 255)
        if checksum != sum(header[:148] + b' ' * 8 + header[156:]):
            raise VerificationError('INVALID_TAR_HEADER_CHECKSUM')
        kind = header[156:157]
        if kind in EXTENSION_TYPES:
            raise VerificationError('UNSUPPORTED_TAR_EXTENSION')
        if kind not in (b'0', b'\0', b'5') or any(header[157:257]):
            raise VerificationError('UNSAFE_TAR_MEMBER_TYPE')
        magic = header[257:265]
        if magic not in (b'ustar\x0000', b'ustar  \x00'):
            raise VerificationError('UNSUPPORTED_TAR_FORMAT')
        prefix = _header_text(header[345:500])
        if magic == b'ustar  \x00' and prefix:
            raise VerificationError('UNSUPPORTED_GNU_TAR_METADATA')
        name = _header_text(header[:100])
        if prefix:
            name = prefix + '/' + name
        name = _safe_member_name(name, kind == b'5')
        if name in members:
            raise VerificationError('DUPLICATE_TAR_MEMBER_PATH')
        size = _tar_number(header[124:136], MAX_ARCHIVE_BYTES)
        for field, maximum in ((header[100:108], 0o7777), (header[108:116], 2**32 - 1),
                               (header[116:124], 2**32 - 1), (header[136:148], 2**63 - 1)):
            _tar_number(field, maximum)
        if kind == b'5' and size:
            raise VerificationError('NONEMPTY_TAR_DIRECTORY')
        offset = stream.tell()
        padded_size = (size + BLOCK_BYTES - 1) // BLOCK_BYTES * BLOCK_BYTES
        if offset + padded_size > archive_size:
            raise VerificationError('INCOMPLETE_TAR_MEMBER')
        members[name] = Member(offset, size, kind == b'5')
        stream.seek(size, os.SEEK_CUR)
        if any(stream.read(padded_size - size)):
            raise VerificationError('NONZERO_TAR_MEMBER_PADDING')
    raise VerificationError('INCOMPLETE_TAR_END_MARKER')


def _json(body):
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError('DUPLICATE_JSON_FIELD')
            result[key] = value
        return result

    def no_constant(_value):
        raise VerificationError('NONFINITE_JSON_NUMBER')

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise VerificationError('NONFINITE_JSON_NUMBER')
        return number

    def bounded_integer(value):
        if len(value.lstrip('-')) > 64:
            raise VerificationError('JSON_INTEGER_LIMIT_EXCEEDED')
        return int(value)

    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=unique_fields,
                           parse_constant=no_constant, parse_float=finite_float, parse_int=bounded_integer)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise VerificationError('INVALID_JSON') from None
    except ValueError as failure:
        if isinstance(failure, VerificationError):
            raise
        raise VerificationError('INVALID_JSON') from None
    pending, nodes = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise VerificationError('JSON_STRUCTURE_LIMIT_EXCEEDED')
        if isinstance(node, dict):
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
    return value


def _read_member(stream, members, name, maximum=MAX_JSON_BYTES):
    member = members.get(name)
    if member is None or member.directory or not 0 < member.size <= maximum:
        raise VerificationError('MISSING_OR_UNBOUNDED_METADATA_MEMBER')
    stream.seek(member.offset)
    body = stream.read(member.size)
    if len(body) != member.size:
        raise VerificationError('INCOMPLETE_TAR_MEMBER')
    return body


def _metadata_budget(members, layers):
    layer_names = set(layers)
    if sum(member.size for name, member in members.items()
           if not member.directory and name not in layer_names) > MAX_METADATA_BYTES:
        raise VerificationError('TOTAL_METADATA_SIZE_LIMIT_EXCEEDED')


def _hash_member(stream, member):
    stream.seek(member.offset)
    remaining, digest = member.size, hashlib.sha256()
    while remaining:
        block = stream.read(min(COPY_BYTES, remaining))
        if not block:
            raise VerificationError('INCOMPLETE_TAR_MEMBER')
        digest.update(block)
        remaining -= len(block)
    return digest.hexdigest()


def _annotations(value):
    if (not isinstance(value, dict) or len(value) > 64
            or any(not isinstance(item, str) or not 0 < len(key) <= 256 or len(item) > 1024
                   for key, item in value.items())):
        raise VerificationError('INVALID_OCI_ANNOTATIONS')


def _descriptor(value, members, allowed_types):
    if (not isinstance(value, dict) or not {'mediaType', 'digest', 'size'} <= set(value)
            or set(value) - {'mediaType', 'digest', 'size', 'annotations', 'platform', 'urls'}
            or not isinstance(value['mediaType'], str) or value['mediaType'] not in allowed_types
            or not isinstance(value['digest'], str) or not IMAGE_ID.fullmatch(value['digest'])
            or type(value['size']) is not int or not 0 < value['size'] <= MAX_ARCHIVE_BYTES):
        raise VerificationError('INVALID_OR_UNSUPPORTED_OCI_DESCRIPTOR')
    if value.get('urls') not in (None, []):
        raise VerificationError('EXTERNAL_LAYER_URLS_UNSUPPORTED')
    if 'annotations' in value:
        _annotations(value['annotations'])
    if 'platform' in value:
        platform = value['platform']
        if (not isinstance(platform, dict) or not {'architecture', 'os'} <= set(platform)
                or set(platform) - {'architecture', 'os', 'os.version', 'os.features', 'variant'}
                or any(not isinstance(platform[key], str) or not 0 < len(platform[key]) <= 128
                       for key in platform if key != 'os.features')
                or ('os.features' in platform and (not isinstance(platform['os.features'], list)
                    or len(platform['os.features']) > 32
                    or any(not isinstance(item, str) or len(item) > 128 for item in platform['os.features'])))):
            raise VerificationError('INVALID_OCI_PLATFORM')
    name = 'blobs/sha256/' + value['digest'][7:]
    member = members.get(name)
    if member is None or member.directory or member.size != value['size']:
        raise VerificationError('OCI_DESCRIPTOR_MEMBER_SIZE_MISMATCH')
    return name


def _verify_oci_graph(stream, members, image, config, expected_image_id):
    layout = _json(_read_member(stream, members, 'oci-layout'))
    if layout != {'imageLayoutVersion': '1.0.0'}:
        raise VerificationError('UNSUPPORTED_OCI_LAYOUT_VERSION')
    index = _json(_read_member(stream, members, 'index.json'))
    if (not isinstance(index, dict) or not {'schemaVersion', 'manifests'} <= set(index)
            or set(index) - {'schemaVersion', 'mediaType', 'manifests', 'annotations'}
            or type(index['schemaVersion']) is not int or index['schemaVersion'] != 2
            or index.get('mediaType', OCI_INDEX) != OCI_INDEX
            or not isinstance(index['manifests'], list) or not 1 <= len(index['manifests']) <= 64):
        raise VerificationError('INVALID_OR_UNSUPPORTED_OCI_INDEX')
    if 'annotations' in index:
        _annotations(index['annotations'])
    manifest_names = {_descriptor(item, members, MANIFEST_TYPES | {OCI_INDEX}) for item in index['manifests']}
    if len(manifest_names) != 1:
        raise VerificationError('SINGLE_OCI_IMAGE_MANIFEST_REQUIRED')
    root_name = manifest_names.pop()
    root_descriptor = index['manifests'][0]
    attestation_descriptors, nested_names = [], set()
    if root_descriptor['mediaType'] == OCI_INDEX:
        nested = _json(_read_member(stream, members, root_name))
        if (not isinstance(nested, dict) or set(nested) - {'schemaVersion', 'mediaType', 'manifests', 'annotations'}
                or type(nested.get('schemaVersion')) is not int or nested['schemaVersion'] != 2
                or nested.get('mediaType') != OCI_INDEX or not isinstance(nested.get('manifests'), list)
                or not 1 <= len(nested['manifests']) <= 16):
            raise VerificationError('INVALID_NESTED_OCI_IMAGE_INDEX')
        if 'annotations' in nested:
            _annotations(nested['annotations'])
        runnable = []
        for descriptor in nested['manifests']:
            name = _descriptor(descriptor, members, MANIFEST_TYPES)
            if name in nested_names:
                raise VerificationError('DUPLICATE_NESTED_OCI_MANIFEST')
            nested_names.add(name)
            annotations = descriptor.get('annotations', {})
            if annotations.get('vnd.docker.reference.type') == 'attestation-manifest':
                attestation_descriptors.append(descriptor)
            elif 'vnd.docker.reference.type' in annotations:
                raise VerificationError('UNSUPPORTED_NESTED_OCI_REFERENCE_TYPE')
            else:
                runnable.append(descriptor)
        if len(runnable) != 1:
            raise VerificationError('SINGLE_RUNNABLE_OCI_IMAGE_REQUIRED')
        main_descriptor = runnable[0]
        manifest_name = 'blobs/sha256/' + main_descriptor['digest'][7:]
    else:
        main_descriptor = root_descriptor
        manifest_name = root_name
    manifest = _json(_read_member(stream, members, manifest_name))
    if (not isinstance(manifest, dict) or not {'schemaVersion', 'config', 'layers'} <= set(manifest)
            or set(manifest) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
            or type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 2
            or not isinstance(manifest.get('mediaType', main_descriptor['mediaType']), str)
            or manifest.get('mediaType', main_descriptor['mediaType']) not in MANIFEST_TYPES
            or manifest.get('mediaType', main_descriptor['mediaType']) != main_descriptor['mediaType']
            or not isinstance(manifest['layers'], list) or not 1 <= len(manifest['layers']) <= MAX_LAYERS):
        raise VerificationError('INVALID_OR_UNSUPPORTED_OCI_IMAGE_MANIFEST')
    if 'annotations' in manifest:
        _annotations(manifest['annotations'])
    for descriptor in index['manifests']:
        if descriptor['mediaType'] != root_descriptor['mediaType']:
            raise VerificationError('OCI_INDEX_MEDIA_TYPE_MISMATCH')
    if 'platform' in main_descriptor:
        for key in ('architecture', 'os', 'variant', 'os.version'):
            if key in main_descriptor['platform'] and main_descriptor['platform'][key] != config.get(key):
                raise VerificationError('OCI_CONFIG_PLATFORM_MISMATCH')
    config_name = _descriptor(manifest['config'], members, CONFIG_TYPES)
    if config_name != image['Config']:
        raise VerificationError('OCI_DOCKER_CONFIG_MAPPING_MISMATCH')
    # Containerd-backed Docker may identify a built image by its OCI index,
    # not by config SHA. Accept only identities on the verified runnable path.
    if expected_image_id not in {root_descriptor['digest'], main_descriptor['digest'], manifest['config']['digest']}:
        raise VerificationError('EXPECTED_IMAGE_NOT_ON_RUNNABLE_OCI_PATH')
    layer_names = [_descriptor(item, members, LAYER_TYPES) for item in manifest['layers']]
    if layer_names != image['Layers']:
        raise VerificationError('OCI_DOCKER_LAYER_MAPPING_MISMATCH')
    sources = image.get('LayerSources')
    if sources not in (None, {}):
        diff_ids = config['rootfs']['diff_ids']
        if not isinstance(sources, dict) or set(sources) != set(diff_ids):
            raise VerificationError('INVALID_DOCKER_LAYER_SOURCES')
        for diff_id, layer_name, descriptor in zip(diff_ids, layer_names, manifest['layers']):
            source = sources[diff_id]
            if (_descriptor(source, members, LAYER_TYPES) != layer_name
                    or any(source[key] != descriptor[key] for key in ('mediaType', 'digest', 'size'))):
                raise VerificationError('OCI_DOCKER_LAYER_SOURCES_MISMATCH')
    referenced = {'manifest.json', 'index.json', 'oci-layout', config_name, root_name, manifest_name,
                  *nested_names, *layer_names}
    for descriptor in attestation_descriptors:
        if (descriptor.get('annotations', {}).get('vnd.docker.reference.digest') != main_descriptor['digest']
                or descriptor.get('platform') != {'architecture': 'unknown', 'os': 'unknown'}):
            raise VerificationError('ATTESTATION_RUNNABLE_REFERENCE_MISMATCH')
        name = 'blobs/sha256/' + descriptor['digest'][7:]
        attestation = _json(_read_member(stream, members, name))
        if (not isinstance(attestation, dict) or set(attestation) - {'schemaVersion', 'mediaType', 'config', 'layers', 'annotations'}
                or type(attestation.get('schemaVersion')) is not int or attestation['schemaVersion'] != 2
                or attestation.get('mediaType') != descriptor['mediaType']
                or not isinstance(attestation.get('layers'), list) or not 1 <= len(attestation['layers']) <= 16):
            raise VerificationError('INVALID_ATTESTATION_MANIFEST')
        if 'annotations' in attestation:
            _annotations(attestation['annotations'])
        attestation_config_name = _descriptor(attestation.get('config'), members, CONFIG_TYPES)
        attestation_config = _json(_read_member(stream, members, attestation_config_name))
        if (not isinstance(attestation_config, dict) or attestation_config.get('architecture') != 'unknown'
                or attestation_config.get('os') != 'unknown'
                or attestation_config.get('rootfs') != {'type': 'layers', 'diff_ids': [layer.get('digest') for layer in attestation['layers']]}):
            raise VerificationError('INVALID_NONRUNNABLE_ATTESTATION_CONFIG')
        referenced.add(attestation_config_name)
        for layer in attestation['layers']:
            layer_name = _descriptor(layer, members, ATTESTATION_LAYER_TYPES)
            if not isinstance(_json(_read_member(stream, members, layer_name)), dict):
                raise VerificationError('INVALID_ATTESTATION_JSON')
            referenced.add(layer_name)
    # Hash every blob, including optional Moby legacy V1 config metadata. No
    # unreferenced image manifests, indexes, or opaque layers are accepted.
    for name, member in members.items():
        if member.directory:
            if name not in ('blobs', 'blobs/sha256'):
                raise VerificationError('UNSUPPORTED_OCI_MEMBER')
        elif match := BLOB_NAME.fullmatch(name):
            if _hash_member(stream, member) != match[1]:
                raise VerificationError('OCI_BLOB_SHA256_MISMATCH')
            if name not in referenced:
                legacy = _json(_read_member(stream, members, name))
                if (not isinstance(legacy, dict) or not isinstance(legacy.get('id'), str)
                        or not HEX.fullmatch(legacy['id'])
                        or not isinstance(legacy.get('architecture'), str)
                        or not isinstance(legacy.get('os'), str)
                        or not isinstance(legacy.get('config'), dict)
                        or any(key in legacy for key in ('rootfs', 'schemaVersion', 'manifests', 'layers'))):
                    raise VerificationError('UNSUPPORTED_UNREFERENCED_OCI_BLOB')
        elif name not in referenced and name != 'repositories':
            raise VerificationError('UNSUPPORTED_OCI_MEMBER')


def _verify_manifest(stream, members, expected_image_id):
    hybrid = any(name in ('index.json', 'oci-layout', 'blobs') or name.startswith('blobs/')
                 for name in members)
    if 'manifest.json' not in members and hybrid:
        raise VerificationError('PURE_OCI_ARCHIVE_UNSUPPORTED')
    manifest = _json(_read_member(stream, members, 'manifest.json'))
    if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict):
        raise VerificationError('SINGLE_DOCKER_SAVE_IMAGE_REQUIRED')
    image = manifest[0]
    if (not {'Config', 'RepoTags', 'Layers'} <= set(image)
            or set(image) - {'Config', 'RepoTags', 'Layers', 'Parent', 'LayerSources'}):
        raise VerificationError('INVALID_DOCKER_SAVE_MANIFEST')
    if image.get('Parent') not in (None, ''):
        raise VerificationError('UNSUPPORTED_PARENT_IMAGE')
    if not hybrid and image.get('LayerSources') not in (None, {}):
        raise VerificationError('UNSUPPORTED_LEGACY_LAYER_SOURCES')
    config_name, layers, tags = image['Config'], image['Layers'], image['RepoTags']
    reference_pattern = BLOB_NAME if hybrid else CONFIG_NAME
    if not isinstance(config_name, str) or not reference_pattern.fullmatch(config_name):
        raise VerificationError('UNSUPPORTED_CONFIG_REFERENCE')
    expected_config_name = ('blobs/sha256/' + expected_image_id[7:] if hybrid
                            else expected_image_id[7:] + '.json')
    if not hybrid and config_name != expected_config_name:
        raise VerificationError('EXPECTED_IMAGE_CONFIG_REFERENCE_MISMATCH')
    if (not isinstance(layers, list) or not 1 <= len(layers) <= MAX_LAYERS
            or any(not isinstance(layer, str) or not (BLOB_NAME if hybrid else LAYER_NAME).fullmatch(layer)
                   for layer in layers)):
        raise VerificationError('INVALID_OR_UNSUPPORTED_LAYER_REFERENCES')
    if tags is not None and (not isinstance(tags, list) or len(tags) > 64
                             or any(not isinstance(tag, str) or not TAG_TEXT.fullmatch(tag) for tag in tags)
                             or len(set(tags)) != len(tags)):
        raise VerificationError('INVALID_REPOSITORY_TAGS')
    _metadata_budget(members, layers)
    config_bytes = _read_member(stream, members, config_name)
    expected_config_digest = 'sha256:' + config_name.rsplit('/', 1)[-1] if hybrid else expected_image_id
    if 'sha256:' + hashlib.sha256(config_bytes).hexdigest() != expected_config_digest:
        raise VerificationError('EXPECTED_IMAGE_CONFIG_SHA256_MISMATCH')
    config = _json(config_bytes)
    if (not isinstance(config, dict) or not isinstance(config.get('rootfs'), dict)
            or not isinstance(config.get('architecture'), str)
            or not re.fullmatch(r'[a-z0-9_+-]{1,64}', config['architecture'])
            or not isinstance(config.get('os'), str)
            or not re.fullmatch(r'[a-z0-9_+-]{1,64}', config['os'])):
        raise VerificationError('INVALID_IMAGE_CONFIG')
    rootfs = config['rootfs']
    diff_ids = rootfs.get('diff_ids')
    if (set(rootfs) != {'type', 'diff_ids'} or rootfs['type'] != 'layers'
            or not isinstance(diff_ids, list) or len(diff_ids) != len(layers)
            or any(not isinstance(item, str) or not IMAGE_ID.fullmatch(item) for item in diff_ids)):
        raise VerificationError('INVALID_CONFIG_ROOTFS_REFERENCES')
    layer_directories = {layer.split('/')[0] for layer in layers} if not hybrid else set()
    for layer in layers:
        member = members.get(layer)
        if member is None or member.directory or not 0 < member.size <= MAX_ARCHIVE_BYTES:
            raise VerificationError('MISSING_OR_UNBOUNDED_LAYER_MEMBER')
    if hybrid:
        _verify_oci_graph(stream, members, image, config, expected_image_id)
    for name, member in members.items():
        if hybrid and name != 'repositories':
            continue
        if member.directory:
            if name not in layer_directories:
                raise VerificationError('UNSUPPORTED_DOCKER_SAVE_MEMBER')
        elif name in ('manifest.json', config_name) or name in layers:
            continue
        elif name == 'repositories':
            repositories = _json(_read_member(stream, members, name))
            if not isinstance(repositories, dict) or len(repositories) > 64:
                raise VerificationError('INVALID_LEGACY_REPOSITORIES')
            for repository, repository_tags in repositories.items():
                if (not TAG_TEXT.fullmatch(repository) or not isinstance(repository_tags, dict)
                        or not 1 <= len(repository_tags) <= 64):
                    raise VerificationError('INVALID_LEGACY_REPOSITORIES')
                for tag, layer_id in repository_tags.items():
                    top_layer_id = diff_ids[-1][7:] if hybrid else layers[-1].split('/')[0]
                    if (not TAG_TEXT.fullmatch(tag) or layer_id != top_layer_id
                            or tags is None or repository + ':' + tag not in tags):
                        raise VerificationError('INVALID_LEGACY_REPOSITORIES')
        elif (match := LEGACY_MEMBER.fullmatch(name)) and match[1] in layer_directories:
            if match[2] == 'json':
                if not isinstance(_json(_read_member(stream, members, name)), dict):
                    raise VerificationError('INVALID_LEGACY_LAYER_METADATA')
            elif _read_member(stream, members, name, 16) not in (b'1.0', b'1.0\n'):
                raise VerificationError('INVALID_LEGACY_LAYER_VERSION')
        else:
            raise VerificationError('UNSUPPORTED_DOCKER_SAVE_MEMBER')
    return len(layers), ('DOCKER_SAVE_OCI_HYBRID_SINGLE_IMAGE' if hybrid
                         else 'DOCKER_SAVE_LEGACY_SINGLE_IMAGE')


def _result(verified=False, code='IMAGE_VERIFICATION_FAILED'):
    return {'format': FORMAT, 'scope': 'LOCAL_READ_ONLY_DOCKER_SAVE_IMMUTABLE_IDENTITY_ONLY',
            'image_archive_verified': verified, 'code': code,
            'archive_format': 'UNVERIFIED',
            'expected_identity_source': 'CALLER_SUPPLIED_NOT_AUTHENTICATED',
            'rootfs_integrity_verified': False, 'rootfs_diff_ids_verified': False,
            'aws_origin_independently_authenticated': False, 'release_ready': False,
            'attestation_authenticity_verified': False,
            'legacy_app_v34_on_schema36_verified': False,
            'docker_calls': False, 'aws_calls': False, 'archive_extracted': False,
            'archive_loaded': False, 'source_artifacts_modified': False}


def verify_image(archive, expected_image_id, *, expected_sha256=None, private_root=None):
    """Return sanitized evidence; an invalid expected ID/hash raises ValueError."""
    if not isinstance(expected_image_id, str) or not IMAGE_ID.fullmatch(expected_image_id):
        raise VerificationError('IMMUTABLE_EXPECTED_IMAGE_ID_REQUIRED')
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                        or not HEX.fullmatch(expected_sha256)):
        raise VerificationError('INVALID_EXPECTED_ARCHIVE_SHA256')
    try:
        with _private_archive(archive, PRIVATE_ROOT if private_root is None else private_root) as (stream, before):
            digest = _hash_archive(stream, before)
            if expected_sha256 is not None and digest != expected_sha256:
                raise VerificationError('EXPECTED_ARCHIVE_SHA256_MISMATCH')
            members = _scan_tar(stream, before.st_size)
            layer_count, archive_format = _verify_manifest(stream, members, expected_image_id)
            if _metadata_identity(before) != _metadata_identity(os.fstat(stream.fileno())):
                raise VerificationError('ARCHIVE_CHANGED_DURING_VERIFICATION')
        result = _result(True, 'PRIVATE_DOCKER_SAVE_CONFIG_IDENTITY_VERIFIED')
        result.update(verified_image_id=expected_image_id, archive_sha256=digest, archive_format=archive_format,
                      layer_count=layer_count, tar_member_count=len(members))
        return result
    except VerificationError as failure:
        return _result(code=str(failure))
    except (OSError, ValueError):
        return _result(code='PRIVATE_ARCHIVE_UNAVAILABLE')


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise VerificationError('INVALID_CLI_ARGUMENTS')


def main():
    parser = _Parser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--expected-image-id', required=True)
    parser.add_argument('--expected-sha256')
    try:
        args = parser.parse_args()
        result = verify_image(args.archive, args.expected_image_id,
                              expected_sha256=args.expected_sha256)
    except VerificationError as failure:
        print(json.dumps(_result(code=str(failure)), sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['image_archive_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
