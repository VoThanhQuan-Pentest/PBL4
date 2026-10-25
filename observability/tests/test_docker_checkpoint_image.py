"""Small private fixtures only: no Docker, AWS, extraction or executable layers."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/verify-docker-checkpoint-image.py'
SPEC = importlib.util.spec_from_file_location('docker_checkpoint_image', SCRIPT)
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)
SECRET = 'PRIVATE_ENV_SENTINEL_NEVER_OUTPUT'


def json_bytes(value):
    return json.dumps(value, separators=(',', ':')).encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def config_bytes():
    return json_bytes({'architecture': 'amd64', 'os': 'linux',
                       'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]},
                       'config': {'Env': ['SECRET=' + SECRET]}})


def classic_entries(body=None):
    body = config_bytes() if body is None else body
    config_name, layer_id = digest(body) + '.json', 'b' * 64
    manifest = [{'Config': config_name, 'RepoTags': ['fixture:local'],
                 'Layers': [layer_id + '/layer.tar']}]
    entries = [('manifest.json', json_bytes(manifest)), (config_name, body),
               (layer_id + '/', None), (layer_id + '/layer.tar', b'opaque layer fixture'),
               (layer_id + '/json', json_bytes({'id': layer_id})),
               (layer_id + '/VERSION', b'1.0'),
               ('repositories', json_bytes({'fixture': {'local': layer_id}}))]
    return entries, 'sha256:' + digest(body)


def hybrid_entries(*, compressed=False, mutate_manifest=None, mutate_index=None,
                   mutate_compat=None, legacy=True):
    config = config_bytes()
    config_name = 'blobs/sha256/' + digest(config)
    layer = gzip.compress(b'opaque compressed layer fixture', mtime=0) if compressed else b'opaque layer fixture'
    layer_name = 'blobs/sha256/' + digest(layer)
    config_descriptor = {'mediaType': 'application/vnd.oci.image.config.v1+json',
                         'digest': 'sha256:' + digest(config), 'size': len(config)}
    layer_descriptor = {'mediaType': 'application/vnd.oci.image.layer.v1.tar' + ('+gzip' if compressed else ''),
                        'digest': 'sha256:' + digest(layer), 'size': len(layer)}
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': config_descriptor, 'layers': [layer_descriptor]}
    if mutate_manifest:
        mutate_manifest(manifest)
    manifest_body = json_bytes(manifest)
    manifest_name = 'blobs/sha256/' + digest(manifest_body)
    index = {'schemaVersion': 2, 'mediaType': verifier.OCI_INDEX,
             'manifests': [{'mediaType': manifest['mediaType'],
                            'digest': 'sha256:' + digest(manifest_body), 'size': len(manifest_body)}]}
    if mutate_index:
        mutate_index(index)
    compat = [{'Config': config_name, 'RepoTags': None, 'Layers': [layer_name],
               'LayerSources': {'sha256:' + 'a' * 64: dict(layer_descriptor)}}]
    if mutate_compat:
        mutate_compat(compat[0])
    entries = [('blobs/', None), ('blobs/sha256/', None), (config_name, config),
               (layer_name, layer), (manifest_name, manifest_body), ('index.json', json_bytes(index)),
               ('manifest.json', json_bytes(compat)),
               ('oci-layout', json_bytes({'imageLayoutVersion': '1.0.0'}))]
    if legacy:
        old_config = json_bytes({'id': 'c' * 64, 'architecture': 'amd64', 'os': 'linux',
                                 'config': {'Env': [SECRET]}, 'container_config': {}})
        entries.append(('blobs/sha256/' + digest(old_config), old_config))
    return entries, 'sha256:' + digest(config)


def indexed_attestation_entries(*, wrong_subject=False, wrong_platform=False):
    entries, config_id = hybrid_entries(legacy=False)
    bodies = {name: body for name, body in entries if body is not None}
    direct = json.loads(bodies['index.json'])
    main = direct['manifests'][0]
    main['platform'] = {'architecture': 'amd64', 'os': 'linux'}
    provenance = json_bytes({'_type': 'https://in-toto.io/Statement/v0.1', 'predicate': {}})
    provenance_descriptor = {'mediaType': 'application/vnd.in-toto+json', 'digest': 'sha256:' + digest(provenance), 'size': len(provenance)}
    attestation_config = json_bytes({'architecture': 'unknown', 'os': 'unknown', 'config': {},
                                    'rootfs': {'type': 'layers', 'diff_ids': [provenance_descriptor['digest']]}})
    attestation = json_bytes({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                             'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                        'digest': 'sha256:' + digest(attestation_config), 'size': len(attestation_config)},
                             'layers': [provenance_descriptor]})
    attestation_descriptor = {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                              'digest': 'sha256:' + digest(attestation), 'size': len(attestation),
                              'platform': {'architecture': 'amd64' if wrong_platform else 'unknown', 'os': 'unknown'},
                              'annotations': {'vnd.docker.reference.type': 'attestation-manifest',
                                              'vnd.docker.reference.digest': 'sha256:' + '0' * 64 if wrong_subject else main['digest']}}
    nested = json_bytes({'schemaVersion': 2, 'mediaType': verifier.OCI_INDEX, 'manifests': [main, attestation_descriptor]})
    expected = 'sha256:' + digest(nested)
    top = json_bytes({'schemaVersion': 2, 'mediaType': verifier.OCI_INDEX,
                      'manifests': [{'mediaType': verifier.OCI_INDEX, 'digest': expected, 'size': len(nested)}]})
    entries = [(name, top if name == 'index.json' else body) for name, body in entries]
    entries.extend(('blobs/sha256/' + digest(body), body) for body in (provenance, attestation_config, attestation, nested))
    return entries, expected, config_id, attestation_descriptor['digest']


def tar_bytes(entries, archive_format=tarfile.USTAR_FORMAT):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=archive_format) as archive:
        for name, body in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if body is None else 0o644
            if body is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
    return result.getvalue()


class DockerCheckpointImageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.archive = self.root / 'fixture.tar'

    def check(self, entries, image_id, *, raw=None, **kwargs):
        self.archive.write_bytes(tar_bytes(entries) if raw is None else raw)
        self.archive.chmod(0o600)
        result = verifier.verify_image(self.archive, image_id, private_root=self.root, **kwargs)
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))
        return result

    def assert_failed(self, result, code=None):
        self.assertFalse(result['image_archive_verified'])
        self.assertEqual(result['archive_format'], 'UNVERIFIED')
        if code:
            self.assertEqual(result['code'], code)

    def test_classic_ustar_and_gnu_save_config_identity_without_rootfs_or_aws_claim(self):
        entries, image_id = classic_entries()
        for archive_format in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT):
            with self.subTest(archive_format=archive_format):
                result = self.check(entries, image_id, raw=tar_bytes(entries, archive_format))
                self.assertTrue(result['image_archive_verified'], result)
                self.assertEqual(result['verified_image_id'], image_id)
                self.assertEqual(result['layer_count'], 1)
                self.assertEqual(result['archive_format'], 'DOCKER_SAVE_LEGACY_SINGLE_IMAGE')
                for field in ('rootfs_integrity_verified', 'rootfs_diff_ids_verified',
                              'aws_origin_independently_authenticated', 'release_ready',
                              'legacy_app_v34_on_schema36_verified', 'docker_calls',
                              'aws_calls', 'archive_extracted', 'archive_loaded', 'source_artifacts_modified'):
                    self.assertFalse(result[field], field)

    def test_hybrid_native_layout_and_opaque_compressed_layers_have_consistent_graph(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                entries, image_id = hybrid_entries(compressed=compressed)
                result = self.check(entries, image_id)
                self.assertTrue(result['image_archive_verified'], result)
                self.assertEqual(result['archive_format'], 'DOCKER_SAVE_OCI_HYBRID_SINGLE_IMAGE')
                self.assertFalse(result['rootfs_diff_ids_verified'])
                self.assertFalse(result['aws_origin_independently_authenticated'])

    def test_archive_hash_is_optional_additional_proof_not_a_substitute_for_config_id(self):
        entries, image_id = classic_entries()
        raw = tar_bytes(entries)
        self.assertTrue(self.check(entries, image_id, expected_sha256=digest(raw))['image_archive_verified'])
        self.assert_failed(self.check(entries, image_id, expected_sha256='f' * 64),
                           'EXPECTED_ARCHIVE_SHA256_MISMATCH')
        self.assert_failed(self.check(entries, 'sha256:' + 'f' * 64, expected_sha256=digest(raw)),
                           'EXPECTED_IMAGE_CONFIG_REFERENCE_MISMATCH')

    def test_config_tamper_retaining_old_filename_fails_exact_byte_sha256(self):
        entries, image_id = classic_entries()
        entries[1] = (entries[1][0], config_bytes() + b' ')
        self.assert_failed(self.check(entries, image_id), 'EXPECTED_IMAGE_CONFIG_SHA256_MISMATCH')

    def test_pure_oci_missing_hybrid_metadata_and_nested_indexes_fail_closed(self):
        entries, image_id = hybrid_entries()
        self.assert_failed(self.check([item for item in entries if item[0] != 'manifest.json'], image_id),
                           'PURE_OCI_ARCHIVE_UNSUPPORTED')
        self.assert_failed(self.check([item for item in entries if item[0] != 'index.json'], image_id),
                           'MISSING_OR_UNBOUNDED_METADATA_MEMBER')
        entries, image_id = hybrid_entries(mutate_index=lambda index: index['manifests'][0].update(mediaType=verifier.OCI_INDEX))
        self.assert_failed(self.check(entries, image_id), 'INVALID_NESTED_OCI_IMAGE_INDEX')

    def test_actual_style_built_index_identity_and_attestation_graph_are_verified_without_trusting_provenance(self):
        entries, index_id, config_id, attestation_id = indexed_attestation_entries()
        for identity in (index_id, config_id):
            result = self.check(entries, identity)
            self.assertTrue(result['image_archive_verified'], result)
            self.assertEqual(result['verified_image_id'], identity)
            self.assertFalse(result['attestation_authenticity_verified'])
            self.assertFalse(result['release_ready'])
        self.assert_failed(self.check(entries, attestation_id), 'EXPECTED_IMAGE_NOT_ON_RUNNABLE_OCI_PATH')

    def test_attestation_cannot_reference_other_image_or_be_presented_as_runnable(self):
        for options in ({'wrong_subject': True}, {'wrong_platform': True}):
            entries, image_id, _, _ = indexed_attestation_entries(**options)
            self.assert_failed(self.check(entries, image_id), 'ATTESTATION_RUNNABLE_REFERENCE_MISMATCH')

    def test_index_blob_tampering_and_unrelated_expected_identity_are_refused(self):
        entries, image_id, _, _ = indexed_attestation_entries()
        self.assert_failed(self.check(entries, 'sha256:' + '1' * 64), 'EXPECTED_IMAGE_NOT_ON_RUNNABLE_OCI_PATH')
        changed = [(name, body + b' ' if name == 'blobs/sha256/' + image_id[7:] else body) for name, body in entries]
        self.assert_failed(self.check(changed, image_id), 'OCI_DESCRIPTOR_MEMBER_SIZE_MISMATCH')

    def test_oci_blob_tamper_sizes_and_layer_source_mapping_fail(self):
        entries, image_id = hybrid_entries()
        entries[3] = (entries[3][0], b'tampered layer bytes!')
        self.assert_failed(self.check(entries, image_id))
        entries, image_id = hybrid_entries(mutate_manifest=lambda manifest: manifest['layers'][0].update(size=1))
        self.assert_failed(self.check(entries, image_id), 'OCI_DESCRIPTOR_MEMBER_SIZE_MISMATCH')
        entries, image_id = hybrid_entries(mutate_compat=lambda image: image['LayerSources'].update({'sha256:' + 'f' * 64: {}}))
        self.assert_failed(self.check(entries, image_id), 'INVALID_DOCKER_LAYER_SOURCES')

    def test_oci_mapping_different_layer_or_config_is_not_accepted(self):
        entries, image_id = hybrid_entries(mutate_compat=lambda image: image['Layers'].__setitem__(0, image['Config']))
        self.assert_failed(self.check(entries, image_id), 'OCI_DOCKER_LAYER_MAPPING_MISMATCH')
        def use_layer_as_config(manifest):
            manifest['config'].update(digest=manifest['layers'][0]['digest'], size=manifest['layers'][0]['size'])
        entries, image_id = hybrid_entries(mutate_manifest=use_layer_as_config)
        self.assert_failed(self.check(entries, image_id), 'OCI_DOCKER_CONFIG_MAPPING_MISMATCH')

    def test_oci_external_urls_unknown_media_boolean_size_and_platform_mismatch_rejected(self):
        mutations = (lambda manifest: manifest['layers'][0].update(urls=['https://invalid.example/private']),
                     lambda manifest: manifest['layers'][0].update(mediaType='unknown'),
                     lambda manifest: manifest['layers'][0].update(size=True),
                     lambda manifest: manifest.update(mediaType=[]),
                     lambda manifest: manifest.update(config=None),
                     lambda manifest: manifest.update(layers=['invalid']),
                     lambda manifest: manifest.update(annotations=SECRET))
        for mutation in mutations:
            entries, image_id = hybrid_entries(mutate_manifest=mutation)
            self.assert_failed(self.check(entries, image_id))
        entries, image_id = hybrid_entries(mutate_index=lambda index: index['manifests'][0].update(platform={'os': 'windows', 'architecture': 'amd64'}))
        self.assert_failed(self.check(entries, image_id), 'OCI_CONFIG_PLATFORM_MISMATCH')

    def test_unreferenced_opaque_blobs_are_not_hidden_graph_members(self):
        entries, image_id = hybrid_entries()
        body = b'unreferenced layer data'
        entries.append(('blobs/sha256/' + digest(body), body))
        self.assert_failed(self.check(entries, image_id), 'INVALID_JSON')

    def test_missing_layer_and_multiple_image_manifest_rejected(self):
        entries, image_id = classic_entries()
        self.assert_failed(self.check([entry for entry in entries if not entry[0].endswith('/layer.tar')], image_id),
                           'MISSING_OR_UNBOUNDED_LAYER_MEMBER')
        manifest = json.loads(entries[0][1])
        entries[0] = ('manifest.json', json_bytes(manifest + manifest))
        self.assert_failed(self.check(entries, image_id), 'SINGLE_DOCKER_SAVE_IMAGE_REQUIRED')

    def test_manifest_path_aliases_and_unknown_fields_fail(self):
        for field, value in (('Config', './' + digest(config_bytes()) + '.json'),
                             ('Layers', ['../private/layer.tar']), ('unknown', SECRET),
                             ('LayerSources', {'untrusted': {}}), ('Parent', 'sha256:' + 'f' * 64)):
            entries, image_id = classic_entries()
            manifest = json.loads(entries[0][1])
            manifest[0][field] = value
            entries[0] = ('manifest.json', json_bytes(manifest))
            self.assert_failed(self.check(entries, image_id))

    def test_duplicate_paths_and_directory_aliases_rejected(self):
        entries, image_id = classic_entries()
        for added in (entries[0], ('b' * 64, None)):
            self.assert_failed(self.check(entries + [added], image_id), 'DUPLICATE_TAR_MEMBER_PATH')

    def test_absolute_traversal_backslash_dot_and_control_paths_rejected(self):
        entries, image_id = classic_entries()
        for name in ('/absolute', '../escape', 'part/../escape', 'part\\escape', './alias', 'two//parts', 'bad\nname'):
            with self.subTest(name=name):
                self.assert_failed(self.check(entries + [(name, b'x')], image_id), 'UNSAFE_TAR_MEMBER_PATH')

    def test_links_devices_fifo_and_contiguous_file_types_rejected(self):
        entries, image_id = classic_entries()
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.CONTTYPE):
            info = tarfile.TarInfo('unsafe')
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = '../' + SECRET
            raw = info.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
            self.assert_failed(self.check(entries, image_id, raw=raw), 'UNSAFE_TAR_MEMBER_TYPE')

    def test_extension_bombs_are_rejected_without_reading_or_tarfile_parsing(self):
        entries, image_id = classic_entries()
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            for size in (10, 2**40):
                info = tarfile.TarInfo('extension')
                info.type, info.size = kind, size
                raw = info.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024)
                with patch('tarfile.open', side_effect=AssertionError('must not parse tar')):
                    self.assert_failed(self.check(entries, image_id, raw=raw), 'UNSUPPORTED_TAR_EXTENSION')

    def test_json_duplicate_nested_nonfinite_overflow_integer_depth_and_truncation(self):
        bad_bodies = ((b'{"config":{"Env":"' + SECRET.encode() + b'","Env":[]}}', 'DUPLICATE_JSON_FIELD'),
                      (b'{"config":{"value":NaN}}', 'NONFINITE_JSON_NUMBER'),
                      (b'{"config":{"value":Infinity}}', 'NONFINITE_JSON_NUMBER'),
                      (b'{"config":{"value":1e9999}}', 'NONFINITE_JSON_NUMBER'),
                      (b'{"config":{"value":' + b'9' * 65 + b'}}', 'JSON_INTEGER_LIMIT_EXCEEDED'),
                      (b'[' * 30 + b'0' + b']' * 30, 'JSON_STRUCTURE_LIMIT_EXCEEDED'),
                      (b'{"Env":"' + SECRET.encode(), 'INVALID_JSON'), (b'\xff', 'INVALID_JSON'))
        for body, code in bad_bodies:
            with self.subTest(code=code):
                entries, image_id = classic_entries(body)
                self.assert_failed(self.check(entries, image_id), code)

    def test_json_metadata_and_structure_limits_are_bounded(self):
        entries, image_id = classic_entries(b' ' * (verifier.MAX_JSON_BYTES + 1))
        self.assert_failed(self.check(entries, image_id), 'MISSING_OR_UNBOUNDED_METADATA_MEMBER')
        with self.assertRaisesRegex(verifier.VerificationError, '^JSON_STRUCTURE_LIMIT_EXCEEDED$'):
            verifier._json(json_bytes([0] * (verifier.MAX_JSON_NODES + 1)))
        entries, image_id = classic_entries()
        with patch.object(verifier, 'MAX_METADATA_BYTES', 1):
            self.assert_failed(self.check(entries, image_id), 'TOTAL_METADATA_SIZE_LIMIT_EXCEEDED')

    def test_rootfs_count_and_diffid_format_must_match_declared_layers(self):
        for diff_ids in ([], ['mutable'], ['sha256:' + 'a' * 64] * 2):
            config = json.loads(config_bytes())
            config['rootfs']['diff_ids'] = diff_ids
            entries, image_id = classic_entries(json_bytes(config))
            self.assert_failed(self.check(entries, image_id), 'INVALID_CONFIG_ROOTFS_REFERENCES')

    def test_truncation_end_marker_hidden_bytes_checksum_and_padding_rejected(self):
        entries, image_id = classic_entries()
        raw = tar_bytes(entries)
        self.assert_failed(self.check(entries, image_id, raw=raw[:-1]), 'INCOMPLETE_TAR_BLOCKS')
        self.assert_failed(self.check(entries, image_id, raw=raw[:512]), 'INCOMPLETE_TAR_MEMBER')
        self.assert_failed(self.check(entries, image_id, raw=raw + b'x' * 512), 'HIDDEN_DATA_AFTER_TAR_END')
        damaged = bytearray(raw)
        damaged[0] ^= 1
        self.assert_failed(self.check(entries, image_id, raw=damaged), 'INVALID_TAR_HEADER_CHECKSUM')
        damaged = bytearray(raw)
        damaged[512 + len(entries[0][1])] = 1
        self.assert_failed(self.check(entries, image_id, raw=damaged), 'NONZERO_TAR_MEMBER_PADDING')

    def test_member_and_archive_size_limits_without_large_fixtures(self):
        entries, image_id = classic_entries()
        with patch.object(verifier, 'MAX_MEMBERS', 2):
            self.assert_failed(self.check(entries, image_id), 'TAR_MEMBER_LIMIT_EXCEEDED')
        with patch.object(verifier, 'MAX_ARCHIVE_BYTES', 512):
            self.assert_failed(self.check(entries, image_id), 'BOUNDED_0600_OWNED_REGULAR_ARCHIVE_REQUIRED')

    def test_0600_private_owned_regular_file_and_directory_required(self):
        entries, image_id = classic_entries()
        self.check(entries, image_id)
        for mode in (0o644, 0o400, 0o660, 0o700):
            self.archive.chmod(mode)
            self.assert_failed(verifier.verify_image(self.archive, image_id, private_root=self.root),
                               'BOUNDED_0600_OWNED_REGULAR_ARCHIVE_REQUIRED')
        self.archive.chmod(0o600)
        self.root.chmod(0o755)
        self.assert_failed(verifier.verify_image(self.archive, image_id, private_root=self.root),
                           'PRIVATE_DIRECTORY_PROTECTION_REQUIRED')
        self.root.chmod(0o700)
        hardlink = self.root / 'hardlink'
        os.link(self.archive, hardlink)
        self.assert_failed(verifier.verify_image(self.archive, image_id, private_root=self.root),
                           'BOUNDED_0600_OWNED_REGULAR_ARCHIVE_REQUIRED')

    def test_no_final_or_ancestor_symlinks_or_private_root_escape(self):
        entries, image_id = classic_entries()
        self.check(entries, image_id)
        link = self.root / 'link.tar'
        link.symlink_to(self.archive)
        self.assert_failed(verifier.verify_image(link, image_id, private_root=self.root))
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_failed(verifier.verify_image(alias / self.archive.name, image_id, private_root=self.root))
        self.assert_failed(verifier.verify_image(self.archive, image_id, private_root=self.root / 'other'),
                           'OUTSIDE_PRIVATE_BACKUP_ROOT')
        self.assert_failed(verifier.verify_image(self.root / '../private.tar', image_id, private_root=self.root),
                           'OUTSIDE_PRIVATE_BACKUP_ROOT')
        ancestor_alias = self.root.parent / (self.root.name + '-alias')
        ancestor_alias.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(ancestor_alias.unlink)
        self.assert_failed(verifier.verify_image(ancestor_alias / self.archive.name, image_id, private_root=ancestor_alias))

    def test_fifo_never_blocks_and_is_not_a_regular_file(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        self.assert_failed(verifier.verify_image(fifo, 'sha256:' + 'a' * 64, private_root=self.root),
                           'BOUNDED_0600_OWNED_REGULAR_ARCHIVE_REQUIRED')

    def test_same_descriptor_metadata_change_after_hash_prevents_success(self):
        entries, image_id = classic_entries()
        original = verifier._hash_archive
        def altered(stream, metadata):
            hashed = original(stream, metadata)
            os.fchmod(stream.fileno(), 0o400)
            return hashed
        with patch.object(verifier, '_hash_archive', side_effect=altered):
            self.assert_failed(self.check(entries, image_id), 'ARCHIVE_CHANGED_DURING_VERIFICATION')

    def test_expected_immutable_id_and_hash_are_required_before_open(self):
        for image_id in ('alpine:latest', 'sha256:' + 'A' * 64, 'sha256:abc', SECRET, None):
            with patch.object(verifier, '_private_archive') as opened:
                with self.assertRaisesRegex(verifier.VerificationError, '^IMMUTABLE_EXPECTED_IMAGE_ID_REQUIRED$'):
                    verifier.verify_image(self.archive, image_id, private_root=self.root)
                opened.assert_not_called()
        with self.assertRaisesRegex(verifier.VerificationError, '^INVALID_EXPECTED_ARCHIVE_SHA256$'):
            verifier.verify_image(self.archive, 'sha256:' + 'a' * 64, expected_sha256=SECRET)

    def test_cli_success_failure_and_argument_errors_never_print_private_values(self):
        entries, image_id = classic_entries()
        self.check(entries, image_id)
        cases = ((['--archive', str(self.archive), '--expected-image-id', image_id], 0),
                 (['--archive', str(self.archive), '--expected-image-id', 'sha256:' + 'f' * 64], 1),
                 (['--archive', str(self.archive), '--expected-image-id', SECRET], 2),
                 (['--unknown', SECRET], 2))
        for arguments, status in cases:
            with patch.object(verifier, 'PRIVATE_ROOT', self.root), \
                    patch('sys.argv', [str(SCRIPT), *arguments]), patch('builtins.print') as printed:
                self.assertEqual(verifier.main(), status)
                output = printed.call_args.args[0]
                self.assertNotIn(str(self.root), output)
                self.assertNotIn(SECRET, output)
                self.assertFalse(json.loads(output)['release_ready'])


if __name__ == '__main__':
    unittest.main()
