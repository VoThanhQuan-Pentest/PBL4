"""Protected per-fold STRICT_SOURCE labels; no holdout numeric reads or admission."""
import hashlib
import os
from pathlib import Path
import re
import stat

from app.catalog import MAX_SHARD_BYTES, ShardedDataset, parse_json, row_stats, utc, validate_rows
from app.hybrid_dataset import training_targets
from app.hybrid_strict_protocol import FOLD_TIMES, LABELED_ROWS, NORMAL_ROWS, SUPPLEMENT_ROWS
from app.policy import canonical

FORMAT = 'HYBRID_STRICT_LABELED_SOURCE_V1'


def digest(value): return hashlib.sha256(canonical(value).encode()).hexdigest()


def private_read(root, relative, maximum):
    if relative not in ('manifest.private.json', 'predeclared.private.json') and not re.fullmatch(
            r'(?:normal|supplement)/[a-z0-9_-]{8,128}\.json', relative):
        raise ValueError('strict training reader refuses calibration/validation/holdout paths')
    path = root / relative
    if path.is_symlink() or path.resolve().parent != path.parent or not path.resolve().is_relative_to(root):
        raise ValueError('canonical private source file required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= maximum):
            raise ValueError('bounded protected source file required')
        body = stream.read(maximum + 1); after = os.fstat(stream.fileno())
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if signature(before) != signature(after) or signature(before) != signature(path.lstat()) or len(body) != before.st_size:
            raise ValueError('source file changed during read')
        return body


def validate_standard_manifest(document, dataset_id, *, scoped_test=False):
    if (type(document) is not dict or type(document.get('splits')) is not dict
            or document.get('dataset_id') != dataset_id or document.get('feature_schema_version') != 4
            or document.get('telemetry_contract_version') != 3 or document.get('data_provenance') != 'DEMO_ONLY'
            or document.get('stage') != ('PILOT' if scoped_test else 'STRICT')):
        raise ValueError('fresh matching standard source identity required')
    for fold, fit_day, cal_day, val_day in FOLD_TIMES:
        fit = document['splits'][f'fold{fold}-fit']
        if (type(fit) is not dict or type(fit.get('records')) is not int or type(fit.get('positive')) is not int
                or fit['positive'] or fit['cohorts'] != {'READY': fit['records']} or fit['records'] != (2 if scoped_test else NORMAL_ROWS)):
            raise ValueError('matching-fold complete normal READY FIT required')
        if not scoped_test:
            for cohort in ('ready', 'cold'):
                part = document['splits'][f'fold{fold}-calibration-{cohort}']
                if part['normal'] != 1000000 or part['positive']:
                    raise ValueError('unchanged million normal calibration required')
            validation = document['splits'][f'fold{fold}-validation']
            if (validation['normal'], validation['positive']) != (1000000, 1000):
                raise ValueError('unchanged full validation required')
    if not scoped_test and (document['splits']['holdout']['normal'], document['splits']['holdout']['positive']) != (10000000, 10000):
        raise ValueError('unchanged unopened holdout descriptor required')


def _load_hybrid_strict_fit(root, expected_sha256, *, allow_scoped_test=False):
    root = Path(root).absolute()
    if (root.resolve() != root or root.stat().st_uid != os.geteuid() or stat.S_IMODE(root.stat().st_mode) != 0o700
            or not isinstance(expected_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', expected_sha256)):
        raise ValueError('protected hash-bound strict training directory required')
    body = private_read(root, 'manifest.private.json', 2 * 1024 * 1024)
    if hashlib.sha256(body).hexdigest() != expected_sha256: raise ValueError('training manifest hash mismatch')
    manifest = parse_json(body)
    if type(manifest) is not dict: raise ValueError('typed strict source manifest required')
    required = {'format', 'stage', 'scope', 'quality_gate', 'fold', 'standard_manifest_sha256', 'standard_fit',
        'predeclared_sha256', 'source_identity_before', 'source_identity_after', 'fit_or_score_calls',
        'holdout_numeric_records_read', 'sections', 'isolation_proof'}
    if (not required <= set(manifest) or type(manifest['sections']) is not dict
            or set(manifest['sections']) != {'normal', 'supplement'}
            or type(manifest['source_identity_before']) is not dict or not manifest['source_identity_before']
            or type(manifest['standard_fit']) is not dict
            or any(not isinstance(manifest[key], str) or not re.fullmatch(r'[a-f0-9]{64}', manifest[key])
                   for key in ('standard_manifest_sha256', 'predeclared_sha256'))):
        raise ValueError('complete typed source/checksum references required')
    scoped = manifest.get('scope') == 'SCOPED_TEST'
    if (manifest.get('format') != FORMAT or manifest.get('stage') != 'STRICT_SOURCE'
            or manifest.get('quality_gate') != 'NOT_EVALUATED' or scoped and not allow_scoped_test
            or manifest.get('scope') not in ('FULL_STRICT_SOURCE', 'SCOPED_TEST')
            or type(manifest.get('fit_or_score_calls')) is not int or manifest['fit_or_score_calls'] != 0
            or type(manifest.get('holdout_numeric_records_read')) is not int or manifest['holdout_numeric_records_read'] != 0):
        raise ValueError('non-selected independent strict training source required')
    declared = private_read(root, 'predeclared.private.json', 2 * 1024 * 1024)
    if hashlib.sha256(declared).hexdigest() != manifest['predeclared_sha256']:
        raise ValueError('training pre-generation source/recipe declaration changed')
    if manifest['source_identity_before'] != manifest['source_identity_after']:
        raise ValueError('source identity changed during generation')
    declaration = parse_json(declared)
    if (type(declaration) is not dict or declaration.get('source_identity') != manifest['source_identity_before']
            or declaration.get('standard_manifest_sha256') != manifest['standard_manifest_sha256']
            or declaration.get('fold') != manifest.get('fold') or type(manifest.get('fold')) is not int
            or manifest['fold'] not in (1, 2, 3)):
        raise ValueError('actual fold/source predeclared binding required')
    normal, supplement, frames, hours = [], [], set(), set()
    for role in ('normal', 'supplement'):
        section = manifest['sections'][role]
        if type(section) is not dict or type(section.get('shards')) is not list or not 1 <= len(section['shards']) <= 1000:
            raise ValueError('bounded actual training section required')
        for shard in manifest['sections'][role]['shards']:
            if type(shard) is not dict or not isinstance(shard.get('sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', shard['sha256']):
                raise ValueError('typed immutable numeric shard descriptor required')
            data = private_read(root, shard['path'], MAX_SHARD_BYTES)
            if hashlib.sha256(data).hexdigest() != shard['sha256']: raise ValueError('actual shard hash mismatch')
            rows = parse_json(data); stats = validate_rows(rows, 4)
            if (any(type(shard.get(key)) is not int for key in ('records', 'normal', 'positive'))
                    or any(shard.get(key) != value for key, value in stats.items())):
                raise ValueError('actual shard counter mismatch')
            for row in rows:
                hour = (row['account_id'], utc(row['window_start']).strftime('%Y-%m-%dT%H'))
                if row['frame_id'] in frames or hour in hours: raise ValueError('duplicate training frame/account-hour')
                if role == 'normal' and (row['label'] or row['cohort'] != 'READY'): raise ValueError('normal component provenance mismatch')
                frames.add(row['frame_id']); hours.add(hour)
            (normal if role == 'normal' else supplement).extend(rows)
    required = (2, 3) if scoped else (NORMAL_ROWS, SUPPLEMENT_ROWS)
    if (len(normal), len(supplement)) != required: raise ValueError('complete source training populations required')
    targets = training_targets([*normal, *supplement])
    standard_fit = manifest['standard_fit']
    original = standard_fit['shards']; copied = manifest['sections']['normal']['shards']
    if (len(original) != len(copied) or any({k: v for k, v in a.items() if k != 'path'} !=
            {k: v for k, v in b.items() if k != 'path'} for a, b in zip(original, copied))
            or row_stats(normal) != {key: standard_fit[key] for key in row_stats(normal)}):
        raise ValueError('normal source is not exact shared standard FIT')
    expected_date = {1: '2026-04-15', 2: '2026-04-22', 3: '2026-04-29'}[manifest['fold']]
    if any(not row['window_start'].startswith(expected_date) for row in [*normal, *supplement]):
        raise ValueError('all actual training rows must retain matching-fold FIT date')
    proof = manifest.get('isolation_proof')
    if (type(proof) is not dict or any(type(proof.get(key)) is not int or proof[key] != 0 for key in (
            'calibration_frame_overlap', 'calibration_account_hour_overlap', 'validation_frame_overlap',
            'validation_account_hour_overlap', 'unseen_validation_training_account_overlap'))
            or proof.get('matching_fold_gaps_gt14days') is not True):
        raise ValueError('matching-fold actual isolation/gap proof required')
    if not scoped:
        from collections import Counter
        if Counter(targets) != {0: 71500, 1: 8000, 2: 2000}: raise ValueError('all three exact planned context classes required')
        if Counter(row['cohort'] for row in supplement if not row['label']) != {'READY': 50, 'UNSEEN_READY': 14300, 'COLD': 7150}:
            raise ValueError('exact normal supplement cohorts required')
        for family in ('request_burst', 'endpoint_scan', 'auth_failure_burst', 'sensitive_action_burst', 'http_error_burst'):
            if Counter(row['cohort'] for row in supplement if row['family'] == family) != {'READY': 1400, 'UNSEEN_READY': 400, 'COLD': 200}:
                raise ValueError('each planned family requires exact70/20/10 cohort population')
    return normal, [*normal, *supplement], manifest


def load_hybrid_strict_fit(root, expected_sha256, *, allow_scoped_test=False):
    try:
        return _load_hybrid_strict_fit(root, expected_sha256, allow_scoped_test=allow_scoped_test)
    except (KeyError, TypeError, AttributeError, OSError):
        raise ValueError('malformed or unavailable protected strict source') from None
