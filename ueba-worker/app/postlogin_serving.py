"""Read-only, explicitly limited scoring of the fixed post-login research model."""
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

import numpy as np

from .postlogin_contract import FEATURE_NAMES, EVALUATION_UNIT, LABELS, validate_snapshot
from .postlogin_semantic import from_state, verifier_sha256

MODEL_VERSION = 'postlogin-legacy-f3-project-v1'
THRESHOLDS = {'READY': 99.99, 'COLD': 99.9995}
MANIFEST_FIELDS = {'format', 'model_version', 'qualification_scope', 'data_provenance',
    'original_bundle_sha256', 'original_recipe_version', 'original_declared_schema',
    'feature_schema_version', 'evaluation_unit', 'feature_names', 'state_sha256',
    'calibration_sha256', 'verifier_sha256', 'thresholds', 'calibration_counts'}


def load_bytes(root, filename, maximum):
    path = root / filename
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o027
                or not 0 < info.st_size <= maximum):
            raise RuntimeError('unsafe or oversized model publication')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            content = stream.read(maximum + 1)
        if len(content) != info.st_size:raise RuntimeError('model publication changed during read')
        return content
    finally:os.close(fd)


class ProjectPostloginModel:
    def __init__(self, directory, manifest_sha256):
        self.directory = Path(directory).absolute()
        if (any(p.is_symlink() for p in [self.directory, *self.directory.parents])
                or not self.directory.is_dir() or self.directory.stat().st_mode & 0o027
                or not re.fullmatch('[a-f0-9]{64}', manifest_sha256 or '')):
            raise RuntimeError('bounded operator model directory and pinned manifest required')
        self.manifest_sha256 = manifest_sha256
        raw = load_bytes(self.directory, 'manifest.json', 16384)
        if hashlib.sha256(raw).hexdigest() != manifest_sha256:raise RuntimeError('model manifest identity differs')
        value = json.loads(raw)
        if (type(value) is not dict or set(value) != MANIFEST_FIELDS
                or value['format'] != 'POSTLOGIN_PROJECT_MODEL_V1' or value['model_version'] != MODEL_VERSION
                or value['qualification_scope'] != 'PROJECT_LIMITED'
                or value['data_provenance'] != 'DEMO_ONLY_RULE_DISTILLATION'
                or type(value['original_recipe_version']) is not int or value['original_recipe_version'] != 8
                or type(value['original_declared_schema']) is not int or value['original_declared_schema'] != 8
                or type(value['feature_schema_version']) is not int or value['feature_schema_version'] != 6
                or value['evaluation_unit'] != EVALUATION_UNIT or value['feature_names'] != list(FEATURE_NAMES)
                or value['thresholds'] != THRESHOLDS or value['calibration_counts'] != {'READY': 5000, 'COLD': 5000}
                or value['verifier_sha256'] != verifier_sha256()):
            raise RuntimeError('fixed project model contract differs')
        for name in ('original_bundle_sha256', 'state_sha256', 'calibration_sha256'):
            if not isinstance(value[name], str) or not re.fullmatch('[a-f0-9]{64}', value[name]):
                raise RuntimeError('model component checksum required')
        self.manifest = value
        state = load_bytes(self.directory, 'model-state.json', 64 * 1024**2)
        calibration = load_bytes(self.directory, 'calibration.json', 2 * 1024**2)
        if (hashlib.sha256(state).hexdigest() != value['state_sha256']
                or hashlib.sha256(calibration).hexdigest() != value['calibration_sha256']):
            raise RuntimeError('model component identity differs')
        self.model = from_state(json.loads(state))
        buckets = json.loads(calibration)
        if type(buckets) is not dict or set(buckets) != {'READY', 'COLD'}:
            raise RuntimeError('matching fixed calibration required')
        self.calibration = {}
        for name, rows in buckets.items():
            if (type(rows) is not list or len(rows) != 5000
                    or any(type(v) not in (int, float) or not math.isfinite(v) for v in rows)):
                raise RuntimeError('bounded finite calibration required')
            array = np.asarray(rows, dtype=np.float64)
            if np.any(array[1:] < array[:-1]):raise RuntimeError('ordered calibration required')
            array.flags.writeable = False;self.calibration[name] = array

    def verify_identity(self):
        for filename, expected, maximum in [
            ('manifest.json', self.manifest_sha256, 16384),
            ('model-state.json', self.manifest['state_sha256'], 64 * 1024**2),
            ('calibration.json', self.manifest['calibration_sha256'], 2 * 1024**2)]:
            if hashlib.sha256(load_bytes(self.directory, filename, maximum)).hexdigest() != expected:
                raise RuntimeError('installed project model changed')

    def score(self, snapshots):
        if type(snapshots) is not list or not 1 <= len(snapshots) <= 32:
            raise ValueError('one to32 bounded snapshots required')
        values = [validate_snapshot(v) for v in snapshots]
        if len({v['snapshot_id'] for v in snapshots}) != len(snapshots):
            raise ValueError('unique snapshot identities required')
        upper = datetime.now(timezone.utc) + timedelta(seconds=1)
        if any(datetime.fromisoformat(v['as_of'].replace('Z', '+00:00')) > upper for v in snapshots):
            raise ValueError('future observations refused')
        self.verify_identity()
        components = self.model.score_components(np.asarray(values, dtype=np.float64))
        raw = components['raw_anomaly_score']
        contexts = np.argmax(components['uncalibrated_context_probabilities'], axis=1)
        assessments = []
        for i, snapshot in enumerate(snapshots):
            cohort = 'READY' if snapshot['baseline_established'] else 'COLD'
            bucket = self.calibration[cohort]
            percentile = float((np.searchsorted(bucket, raw[i], side='left')
                                + np.searchsorted(bucket, raw[i], side='right')) / (2 * len(bucket)) * 100)
            assessments.append({'snapshot_id': snapshot['snapshot_id'], 'as_of': snapshot['as_of'],
                'raw_score': float(raw[i]), 'normal_percentile': percentile,
                'context': LABELS[int(contexts[i])], 'cohort': cohort,
                'threshold': THRESHOLDS[cohort], 'above_threshold': percentile >= THRESHOLDS[cohort],
                'trusted_window_count': snapshot['trusted_window_count']})
        return {'model_version': MODEL_VERSION, 'model_sha256': self.manifest['original_bundle_sha256'],
            'runtime_state_sha256': self.manifest['state_sha256'],
            'calibration_sha256': self.manifest['calibration_sha256'], 'manifest_sha256': self.manifest_sha256,
            'qualification_scope': 'PROJECT_LIMITED', 'data_provenance': self.manifest['data_provenance'],
            'feature_schema_version': 6, 'evaluation_unit': EVALUATION_UNIT, 'assessments': assessments}


@lru_cache(maxsize=2)
def _loaded(directory, expected):
    return ProjectPostloginModel(directory, expected)


def configured_model():
    directory = os.environ.get('UEBA_POSTLOGIN_MODEL_DIR', '')
    expected = os.environ.get('UEBA_POSTLOGIN_MANIFEST_SHA256', '')
    if not directory:raise RuntimeError('project postlogin model disabled')
    return _loaded(directory, expected)


def health():
    if not os.environ.get('UEBA_POSTLOGIN_MODEL_DIR'):
        return {'available': False, 'state': 'DISABLED', 'supported_snapshot_schema': 6}
    try:
        model = configured_model();model.verify_identity()
        return {'available': True, 'state': 'READY', 'model_version': MODEL_VERSION,
                'manifest_sha256': model.manifest_sha256, 'qualification_scope': 'PROJECT_LIMITED',
                'supported_snapshot_schema': 6}
    except (OSError, ValueError, RuntimeError):
        return {'available': False, 'state': 'UNAVAILABLE', 'supported_snapshot_schema': 6}
