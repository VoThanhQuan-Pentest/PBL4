#!/usr/bin/env python3
"""Export the hash-bound fold3 model and calibration, with zero fits and parity."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from app.hybrid_incident import HybridResearchConfig
from app.normal_support import NormalSupportScorer
from app.postlogin_contract import FEATURE_NAMES, EVALUATION_UNIT
from app.postlogin_model import PostLoginContextScorer
from app.postlogin_semantic import to_state, verifier_sha256
from app.postlogin_serving import MODEL_VERSION, THRESHOLDS, ProjectPostloginModel
from postlogin_pilot_artifacts import read_bundle
from postlogin_preparation_audit import checked
from postlogin_risk_rolling import model_features
from ueba_research_artifacts import canonical, commit, digest, private_directory, publish


def forbidden(*args, **kwargs):
    raise AssertionError('ZERO_FIT_IMPLEMENTATION_ATTEMPTED_FIT')


def snapshots_for(rows, label):
    return [{'snapshot_id': f'parity-{label}-{i:07d}', 'evaluation_unit': EVALUATION_UNIT,
             'feature_schema_version': 6, 'feature_names': list(FEATURE_NAMES),
             'features': list(model_features(row)), 'as_of': row['as_of'],
             'baseline_established': row['baseline_established'],
             'trusted_window_count': row['trusted_window_count']} for i, row in enumerate(rows)]


def verify_batch(original, calibration, restored, snapshots):
    x = np.asarray([s['features'] for s in snapshots], dtype=np.float64)
    reference = original.anomaly_scores(x);contexts = original.contexts(x)
    observed = restored.score(snapshots)['assessments']
    if not np.allclose(reference, [r['raw_score'] for r in observed], atol=1e-12, rtol=0):
        raise AssertionError('RESTORED_MODEL_SCORE_DRIFT')
    for i, (snapshot, row) in enumerate(zip(snapshots, observed)):
        cohort = 'READY' if snapshot['baseline_established'] else 'COLD';bucket = calibration[cohort]
        pct = float((np.searchsorted(bucket, reference[i], side='left')
                     + np.searchsorted(bucket, reference[i], side='right')) / (2 * len(bucket)) * 100)
        if row['normal_percentile'] != pct or row['above_threshold'] != (pct >= THRESHOLDS[cohort]):
            raise AssertionError('FROZEN_CALIBRATION_OR_THRESHOLD_DRIFT')
        if row['context'] != ('ROUTINE_CONTEXT', 'BEHAVIOR_REVIEW_CONTEXT', 'SERVICE_DEGRADATION_CONTEXT')[int(contexts[i])]:
            raise AssertionError('CONTEXT_CLASS_DRIFT')
    return [r['above_threshold'] for r in observed]


def main(args):
    root = private_directory(args.output.resolve());parent = args.parent
    fixed = checked(root, 'fixed-model-binding-v1')
    ledger = digest(parent / 'risk-fit-ledger.private.json')
    unit = 'projection-fit-fold3-candidate';directory = parent / 'factorial-v1'
    bundle = directory / (unit + '.bundle.zip')
    if digest(bundle) != fixed['bundle_sha256']:raise RuntimeError('FIXED_SOURCE_MODEL_CHANGED')
    with zipfile.ZipFile(bundle) as source:binding = json.loads(source.read('manifest.json'))['binding']
    contents = read_bundle(directory, unit, binding)
    HistGradientBoostingClassifier.fit = forbidden;NormalSupportScorer.fit = forbidden
    old = joblib.load(io.BytesIO(contents['model.joblib']))  # Only this pinned, own local artifact.
    original = old['model'];calibration = old['calibration']
    model = PostLoginContextScorer(HybridResearchConfig(100, 15, 0, 42))
    model._normal = original.normal;model._classifier = original.classifier
    model.normal_fit_count = 2000;model.labeled_fit_count = 4240
    target = root / 'project-model-v1';target.mkdir(mode=0o700, exist_ok=True);private_directory(target)
    publish(target / 'model-state.json', to_state(model), maximum=64 * 1024**2)
    publish(target / 'calibration.json', {k: calibration[k].tolist() for k in ('READY', 'COLD')}, maximum=2 * 1024**2)
    manifest = {'format': 'POSTLOGIN_PROJECT_MODEL_V1', 'model_version': MODEL_VERSION,
        'qualification_scope': 'PROJECT_LIMITED', 'data_provenance': 'DEMO_ONLY_RULE_DISTILLATION',
        'original_bundle_sha256': digest(bundle), 'original_recipe_version': original.recipe_version,
        'original_declared_schema': original.feature_schema_version,
        'feature_schema_version': 6, 'evaluation_unit': EVALUATION_UNIT, 'feature_names': list(FEATURE_NAMES),
        'state_sha256': digest(target / 'model-state.json'), 'calibration_sha256': digest(target / 'calibration.json'),
        'verifier_sha256': verifier_sha256(), 'thresholds': THRESHOLDS,
        'calibration_counts': {k: len(calibration[k]) for k in ('READY', 'COLD')}}
    publish(target / 'manifest.json', manifest, maximum=16384)
    restored = ProjectPostloginModel(target, digest(target / 'manifest.json'))
    results = {}
    for label, source, pattern, expected_inventory in [
        ('fold3', parent, 'risk-source-f3-validation-*.commit.private.json', binding['source_splits_sha256']['validation']),
        ('forward4', parent / 'forward-validation-v1', 'forward-source-f4-validation-*.commit.private.json',
         checked(parent / 'forward-validation-v1', 'source-result-v1')['commit_inventory_sha256'])]:
        markers = sorted(source.glob(pattern));hashes = [digest(p) for p in markers]
        if hashlib.sha256(canonical(hashes).encode()).hexdigest() != expected_inventory:
            raise RuntimeError('VALIDATION_SOURCE_INVENTORY_CHANGED')
        counts = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0};n = 0
        for marker in markers:
            rows = checked(source, marker.name.removesuffix('.commit.private.json'))['rows']
            predicted = verify_batch(original, calibration, restored, snapshots_for(rows, label))
            for row, positive in zip(rows, predicted):
                key = 'tp' if positive and row['label'] else 'fp' if positive else 'fn' if row['label'] else 'tn'
                counts[key] += 1
            n += len(rows)
        if n != 21000:raise RuntimeError('COMPLETE21000ROW_REGRESSION_REQUIRED')
        results[label] = {'rows': n, 'counts': counts}
    real = args.preparation / 'capture-real-v1'
    markers = sorted(real.glob('benchmark-*-precommit.commit.private.json'));n = 0
    for i in range(0, len(markers), 32):
        snapshots = [checked(real, m.name.removesuffix('.commit.private.json'))['snapshot'] for m in markers[i:i+32]]
        verify_batch(original, calibration, restored, snapshots);n += len(snapshots)
    if n != 360:raise RuntimeError('COMPLETE360REAL_CAPTURE_REGRESSION_REQUIRED')
    if results['fold3']['counts'] != {'tp': 999, 'tn': 20000, 'fp': 0, 'fn': 1}:
        raise RuntimeError('ORIGINAL_FOLD3_POINT_RESULTS_CHANGED')
    if results['forward4']['counts'] != {'tp': 1000, 'tn': 20000, 'fp': 0, 'fn': 0}:
        raise RuntimeError('ORIGINAL_FORWARD_POINT_RESULTS_CHANGED')
    if digest(parent / 'risk-fit-ledger.private.json') != ledger:raise RuntimeError('FIT_LEDGER_CHANGED')
    report = {'status': 'FIXED_MODEL_EXPORT_AND42360REGRESSIONS_PASS', 'new_fits': 0,
        'model_version': MODEL_VERSION, 'manifest_sha256': digest(target / 'manifest.json'),
        'original_bundle_sha256': fixed['bundle_sha256'], 'regressions': results,
        'real_capture_parity_rows': n, 'source_class': 'DEMO_ONLY_RULE_DISTILLATION',
        'score_absolute_tolerance': 1e-12, 'decision_or_context_differences': 0,
        'holdout_scored': False, 'strict_qualification': False, 'fit_methods_forbidden': True,
        'model_publication_bytes': sum(p.stat().st_size for p in target.iterdir() if p.is_file())}
    commit(root, report, phase='fixed-model-export-v1')
    print(canonical(report), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True);p.add_argument('--parent', type=Path, required=True)
    p.add_argument('--preparation', type=Path, required=True)
    main(p.parse_args())
