#!/usr/bin/env python3
"""Fixed default then complete 24-recipe hybrid PILOT_DEMO_ONLY diagnostic.

Reuse the exact old 25k pilot, independent cohort calibration, frozen real Java
replay and counter-verified point diagnostics. Only a separately protected,
hash-bound chronological labeled training artifact may train the supervised
component. The normal component still fits exactly the original 2k normal READY
FIT. No holdout, winner selection, serialization, registration or activation.
Planned simulation contexts are not confirmed security attacks or calibrated
real-world probabilities. Execute in the pinned image with read-only sources.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import importlib.util
import inspect
import os
from pathlib import Path
import re
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ueba-worker'))
SPEC = importlib.util.spec_from_file_location('fixed_pilot_hybrid_diagnostic',
    ROOT / 'observability/scripts/diagnose-ueba-normal-density.py')
fixed = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixed
SPEC.loader.exec_module(fixed)

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_dataset import CLASS_TARGET_NAMES, load_hybrid_fit, training_targets
from app.hybrid_incident import CONFIGURATIONS, HybridIncidentScorer, HybridResearchConfig, RECIPE_VERSION
from app.normal_support import NormalSupportScorer

DEFAULT = (200, 31, 1)
STAGE = 'PILOT_DEMO_ONLY'
DIAGNOSTIC = 'BOUNDED_NORMAL_PLUS_INCIDENT_HYBRID'
EXPECTED_MODEL_SHA = '7a3b6e51582a72b681660bc08dc2d7b6be4bf66f1388c6fca79bdaba158e34c2'
TRAINING_SOURCES = (
    'observability/scripts/prepare-ueba-hybrid-pilot.py', 'observability/scripts/prepare-ueba-schema4.py',
    'ueba-worker/app/hybrid_dataset.py', 'ueba-worker/app/schema4_episodes.py', 'ueba-worker/app/catalog.py',
    'ueba-worker/app/contract.py', 'ueba-worker/app/policy.py', 'ueba-worker/app/strict_metrics.py',
)
EXTRA_SOURCES = ('observability/scripts/diagnose-ueba-hybrid.py', 'ueba-worker/app/hybrid_incident.py',
                 'ueba-worker/app/hybrid_dataset.py', 'observability/scripts/prepare-ueba-hybrid-pilot.py')


def protected_directory(output):
    if output is None:
        output = Path(tempfile.mkdtemp(prefix='hybrid-pilot-diagnostic-', dir=ROOT / 'observability/runtime'))
    else:
        output = Path(output).absolute()
        if output.exists() or output.is_symlink() or not output.parent.is_dir():
            raise ValueError('New private diagnostic directory required')
        for parent in (output.parent, *output.parent.parents):
            if parent.is_symlink():
                raise ValueError('Symlinked diagnostic output rejected')
        if output.parent.stat().st_uid != os.geteuid() or output.parent.stat().st_mode & 0o077:
            raise ValueError('Owned protected 0700 output parent required')
        output.mkdir(mode=0o700)
    output.chmod(0o700)
    return output


def episode(row):
    return row['account_id'], fixed.utc(row['window_start']).strftime('%Y-%m-%dT%H')


def separation_checks(training, old):
    """Allow ONLY explicitly shared original FIT; never score-only leakage."""
    if len(training) != 4000 or len(old['fold1-fit']) != 2000 or training[:2000] != old['fold1-fit']:
        raise ValueError('Exactly original 2000 normal READY FIT rows must be shared unchanged')
    normal = old['fold1-fit']
    if any(row['label'] != 0 or row['family'] != 'normal' or row['cohort'] != 'READY'
           or row['baseline_established'] is not True for row in normal):
        raise ValueError('Normal component must retain exact normal READY only FIT')
    train_frames = {row['frame_id'] for row in training}
    train_episodes = {episode(row) for row in training}
    if len(train_frames) != len(training) or len(train_episodes) != len(training):
        raise ValueError('Training frames and account-hours must be unique')
    score_only = [row for name in fixed.SPLITS[1:] for row in old[name]]
    if (train_frames & {row['frame_id'] for row in score_only}
            or train_episodes & {episode(row) for row in score_only}):
        raise ValueError('Training/calibration/validation frame or account-hour leakage')
    old_frames = {row['frame_id'] for group in old.values() for row in group}
    old_hours = {episode(row) for group in old.values() for row in group}
    if ({row['frame_id'] for row in training[2000:]} & old_frames
            or {episode(row) for row in training[2000:]} & old_hours):
        raise ValueError('Only exact old normal FIT sharing is permitted')
    unseen = {row['account_id'] for row in old['fold1-validation'] if row['cohort'] == 'UNSEEN_READY'}
    if {row['account_id'] for row in training} & unseen:
        raise ValueError('UNSEEN validation account occurred in either training component')
    latest = max(fixed.utc(row['window_start']) for row in training)
    earliest = min(fixed.utc(row['window_start']) for name in fixed.SPLITS[1:3] for row in old[name])
    if earliest - latest <= timedelta(days=14):
        raise ValueError('Every training row must precede calibration by more than14 days')
    targets = training_targets(training)
    if Counter(targets) != Counter({0: 3000, 1: 800, 2: 200}):
        raise ValueError('Fixed supervised context class populations changed')
    return {'shared_original_normal_ready_rows': 2000, 'independent_new_training_rows': 2000,
            'supervised_training_rows': 4000, 'class_counts': {'0': 3000, '1': 800, '2': 200},
            'latest_training_utc': latest.isoformat(), 'earliest_calibration_utc': earliest.isoformat(),
            'training_to_calibration_gap_seconds': (earliest - latest).total_seconds(),
            'score_only_frame_and_account_hour_disjoint': True, 'unseen_validation_accounts_excluded': True,
            'unseen_validation_accounts_sha256': fixed.value_sha(sorted(unseen)),
            'shared_normal_rows_sha256': fixed.value_sha(normal),
            'features_only_in_X': list(fixed.FEATURE_NAMES_V4), 'labels_identity_and_context_excluded_from_X': True}


def integrity(dataset, training_root, training_sha, manifest):
    original = fixed.integrity(dataset)
    if fixed.checksum(ROOT / 'ueba-worker/app/hybrid_incident.py') != EXPECTED_MODEL_SHA:
        raise ValueError('Parent-frozen hybrid model source required')
    if fixed.checksum(training_root / 'manifest.private.json') != training_sha:
        raise ValueError('Frozen hybrid training manifest changed')
    bound_sources = manifest['source_identity_before']['sources']
    if set(bound_sources) != set(TRAINING_SOURCES) or any(
            fixed.checksum(ROOT / name) != sha for name, sha in bound_sources.items()):
        raise ValueError('Training generation source identity differs from actual current source')
    shards = {entry['path']: entry['sha256'] for entry in manifest['split']['shards']}
    if any(fixed.checksum(training_root / name) != sha for name, sha in shards.items()):
        raise ValueError('Frozen supervised numeric training shard changed')
    receipts = manifest['batch_receipt_sha256']
    if any(not re.fullmatch(r'batch-[0-9]{4}\.private\.json', name)
           or fixed.checksum(training_root / name) != sha for name, sha in receipts.items()):
        raise ValueError('Actual Java training extraction receipt changed')
    declaration = training_root / 'predeclared.private.json'
    if fixed.checksum(declaration) != manifest['predeclared_identity_sha256']:
        raise ValueError('Pre-generation training declaration changed')
    estimator_source = Path(inspect.getsourcefile(HistGradientBoostingClassifier))
    return {'original_fixed_pilot': original,
            'hybrid_repository_sources': {name: fixed.checksum(ROOT / name) for name in EXTRA_SOURCES},
            'hybrid_training_generation_sources': bound_sources,
            'sklearn_hist_gradient_boosting_source_sha256': fixed.checksum(estimator_source),
            'training': {'manifest_sha256': training_sha, 'predeclared_sha256': fixed.checksum(declaration),
                         'split_sha256': manifest['split']['sha256'], 'shards': shards,
                         'actual_java_extraction_receipts': receipts},
            'execution_image_id': fixed.IMAGE_ID}


class FitCounter:
    """Observe real Python fit frames; never replace estimators or score math."""
    def __init__(self):
        self.counts = {'composite_fit_trials': 0, 'normal_component_fit_calls': 0, 'supervised_component_fit_calls': 0}
        self.codes = {HybridIncidentScorer.fit.__code__: 'composite_fit_trials',
                      NormalSupportScorer.fit.__code__: 'normal_component_fit_calls',
                      inspect.unwrap(HistGradientBoostingClassifier.fit).__code__: 'supervised_component_fit_calls'}

    def profile(self, frame, event, _arg):
        if event == 'call' and frame.f_code in self.codes:
            self.counts[self.codes[frame.f_code]] += 1

    def __enter__(self):
        self.previous = sys.getprofile()
        if self.previous is not None:
            raise ValueError('Conflicting profiler would make genuine fit counts ambiguous')
        sys.setprofile(self.profile)
        return self

    def __exit__(self, *_args):
        sys.setprofile(self.previous)


def context_metrics(records):
    def summary(group):
        matrix = np.zeros((3, 3), dtype=np.int64)
        for row in group:
            truth, predicted = row['context_target'], row['predicted_context']
            if type(truth) is not int or truth not in (0, 1, 2) or type(predicted) is not int or predicted not in (0, 1, 2):
                raise ValueError('Explicit planned context classes required')
            matrix[truth, predicted] += 1
        counts = {}
        for label in (0, 1, 2):
            tp = int(matrix[label, label]); fn = int(matrix[label].sum()) - tp
            fp = int(matrix[:, label].sum()) - tp; tn = int(matrix.sum()) - tp - fn - fp
            counts[str(label)] = fixed.Confusion(tp, fn, fp, tn).metrics()
        return {'rows': int(matrix.sum()), 'true_by_predicted_context': matrix.tolist(),
                'one_vs_rest': counts, 'descriptive_accuracy': float(np.trace(matrix) / matrix.sum()) if matrix.sum() else None}
    groups = {'families': defaultdict(list), 'cohorts': defaultdict(list), 'family_cohort': defaultdict(list)}
    for row in records:
        groups['families'][row['family']].append(row)
        groups['cohorts'][row['cohort']].append(row)
        groups['family_cohort'][row['family'] + ':' + row['cohort']].append(row)
    return {'complete_validation': summary(records),
            **{name: {key: summary(group) for key, group in sorted(values.items())} for name, values in groups.items()},
            'class_names': CLASS_TARGET_NAMES, 'probabilities_calibrated': False,
            'target_semantics': 'PREDECLARED_SIMULATION_CONTEXT_NOT_CONFIRMED_SECURITY_ATTACK',
            'applicability': 'DESCRIPTIVE_TRAINING_PRIOR_ONLY_NOT_REAL_WORLD_RISK', 'quality_gate': 'NOT_APPLICABLE'}


def verify_default(path, before, policy):
    if path is None or path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Complete fixed hybrid default required before grid')
    if path.stat().st_mode & 0o077 or path.parent.stat().st_mode & 0o077:
        raise ValueError('Protected default receipt required')
    result = fixed.parse_json(path.read_bytes())
    if (result.get('status') != 'COMPLETED' or result.get('mode') != 'FIXED_DEFAULT'
            or result.get('stage') != STAGE or result.get('diagnostic') != DIAGNOSTIC
            or result.get('quality_gate') != 'NOT_APPLICABLE' or result.get('integrity_before') != before
            or result.get('integrity_after') != before or result.get('policy_sha256') != policy.sha256
            or result.get('actual_composite_fit_trials') != 1 or result.get('actual_component_fit_calls') != 2
            or result.get('actual_validation_rows_replayed') != 21000 or result.get('holdout_numeric_records_read') != 0
            or result.get('strict_fit_calls') != 0 or len(result.get('configurations', [])) != 1
            or result['configurations'][0].get('configuration') != list(DEFAULT)):
        raise ValueError('Same-source complete fixed hybrid default receipt required')
    receipt = path.parent / 'predeclared.private.json'
    if fixed.checksum(receipt) != result['predeclared_receipt_sha256']:
        raise ValueError('Default declaration changed')
    for name, expected in result['private_artifacts'].items():
        if Path(name).name != name or fixed.checksum(path.parent / name) != expected:
            raise ValueError('Completed default evidence changed')
    return {'result_sha256': fixed.checksum(path), 'predeclared_receipt_sha256': fixed.checksum(receipt)}


def run(output, training_root, training_sha, *, grid=False, default_result=None):
    if os.environ.get('UEBA_DIAGNOSTIC_IMAGE_ID') != fixed.IMAGE_ID or not Path('/.dockerenv').exists():
        raise ValueError('Pinned Docker-only execution required; do not install host dependencies')
    if not re.fullmatch(r'[0-9a-f]{64}', str(training_sha)):
        raise ValueError('Explicit frozen training manifest SHA-256 required')
    dataset, rows = fixed.load_pilot()
    training_root = Path(training_root).absolute()
    training, manifest = load_hybrid_fit(training_root, training_sha)
    separation = separation_checks(training, rows)
    policy = fixed.ScorePolicy.strict(schema=4)
    before = integrity(dataset, training_root, training_sha, manifest)
    if RECIPE_VERSION != 1 or len(CONFIGURATIONS) != 24 or len(set(CONFIGURATIONS)) != 24 or DEFAULT not in CONFIGURATIONS:
        raise ValueError('Exact predeclared distinct hybrid recipe grid required')
    previous = verify_default(default_result, before, policy) if grid else None
    if default_result is not None and not grid:
        raise ValueError('Default receipt is only valid for complete grid invocation')
    output = protected_directory(output)
    configurations = tuple(CONFIGURATIONS) if grid else (DEFAULT,)
    declaration = {'stage': STAGE, 'diagnostic': DIAGNOSTIC, 'mode': 'COMPLETE_PREDECLARED_GRID' if grid else 'FIXED_DEFAULT',
        'fold': 1, 'seed': 42, 'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY',
        'configurations': [list(value) for value in configurations], 'all_predeclared_configurations': [list(value) for value in CONFIGURATIONS],
        'parameters': [HybridIncidentScorer(HybridResearchConfig(*value, random_state=42)).parameters() for value in configurations],
        'integrity_before': before, 'separation_before': separation, 'policy': policy.wire(), 'fixed_default_before_grid': previous,
        'composite_fit_trials_before_declaration': 0, 'component_fit_calls_before_declaration': 0, 'score_calls_before_declaration': 0,
        'normal_component_fit_population': 'EXACT_ORIGINAL_NORMAL_READY_FOLD1_FIT_2000',
        'supervised_component_fit_population': 'ONLY_SEPARATE_CHRONOLOGICAL4000_TRAINING_SHARED_NORMAL_FIT_EXPLICITLY_ALLOWED',
        'confirmed_attack_target_available': False, 'supervised_class_names': CLASS_TARGET_NAMES,
        'threshold_tuning': False, 'validation_labels_features_or_cohorts_modified': False, 'selection_or_promotion': False}
    receipt = output / 'predeclared.private.json'
    fixed.write_private(receipt, declaration)
    fixed.write_private(output / 'integrity-before.private.json', before)
    normal_X = [row['features'] for row in rows['fold1-fit']]
    labeled_X = [row['features'] for row in training]
    targets = training_targets(training)
    completed, artifacts, replayed, fit_trials, component_fits = [], {}, 0, 0, 0
    started = time.monotonic()
    for ordinal, configuration in enumerate(configurations):
        candidate_start = time.monotonic()
        scorer = HybridIncidentScorer(HybridResearchConfig(*configuration, random_state=42))
        with FitCounter() as counter:
            scorer.fit(normal_X, labeled_X, targets)
        if counter.counts != {'composite_fit_trials': 1, 'normal_component_fit_calls': 1, 'supervised_component_fit_calls': 1}:
            raise ValueError('One composite trial must contain two observed genuine component fits')
        if scorer.normal_fit_count != 2000 or scorer.labeled_fit_count != 4000:
            raise ValueError('Both genuine component fits must conserve exact training populations')
        fit_trials += 1; component_fits += 2
        buckets = {cohort: np.sort(scorer.anomaly_scores([row['features'] for row in rows['fold1-calibration-' + cohort.lower()]]))
                   for cohort in ('READY', 'COLD')}
        calibration = output / f'candidate-{ordinal:02d}-calibration.private.json'
        fixed.write_private(calibration, {key: value.tolist() for key, value in buckets.items()})
        artifacts[calibration.name] = fixed.checksum(calibration)
        score_path = output / f'candidate-{ordinal:02d}-scores-decisions.private.jsonl'
        descriptor = os.open(score_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        decisions, contexts, raw_scores, percentages = [], [], [], []
        batch_calls = 0
        with os.fdopen(descriptor, 'w', encoding='utf-8') as evidence, fixed.JavaRiskReplay(
                fixed.WORKSPACE, policy, expected_classes=before['original_fixed_pilot']['java']['replay_classes']) as java:
            validation = rows['fold1-validation']
            for offset in range(0, len(validation), 1000):
                batch = validation[offset:offset + 1000]
                parts = scorer.score_components([row['features'] for row in batch])
                raw = parts['raw_anomaly_score']
                probabilities = parts['uncalibrated_context_probabilities']
                if (probabilities.shape != (len(batch), 3) or not np.isfinite(probabilities).all()
                        or (probabilities < 0).any() or (probabilities > 1).any()
                        or not np.allclose(probabilities.sum(axis=1), 1, rtol=0, atol=1e-12)):
                    raise ValueError('Complete finite three-class descriptive probabilities required')
                scores = fixed.calibrate_scores(raw, batch, buckets, policy)
                actual = java.score(batch, scores)
                decisions.extend(actual); raw_scores.extend(float(value) for value in raw)
                percentages.extend(score['normal_percentile'] for score in scores)
                context_truth = training_targets(batch)
                for index, (original, score, decision) in enumerate(zip(batch, scores, actual)):
                    prediction = int(np.argmax(probabilities[index]))
                    contexts.append({'family': original['family'], 'cohort': original['cohort'],
                                     'context_target': context_truth[index], 'predicted_context': prediction})
                    evidence.write(fixed.canonical({'frame_id': original['frame_id'], **score,
                        'predictions': decision['predictions'], 'incident_margin': float(parts['incident_margin'][index]),
                        'normal_support_distance': float(parts['normal_support_distance'][index]),
                        'normal_novelty_log_score': float(parts['normal_novelty_log_score'][index]),
                        'uncalibrated_context_probabilities': probabilities[index].tolist(),
                        'planned_context_target': context_truth[index], 'predicted_context': prediction}) + '\n')
                batch_calls += 1; replayed += len(actual)
            evidence.flush(); os.fsync(evidence.fileno())
        if len(decisions) != 21000 or len(contexts) != 21000 or sum(row['label'] for row in decisions) != 1000:
            raise ValueError('Actual frozen Java must conserve every unchanged validation row')
        artifacts[score_path.name] = fixed.checksum(score_path)
        metrics = fixed.decision_metrics(decisions)
        record = {'ordinal': ordinal, 'configuration': list(configuration), 'parameters': scorer.parameters(),
            'actual_composite_fit_trials': 1, 'actual_component_fit_calls': 2, 'actual_fit_frames_observed': counter.counts,
            'actual_normal_ready_fit_rows': scorer.normal_fit_count, 'actual_labeled_fit_rows': scorer.labeled_fit_count,
            'training_class_counts': dict(Counter(targets)), 'calibration_rows': {cohort: len(bucket) for cohort, bucket in buckets.items()},
            'calibration_scope': 'PILOT_INDEPENDENT_COHORT_NORMAL_ONLY_MIDRANK',
            'calibration_sha256': {cohort: fixed.array_sha(bucket) for cohort, bucket in buckets.items()},
            'actual_java_replay_batches': batch_calls, 'actual_validation_rows_replayed': len(decisions),
            'raw_score_sha256': fixed.array_sha(raw_scores), 'percentile_sha256': fixed.array_sha(percentages),
            'decisions': metrics, 'point_diagnostic': fixed.point_diagnostic(metrics, policy),
            'uncalibrated_context_class_metrics': context_metrics(contexts),
            'finite_calibration_tail': {'normal_rows_per_bucket': 1000,
                'detection_percentile_micro': policy.document['detection_percentile_micro'],
                'detection_requires_score_strictly_above_observed_calibration_max': True,
                'not_equivalent_to_million_row_strict_calibration': True},
            'elapsed_seconds': time.monotonic() - candidate_start, 'stage': STAGE,
            'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY'}
        candidate_path = output / f'candidate-{ordinal:02d}.private.json'
        fixed.write_private(candidate_path, record); artifacts[candidate_path.name] = fixed.checksum(candidate_path)
        completed.append(record)
        print(fixed.canonical({'stage': STAGE, 'diagnostic': DIAGNOSTIC, 'completed_configurations': len(completed),
            'planned_configurations': len(configurations), 'configuration': list(configuration),
            'actual_composite_fit_trials': fit_trials, 'actual_component_fit_calls': component_fits,
            'actual_validation_rows_replayed': replayed, 'aggregate_decisions': {
                scope: metrics[scope]['complete_validation'] for scope in fixed.SCOPES}, 'quality_gate': 'NOT_APPLICABLE'}), flush=True)
    after = integrity(dataset, training_root, training_sha, manifest)
    reloaded, _ = load_hybrid_fit(training_root, training_sha)
    fixed.write_private(output / 'integrity-after.private.json', after)
    if after != before or reloaded != training or separation_checks(reloaded, rows) != separation:
        raise ValueError('Frozen source/training/pilot/Java identity changed; retain unqualified evidence')
    if any(fixed.checksum(output / name) != expected for name, expected in artifacts.items()):
        raise ValueError('Candidate evidence changed before terminal receipt')
    result = {'status': 'COMPLETED', 'stage': STAGE, 'diagnostic': DIAGNOSTIC, 'mode': declaration['mode'],
        'fold': 1, 'seed': 42, 'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY',
        'policy': policy.wire(), 'policy_sha256': policy.sha256, 'predeclared_receipt_sha256': fixed.checksum(receipt),
        'fixed_default_before_grid': previous, 'integrity_before': before, 'integrity_after': after,
        'integrity_unchanged': True, 'training_separation': separation, 'configurations': completed,
        'private_artifacts': artifacts, 'actual_composite_fit_trials': fit_trials, 'actual_component_fit_calls': component_fits,
        'actual_validation_rows_replayed': replayed, 'strict_fit_calls': 0, 'holdout_numeric_records_read': 0,
        'labels_features_counters_cohorts_modified': False, 'serving_contract_changed': False,
        'primary_or_aws_changed': False, 'registered_serialized_selected_or_promoted': False,
        'confirmed_attack_target_available': False, 'limitations': [
            'SIMULATED_PLANNED_CONTEXTS_ARE_NOT_CONFIRMED_SECURITY_INCIDENTS',
            'CONTEXT_CLASS_PROBABILITIES_UNCALIBRATED_AND_TRAINING_PRIOR_DEPENDENT',
            'NO_STRICT_QUALIFICATION_OR_CONFIDENCE_GATE', 'READY_NORMAL_FIT_DOES_NOT_QUALIFY_COLD_SERVING',
            'FINITE_1000_NORMAL_CALIBRATION_TAIL_IS_NOT_STRICT_QUANTILE',
            'FIXED_MAX_FUSION_AXES_HAVE_DIFFERENT_NATURAL_SCALES',
            'SMALL_CHRONOLOGICAL_TRAINING_PILOT_NOT_REPRESENTATIVE_PREVALENCE_OR_DEPLOYMENT_EVIDENCE',
            'ALL_PREDECLARED_RECIPES_REPORTED_WITHOUT_WINNER_SELECTION'],
        'elapsed_seconds': time.monotonic() - started, 'completed_at_utc': datetime.now(timezone.utc).isoformat()}
    fixed.write_private(output / 'result.private.json', result)
    return output, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--training-root', type=Path, required=True)
    parser.add_argument('--expected-training-sha256', required=True)
    parser.add_argument('--grid', action='store_true')
    parser.add_argument('--default-result', type=Path)
    args = parser.parse_args()
    output, result = run(args.output, args.training_root, args.expected_training_sha256,
                         grid=args.grid, default_result=args.default_result)
    print(fixed.canonical({'status': result['status'], 'stage': STAGE, 'output': str(output),
        'result_sha256': fixed.checksum(output / 'result.private.json'),
        'actual_composite_fit_trials': result['actual_composite_fit_trials'],
        'actual_component_fit_calls': result['actual_component_fit_calls'], 'quality_gate': 'NOT_APPLICABLE'}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as failure:
        raise SystemExit('Hybrid pilot diagnostic refused/failed: ' + type(failure).__name__ + '; private evidence retained') from None
