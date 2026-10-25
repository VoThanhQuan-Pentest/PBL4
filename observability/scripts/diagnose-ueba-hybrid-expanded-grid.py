#!/usr/bin/env python3
"""Complete predeclared hybrid grid with replacement 60k normal calibration.

Research only: every fresh recipe must reproduce the matching ORIGINAL grid
validation raw-score hash before any new percentile/Java decisions. Exactly the
same training, recipe grid, frozen Java and policy remain in use. This refits
two genuine components per trial, never zero-fit strict recalibration. Expanded
normal buckets REPLACE old 1k buckets, never merge them. No holdout, selection,
registration, serialization, serving admission, activation or AWS changes.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('expanded_hybrid_grid_base',
    ROOT / 'observability/scripts/diagnose-ueba-hybrid-expanded-calibration.py')
base = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = base
SPEC.loader.exec_module(base)
hybrid, fixed, np = base.hybrid, base.fixed, base.np

STAGE = 'PILOT_EXPANDED_NORMAL_CALIBRATION_PREDECLARED_GRID_ONLY'
EXPANDED_ROOT = ROOT / 'observability/runtime/expanded-calibration-20261003-F4wITdBt/data'
EXPANDED_SHA = '05253075440b741a010ceae9b497d62acfa2c007952f11a13b91b5ae7443432d'
EXPANDED_DEFAULT = EXPANDED_ROOT.parent / 'default/result.private.json'
EXPANDED_DEFAULT_SHA = 'c6378372e624343e76dd8f569aa734f33591535ac6c9a1e7326895580643a6bf'
ORIGINAL_GRID = ROOT / 'observability/runtime/hybrid-diagnostic-20261003-GEXijOUR/grid/result.private.json'
ORIGINAL_GRID_SHA = '25966228bab143d98fc3cfc92063a7ad4f221e4e5f8d5f6fbe395603d301af9e'
SOURCES = ('observability/scripts/diagnose-ueba-hybrid-expanded-grid.py',)


def protected_receipt(path, expected_sha):
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024
            or path.stat().st_mode & 0o077 or path.parent.stat().st_mode & 0o077
            or path.stat().st_uid != os.geteuid() or fixed.checksum(path) != expected_sha):
        raise ValueError('Exact complete protected frozen reference receipt required')
    result = fixed.parse_json(path.read_bytes())
    for name, expected in result['private_artifacts'].items():
        if Path(name).name != name or fixed.checksum(path.parent / name) != expected:
            raise ValueError('Bound frozen reference artifact changed')
    return result


def reference_receipts(binding, policy):
    original = protected_receipt(ORIGINAL_GRID, ORIGINAL_GRID_SHA)
    expanded = protected_receipt(EXPANDED_DEFAULT, EXPANDED_DEFAULT_SHA)
    if (original.get('status') != 'COMPLETED' or original.get('mode') != 'COMPLETE_PREDECLARED_GRID'
            or original.get('integrity_before') != binding['original_hybrid']
            or original.get('integrity_after') != binding['original_hybrid']
            or original.get('policy_sha256') != policy.sha256
            or original.get('actual_composite_fit_trials') != 24 or original.get('actual_component_fit_calls') != 48
            or original.get('actual_validation_rows_replayed') != 504000
            or original.get('holdout_numeric_records_read') != 0 or original.get('strict_fit_calls') != 0
            or [tuple(row['configuration']) for row in original['configurations']] != list(hybrid.CONFIGURATIONS)):
        raise ValueError('Same-source complete original 24-grid required')
    if (expanded.get('status') != 'COMPLETED' or expanded.get('stage') != base.STAGE
            or expanded.get('integrity_before') != binding or expanded.get('integrity_after') != binding
            or expanded.get('policy_sha256') != policy.sha256 or expanded.get('quality_gate') != 'NOT_APPLICABLE'
            or expanded.get('actual_composite_fit_trials') != 1 or expanded.get('actual_component_fit_calls') != 2
            or expanded.get('actual_validation_rows_replayed') != 21000
            or expanded.get('actual_normal_calibration_rows') != {'READY': 60000, 'COLD': 60000}
            or expanded.get('validation_raw_scores_exactly_reproduced') is not True
            or expanded.get('holdout_numeric_records_read') != 0 or expanded.get('strict_fit_calls') != 0):
        raise ValueError('Same-source complete expanded default required before grid')
    if (fixed.checksum(ORIGINAL_GRID.parent / 'predeclared.private.json') != original['predeclared_receipt_sha256']
            or fixed.checksum(EXPANDED_DEFAULT.parent / 'predeclared.private.json') != expanded['predeclared_sha256']):
        raise ValueError('Frozen predeclared reference receipt changed')
    references = {tuple(row['configuration']): row for row in original['configurations']}
    if len(references) != 24 or len(set(hybrid.CONFIGURATIONS)) != 24:
        raise ValueError('All distinct original recipe references required')
    return references, expanded


def integrity(binding):
    return {'base_integrity': binding, 'grid_sources': {name: fixed.checksum(ROOT / name) for name in SOURCES},
            'original_grid_sha256': fixed.checksum(ORIGINAL_GRID),
            'expanded_default_sha256': fixed.checksum(EXPANDED_DEFAULT)}


def validation_raw_scores(scorer, rows):
    # Keep original validation batch boundaries, not just the model recipe.
    values = np.concatenate([scorer.anomaly_scores([row['features'] for row in rows[offset:offset + 1000]])
                             for offset in range(0, len(rows), 1000)])
    if values.shape != (21000,) or not np.isfinite(values).all():
        raise ValueError('Complete finite unchanged validation raw vector required')
    return values


def assert_raw_reproduction(values, reference):
    if len(values) != 21000 or fixed.array_sha(values) != reference['raw_score_sha256']:
        raise ValueError('Matching ORIGINAL recipe validation raw-score hash did not reproduce')


def run(output):
    if os.environ.get('UEBA_DIAGNOSTIC_IMAGE_ID') != fixed.IMAGE_ID or not Path('/.dockerenv').exists():
        raise ValueError('Pinned Docker-only research execution required')
    dataset, old = fixed.load_pilot()
    training, training_manifest = base.load_hybrid_fit(base.TRAINING, base.TRAINING_SHA)
    policy = fixed.ScorePolicy.strict(schema=4)
    binding, buckets = base.source_binding(dataset, training_manifest, EXPANDED_ROOT, EXPANDED_SHA)
    references, expanded_default = reference_receipts(binding, policy)
    proof = base.separation(training, old, buckets)
    before = integrity(binding)
    output = hybrid.protected_directory(output)
    configurations = tuple(hybrid.CONFIGURATIONS)
    declaration = {'stage': STAGE, 'mode': 'COMPLETE_PREDECLARED_GRID', 'fold': 1, 'seed': 42,
        'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY', 'integrity_before': before,
        'configurations': [list(value) for value in configurations],
        'parameters': [base.HybridIncidentScorer(base.HybridResearchConfig(*value, random_state=42)).parameters()
                       for value in configurations], 'policy': policy.wire(), 'separation': proof,
        'original_recipe_raw_score_sha256': {str(value): references[value]['raw_score_sha256'] for value in configurations},
        'expanded_default_sha256': EXPANDED_DEFAULT_SHA, 'expanded_manifest_sha256': EXPANDED_SHA,
        'composite_fit_trials_before_declaration': 0, 'component_fit_calls_before_declaration': 0,
        'score_calls_before_declaration': 0, 'actual_planned_composite_fit_trials': 24,
        'actual_planned_component_fit_calls': 48, 'normal_calibration_rows_per_bucket': 60000,
        'old_calibration_replaced_not_merged': True, 'zero_fit_strict_recalibration': False,
        'threshold_or_hyperparameter_tuning': False, 'selection_or_promotion': False}
    receipt = output / 'predeclared.private.json'
    fixed.write_private(receipt, declaration)
    fixed.write_private(output / 'integrity-before.private.json', before)
    started = time.monotonic()
    completed, artifacts, replayed, calibration_rows, composite_trials, component_fits = [], {}, 0, 0, 0, 0
    normal_X = [row['features'] for row in old['fold1-fit']]
    labeled_X = [row['features'] for row in training]
    labels = base.training_targets(training)
    validation = old['fold1-validation']
    for ordinal, configuration in enumerate(configurations):
        candidate_start = time.monotonic()
        scorer = base.HybridIncidentScorer(base.HybridResearchConfig(*configuration, random_state=42))
        with hybrid.FitCounter() as count:
            scorer.fit(normal_X, labeled_X, labels)
        if (count.counts != {'composite_fit_trials': 1, 'normal_component_fit_calls': 1, 'supervised_component_fit_calls': 1}
                or scorer.normal_fit_count != 2000 or scorer.labeled_fit_count != 4000):
            raise ValueError('Exact two-component genuine refit population/count required')
        composite_trials += 1; component_fits += 2
        raw = validation_raw_scores(scorer, validation)
        assert_raw_reproduction(raw, references[configuration])
        calibration = {cohort: np.sort(base.chunk_scores(scorer, rows)) for cohort, rows in buckets.items()}
        if {key: len(values) for key, values in calibration.items()} != {'READY': 60000, 'COLD': 60000}:
            raise ValueError('Replacement buckets cannot merge or double-count old calibration')
        calibration_rows += 120000
        calibration_path = output / f'candidate-{ordinal:02d}-calibration.private.json'
        fixed.write_private(calibration_path, {key: values.tolist() for key, values in calibration.items()})
        artifacts[calibration_path.name] = fixed.checksum(calibration_path)
        score_path = output / f'candidate-{ordinal:02d}-scores-decisions.private.jsonl'
        descriptor = os.open(score_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        decisions, percentages, batches = [], [], 0
        with os.fdopen(descriptor, 'w', encoding='utf-8') as evidence, fixed.JavaRiskReplay(
                fixed.WORKSPACE, policy, expected_classes=binding['original_hybrid']['original_fixed_pilot']['java']['replay_classes']) as java:
            for offset in range(0, len(validation), 1000):
                rows = validation[offset:offset + 1000]
                scores = fixed.calibrate_scores(raw[offset:offset + len(rows)], rows, calibration, policy)
                actual = java.score(rows, scores)
                if len(actual) != len(rows):
                    raise ValueError('Actual frozen Java dropped validation rows')
                decisions.extend(actual); percentages.extend(score['normal_percentile'] for score in scores)
                for original, score, decision in zip(rows, scores, actual):
                    evidence.write(fixed.canonical({'frame_id': original['frame_id'], **score,
                                                   'predictions': decision['predictions']}) + '\n')
                batches += 1; replayed += len(actual)
            evidence.flush(); os.fsync(evidence.fileno())
        if len(decisions) != 21000 or sum(row['label'] for row in decisions) != 1000 or batches != 21:
            raise ValueError('Actual Java must conserve all original validation/family populations')
        artifacts[score_path.name] = fixed.checksum(score_path)
        metrics = fixed.decision_metrics(decisions)
        cal_sha = {key: fixed.array_sha(values) for key, values in calibration.items()}
        pct_sha = fixed.array_sha(percentages)
        if configuration == hybrid.DEFAULT and (cal_sha != expanded_default['calibration_sha256']
                or pct_sha != expanded_default['percentile_sha256'] or metrics != expanded_default['decisions']):
            raise ValueError('Repeated expanded default did not reproduce completed reference')
        record = {'ordinal': ordinal, 'configuration': list(configuration), 'parameters': scorer.parameters(),
            'stage': STAGE, 'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY',
            'actual_composite_fit_trials': 1, 'actual_component_fit_calls': 2, 'actual_fit_frames_observed': count.counts,
            'actual_normal_ready_fit_rows': scorer.normal_fit_count, 'actual_labeled_fit_rows': scorer.labeled_fit_count,
            'actual_calibration_score_rows': 120000, 'actual_calibration_fit_calls': 0,
            'normal_calibration_rows': {'READY': 60000, 'COLD': 60000}, 'old_calibration_replaced_not_merged': True,
            'actual_java_replay_batches': batches, 'actual_validation_rows_replayed': len(decisions),
            'validation_raw_scores_exactly_reproduced': True, 'raw_score_sha256': fixed.array_sha(raw),
            'original_recipe_raw_score_sha256': references[configuration]['raw_score_sha256'],
            'percentile_sha256': pct_sha, 'calibration_sha256': cal_sha,
            'decisions': metrics, 'point_diagnostic': fixed.point_diagnostic(metrics, policy),
            'elapsed_seconds': time.monotonic() - candidate_start}
        candidate = output / f'candidate-{ordinal:02d}.private.json'
        fixed.write_private(candidate, record); artifacts[candidate.name] = fixed.checksum(candidate)
        completed.append(record)
        print(fixed.canonical({'stage': STAGE, 'configuration': list(configuration),
            'completed_configurations': len(completed), 'planned_configurations': 24,
            'actual_composite_fit_trials': composite_trials, 'actual_component_fit_calls': component_fits,
            'actual_validation_rows_replayed': replayed, 'aggregate_decisions': {
                scope: metrics[scope]['complete_validation'] for scope in fixed.SCOPES},
            'quality_gate': 'NOT_APPLICABLE'}), flush=True)
    after_binding, _ = base.source_binding(dataset, training_manifest, EXPANDED_ROOT, EXPANDED_SHA)
    after = integrity(after_binding)
    reference_receipts(after_binding, policy)
    if after != before or any(fixed.checksum(output / name) != sha for name, sha in artifacts.items()):
        raise ValueError('Frozen source/data/reference or private evidence changed')
    fixed.write_private(output / 'integrity-after.private.json', after)
    result = {'status': 'COMPLETED', 'stage': STAGE, 'mode': 'COMPLETE_PREDECLARED_GRID',
        'fold': 1, 'seed': 42, 'quality_gate': 'NOT_APPLICABLE', 'data_provenance': 'DEMO_ONLY',
        'integrity_before': before, 'integrity_after': after, 'integrity_unchanged': True,
        'policy': policy.wire(), 'policy_sha256': policy.sha256, 'separation': proof,
        'expanded_default_result_sha256': EXPANDED_DEFAULT_SHA, 'original_grid_sha256': ORIGINAL_GRID_SHA,
        'predeclared_sha256': fixed.checksum(receipt), 'configurations': completed, 'private_artifacts': artifacts,
        'actual_composite_fit_trials': composite_trials, 'actual_component_fit_calls': component_fits,
        'actual_normal_calibration_rows_scored': calibration_rows, 'actual_calibration_fit_calls': 0,
        'actual_validation_rows_replayed': replayed, 'all_original_recipe_validation_raw_hashes_reproduced': True,
        'strict_fit_calls': 0, 'holdout_numeric_records_read': 0, 'old_calibration_merged': False,
        'labels_features_counters_or_cohorts_modified': False, 'threshold_or_hyperparameter_tuning': False,
        'registered_serialized_selected_promoted_or_aws_changed': False,
        'limitations': ['SAME_PREVIOUSLY_INSPECTED_VALIDATION_NOT_UNOPENED_HOLDOUT',
            '60000_NOT_MILLION_NORMAL_CALIBRATION_ROWS_PER_COHORT', 'NO_STRICT_CONFIDENCE_OR360_FIT_SELECTION',
            'REPEATED_CAUSAL_WORLDS_ARE_NOT_INDEPENDENT_PRODUCTION_SAMPLES',
            'PILOT_POINT_QUALIFICATION_IS_NOT_SERVING_QUALIFICATION', 'ALL24_RECIPES_REPORTED_NO_WINNER_SELECTION'],
        'elapsed_seconds': time.monotonic() - started}
    fixed.write_private(output / 'result.private.json', result)
    return output, result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        location, result = run(args.output)
        print(fixed.canonical({'status': result['status'], 'output': str(location),
            'result_sha256': fixed.checksum(location / 'result.private.json'),
            'actual_composite_fit_trials': result['actual_composite_fit_trials'],
            'actual_component_fit_calls': result['actual_component_fit_calls'],
            'quality_gate': 'NOT_APPLICABLE'}), flush=True)
    except Exception as failure:
        raise SystemExit('Expanded hybrid grid refused/failed: ' + type(failure).__name__ + '; private evidence retained') from None
