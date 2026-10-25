"""Zero-fit capacity screen for the real-time strict campaign, never an approval."""
import argparse
from collections import Counter
import hashlib
import math
from pathlib import Path
import shutil

from postlogin_preparation_audit import checked, full_population, verify_pipeline
from ueba_research_artifacts import canonical, commit, digest, private_directory

COHORTS = ('READY', 'UNSEEN_READY', 'COLD')
FAMILIES = ('request_burst', 'endpoint_scan', 'auth_failure_burst',
            'sensitive_action_burst', 'http_error_burst')


def ratio_counts(count, ratio):
    if sum(ratio) != 100 or any(count * n % 100 for n in ratio):
        raise ValueError('exact integral cohort counts required')
    return {cohort: count * n // 100 for cohort, n in zip(COHORTS, ratio)}


def population(normal, per_family=None):
    result = Counter({c + '/normal': n for c, n in normal.items()})
    for family in FAMILIES:
        result.update({c + '/' + family: n for c, n in (per_family or {}).items()})
    return result


def capacity_screen(protocol, mean):
    if set(mean) != set(full_population()) or any(
            type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in mean.values()):
        raise ValueError('finite positive measurements for all18strata required')
    phases = []
    for fold in protocol['folds']:
        label = fold['labeled_training']
        normal = dict(label['supplement_normal_cohorts'])
        normal['READY'] += fold['normal_fit']['records']
        phases.append((f"fold-{fold['fold']}-training-source", None,
                       population(normal, label['positive_per_family'])))
        cal = fold['calibration']
        phases.append((f"fold-{fold['fold']}-calibration", cal['days'],
                       population({c: cal[c] for c in ('READY', 'COLD')})))
        val = fold['validation']
        phases.append((f"fold-{fold['fold']}-validation", val['days'],
                       population(ratio_counts(val['normal'], val['cohort_ratio']),
                                  ratio_counts(val['positive_per_family'], val['cohort_ratio']))))
    hold = protocol['holdout']
    phases.append(('holdout-source-only-unopened', hold['days'],
                   population(ratio_counts(hold['normal'], hold['cohort_ratio']),
                              ratio_counts(hold['positive_per_family'], hold['cohort_ratio']))))
    total = Counter()
    report = []
    for name, days, counts in phases:
        total.update(counts)
        seconds = sum(n * mean[key] for key, n in counts.items())
        available = None if days is None else days * 86400
        report.append({'phase': name, 'rows': sum(counts.values()),
                       'measured_serial_seconds': seconds,
                       'serial_seconds_with50percent_margin': seconds * 1.5,
                       'fixed_collection_seconds': available,
                       'single_serial_producer_fits_window': None if available is None else seconds * 1.5 <= available,
                       'arithmetic_concurrency_lower_bound_not_verified_speedup': None if available is None else math.ceil(seconds * 1.5 / available)})
    if total != Counter(full_population()):
        raise ValueError('source layout population differs from measured full campaign population')
    return report


def admission(root):
    verify_pipeline(root)
    measured = checked(root, 'measured-preparation-result-v1')
    proposal = checked(root, 'campaign-budget-proposal-v1')
    if (measured['status'] != 'ZERO_FIT_PREPARATION_MEASUREMENTS_COMPLETE'
            or proposal['measurements_receipt_sha256'] != digest(root / 'measured-preparation-result-v1.receipt.private.json')):
        raise ValueError('complete checksum-bound measurements required')
    protocol = measured['strict_protocol']
    phases = capacity_screen(protocol, measured['mean_capture_seconds_per_stratum'])
    from app.hybrid_strict_protocol import disk_plan
    storage = disk_plan()
    components = storage['components_bytes']
    rows = sum(full_population().values())
    # Bounded JSONL feature rows: opaque ID<=128,65 finite doubles; no names,
    # raw events or labels in this component. This does not bound retained raw.
    components['numeric_json_upper'] = rows * 2048
    components.pop('shared37_float64_cache')
    components['shared65_float64_cache'] = rows * 65 * 8
    planned = sum(components.values()) + storage['reserve_bytes']
    failed = [p['phase'] for p in phases if p['single_serial_producer_fits_window'] is False]
    return {'status': 'NOT_ADMITTED_CAPACITY_STORAGE_AND_RUNNER',
            'measurements_receipt_sha256': digest(root / 'measured-preparation-result-v1.receipt.private.json'),
            'protocol_sha256': hashlib.sha256(canonical(protocol).encode()).hexdigest(),
            'source_layout': {'evaluation_unit': protocol['evaluation_unit'], 'feature_schema_version': 6,
                              'total_unique_episodes': rows, 'phases': phases,
                              'normal_training_rows_shared_once': True,
                              'labels_outside_numeric_features': True,
                              'benchmark_reuse_for_training': False,
                              'real_clock_calendar_days': 99},
            'serial_capacity_failures': failed,
            'parallel_speedup_verified': False,
            'storage': {'conservative_retention_components_bytes': components,
                        'planned_bytes_including5GBreserve_before_raw': planned,
                        'ssd_free_bytes': shutil.disk_usage(root).free,
                        'raw_history_storage_upper_bound_verified': False,
                        'model_size_uses_codec_ceiling_not_measured_typical_size': True,
                        'usb_used_as_hot_storage': False, 'admitted': False},
            'runner_bound_to_final_source_layout': False,
            'campaign_total_job_cap_authorized': False,
            'fit_time_estimate_measured': False,
            'next_actions': ['Measure producer concurrency without weakening real login limits.',
                             'Verify retained raw/history/model/score storage with a feasible allocation.',
                             'Bind final source/runner and one total campaign authorization before T0.'],
            'new_fits': 0, 'holdout_numeric_records_read': 0, 'quota_policy': 'NOT_USED',
            'training_admitted': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    root = private_directory(args.output.resolve())
    result = admission(root)
    commit(root, result, phase='strict-campaign-admission-v1')
    print(canonical({k: result[k] for k in ('status', 'serial_capacity_failures', 'new_fits')}))
