"""Prepare the strict campaign schedule without reading data or fitting models.

This is a plan, not an executable authorization or a training runner. All trial
identities and population/calendar requirements come from the existing protocol.
"""
import argparse
import hashlib
from pathlib import Path

from ueba_research_artifacts import canonical, commit, private_directory


def build_plan(dataset_id):
    from app.postlogin_contract import source_protocol

    protocol = source_protocol(dataset_id)
    protocol_hash = hashlib.sha256(canonical(protocol).encode()).hexdigest()
    sources = {fold['fold']: fold for fold in protocol['folds']}
    trials = []
    for run in protocol['campaign']:
        fold = sources[run['fold']]
        trials.append({
            'run_id': run['run_id'], 'fold': run['fold'],
            'recipe_sha256': run['recipe_sha256'], 'config': run['config'],
            'required_source_section': f"fold-{run['fold']}",
            'ordered_steps': ['FIT_NORMAL', 'FIT_CONTEXT_CLASSIFIER',
                              'CALIBRATE_MATCHING_FOLD', 'VALIDATE_MATCHING_FOLD'],
            'relative_protocol_days': {
                'fit': fold['fit_day'],
                'calibration': fold['calibration']['start_day'],
                'validation': fold['validation']['start_day']},
        })
    if len(trials) != 360 or len({r['run_id'] for r in trials}) != 360:
        raise ValueError('exact unique strict360 schedule required')
    return {
        'status': 'PLAN_ONLY_NOT_AUTHORIZED', 'format': 'POSTLOGIN_CAMPAIGN_PLAN_V1',
        'dataset_id': dataset_id, 'protocol_sha256': protocol_hash,
        'feature_schema_version': 6, 'evaluation_unit': protocol['evaluation_unit'],
        'source_folds': protocol['folds'], 'trials': trials,
        'required_composite_fits': protocol['required_composite_trials'],
        'required_component_fits': protocol['required_component_fit_calls'],
        'required_top_recalibrations': protocol['required_top_recalibrations'],
        'recalibration_additional_fits': 0,
        'holdout': protocol['holdout'],
        'phase_order': ['MEASURE_PREPARATION', 'BIND_FRESH_SOURCE_LAYOUT_AND_RUNNER',
                        'ADMIT_STORAGE_RUNTIME_AND_CAMPAIGN_BUDGET',
                        'COLLECT_REAL_TIME_SOURCE', 'FIT_CALIBRATE_VALIDATE_ALL360',
                        'TOP45_RECALIBRATIONS_AND_COMMON_POLICY',
                        'LOCK_SELECTION_BEFORE_HOLDOUT', 'EVALUATE_SEALED_HOLDOUT',
                        'REAL_SHADOW_AT_LEAST24H', 'REVIEW_ADOPTION'],
        'failure_routes': {
            'preparation_incomplete': 'RECONCILE_COMMITTED_UNITS_WITHOUT_BLIND_REPLAY',
            'source_not_qualified': 'CORRECT_SOURCE_WITH_NEW_VERSION_BEFORE_FIT',
            'storage_or_budget_insufficient': 'REVISE_RESOURCE_PLAN_BEFORE_START',
            'trial_failed': 'RECORD_FAILURE_AND_RESUME_ONLY_UNCOMMITTED_AUTHORIZED_UNIT',
            'strict_gate_failed': 'REPORT_NOT_QUALIFIED_WITHOUT_OPENING_HOLDOUT',
            'holdout_failed': 'REJECT_CANDIDATE_KEEP_CURRENT_MODEL',
            'shadow_failed': 'REJECT_ADOPTION_KEEP_CURRENT_MODEL',
            'all_gates_passed': 'PRESENT_VERIFIED_RESULT_FOR_ADOPTION_REVIEW'},
        'new_fits': 0, 'holdout_numeric_records_read': 0,
        'training_admitted': False, 'quota_policy': 'NOT_USED',
        'automatic_deployment_or_containment': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset-id', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = build_plan(args.dataset_id)
    commit(private_directory(args.output.resolve()), result,
           phase='strict-campaign-execution-plan-v1')
    print(canonical({key: result[key] for key in
                     ('status', 'required_composite_fits', 'required_component_fits', 'new_fits')}))
