#!/usr/bin/env python3
"""Run a bounded, network-isolated strict-candidate selection batch after all parallel fit/validation receipts pass.

This command never fits a model, scores holdout rows, registers a candidate in
AWS, activates a model, or modifies cloud resources. Repeated invocations reuse
the exact checksum-bound selection/recalibration receipts already on disk.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / 'observability/scripts/parallel_hybrid_campaign.py'
MIN_RECALIBRATIONS = 1
MAX_RECALIBRATIONS = 45
MAX_LOG_BYTES = 4 * 1024 * 1024
# A full 45-receipt batch can exceed two hours; keep the supervisor attached
# long enough for the child container to reach its bounded checkpoint.
SELECTION_TIMEOUT_SECONDS = 6 * 60 * 60


def load_controller():
    import importlib.util
    spec = importlib.util.spec_from_file_location('parallel_hybrid_campaign_selection', CONTROLLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_selection_readiness(progress):
    if (not isinstance(progress, dict)
            or progress.get('status') != 'PARALLEL_FIT_VALIDATION_COMPLETE'
            or progress.get('completed_fits') != 360
            or progress.get('required_fits') != 360
            or progress.get('completed_validations') != 360
            or progress.get('required_validations') != 360
            or progress.get('quality_gate') != 'NOT_RUN'
            or progress.get('holdout_scored') is not False
            or progress.get('aws_changed') is not False):
        raise ValueError('Selection requires all 360 fit and validation receipts, with holdout unopened')


def selection_preflight(controller, campaign_root):
    """Reject an incomplete run from its small private checkpoint before a full source recheck."""
    root = controller.private_dir(Path(campaign_root).absolute())
    progress = controller.read_private(root / 'parallel-campaign.progress.private.json')
    validate_selection_readiness(progress)
    return root


def validate_batch_limit(value):
    if type(value) is not int or not MIN_RECALIBRATIONS <= value <= MAX_RECALIBRATIONS:
        raise ValueError('A bounded recalibration batch from 1 to 45 is required')


def selection_command(plan, identity, container_name, maximum_recalibrations):
    validate_batch_limit(maximum_recalibrations)
    if re.fullmatch(r'flare-ph-[a-f0-9]{8}-selection-[a-f0-9]{8}', container_name) is None:
        raise ValueError('Owned selection container name required')
    return [
        'docker', 'run', '--rm', '--network', 'none', '--name', container_name,
        '--user', '1000:1000', '--memory', '2g', '--memory-swap', '2g', '--cpus', '1',
        '--pids-limit', '128', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
        '--tmpfs', '/tmp:rw,noexec,nosuid,size=268435456,uid=1000,gid=1000,mode=0700',
        '--entrypoint', 'python',
        '--label', 'flare.parallel.identity=' + identity['campaign_id'],
        '--label', 'flare.parallel.phase=selection',
        '-v', str(plan.code) + ':/code:ro',
        '-v', str(plan.dataset.parent) + ':/source:rw',
        '-v', str(plan.workspace) + ':/workspace:ro',
        '-v', str(plan.workspace) + ':' + str(plan.workspace) + ':ro',
        '-w', '/code',
        '-e', 'PYTHONPATH=/code',
        '-e', 'PYTHONDONTWRITEBYTECODE=1',
        '-e', 'PYTHONPYCACHEPREFIX=/tmp/parallel-selection-bytecode',
        '-e', 'OPENBLAS_NUM_THREADS=1',
        '-e', 'OMP_NUM_THREADS=1',
        plan.image, '-B', '-m', 'app.selection', 'choose',
        '--dataset', '/source/standard', '--workspace', '/workspace',
        '--model-kind', plan.identity['model_kind'], '--coordinated',
        '--dataset-sha256', plan.identity['dataset_sha256'],
        '--archive-sha256', plan.identity['archive_sha256'],
        '--max-new-recalibrations', str(maximum_recalibrations),
    ]


def write_private_log(path, raw):
    if len(raw) > MAX_LOG_BYTES:
        raw = raw[-MAX_LOG_BYTES:]
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def run_batch(campaign_root, maximum_recalibrations):
    validate_batch_limit(maximum_recalibrations)
    controller = load_controller()
    campaign_root = selection_preflight(controller, campaign_root)
    legacy, root, identity, plan = controller.load_campaign(campaign_root)
    progress_path = root / 'parallel-campaign.progress.private.json'
    progress = controller.read_private(progress_path)
    validate_selection_readiness(progress)

    coordinator_path = root / 'state/coordinator.private.json'
    if coordinator_path.exists():
        coordinator = controller.read_private(coordinator_path)
        if (coordinator.get('campaign_id') == identity['campaign_id']
                and controller._coordinator_is_alive(coordinator.get('pid'), root)):
            raise ValueError('Fit/validation coordinator is still live; selection must wait for its terminal exit')

    dataset = plan.dataset
    validation_progress_path = dataset / 'hybrid-validation.progress.json'
    ranking_path = dataset / 'hybrid-ranking.json'
    validation_progress = controller._read_receipt(validation_progress_path)
    ranking = controller._read_receipt(ranking_path)
    if (validation_progress is None or validation_progress.get('status') != 'COMPLETED'
            or validation_progress.get('completed_runs') != 360
            or ranking is None or ranking.get('validation_runs_completed') != 360
            or ranking.get('data_provenance') != 'DEMO_ONLY'):
        raise ValueError('The independently finalized 360-run DEMO_ONLY ranking is required')

    container_name = 'flare-ph-' + identity['campaign_id'][:8] + '-selection-' + secrets.token_hex(4)
    if subprocess.run(['docker', 'inspect', container_name], capture_output=True).returncode == 0:
        raise ValueError('Selection container name collision')
    command = selection_command(plan, identity, container_name, maximum_recalibrations)
    result = subprocess.run(command, capture_output=True, timeout=SELECTION_TIMEOUT_SECONDS)
    log_path = root / 'logs' / ('selection-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                                + '-' + secrets.token_hex(3) + '.private.log')
    write_private_log(log_path, (result.stdout or b'') + (result.stderr or b''))
    if result.returncode:
        raise RuntimeError('Bounded selection container failed; private log retained')
    lines = result.stdout.decode('utf-8', errors='strict').splitlines()
    summary = json.loads(lines[-1]) if lines else {}
    if (summary.get('status') not in ('STOPPED_AT_RECALIBRATION_BOUNDARY', 'SELECTED', 'NO_QUALIFIED_CONFIG')
            or summary.get('quality_gate') != 'NOT_RUN'
            or summary.get('holdout_scored') is not False
            or summary.get('data_provenance') != 'DEMO_ONLY'
            or summary.get('actual_fits_completed') != 360
            or summary.get('validation_runs_completed') != 360
            or summary.get('additional_fit_calls_in_recalibration') != 0):
        raise ValueError('Selection summary violated the frozen strict-campaign contract; private log retained')
    return {
        'status': summary['status'],
        'model_version': summary.get('model_version'),
        'completed_recalibrations': summary.get('completed_recalibrations'),
        'new_recalibrations_completed': summary.get('new_recalibrations_completed'),
        'additional_fit_calls_in_recalibration': summary['additional_fit_calls_in_recalibration'],
        'quality_gate': summary['quality_gate'],
        'holdout_scored': summary['holdout_scored'],
        'data_provenance': summary['data_provenance'],
        'aws_changed': False,
        'private_log': str(log_path.relative_to(ROOT)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-root', type=Path, required=True)
    parser.add_argument('--max-new-recalibrations', type=int, required=True,
                        help='Bound this invocation to 1..45 new calibration-only receipts')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = run_batch(args.campaign_root, args.max_new_recalibrations)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({'status': 'FAILED', 'error_type': type(error).__name__, 'sensitive_output_omitted': True}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
