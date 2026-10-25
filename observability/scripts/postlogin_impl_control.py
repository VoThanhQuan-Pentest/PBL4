#!/usr/bin/env python3
"""Bounded implementation jobs and explicit safe pause/resume; never grants fits."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time

from postlogin_research_step import run as research_run, process_start
from ueba_research_artifacts import commit, digest, private_directory, publish
from postlogin_preparation_audit import checked

REPO = Path(__file__).resolve().parents[2]
OUTPUT = REPO / 'observability/runtime/postlogin-legacy-reuse-20261022-r1'
PARENT = REPO / 'observability/runtime/postlogin-lab-preparation-20261021-r1'
FIT_LEDGER = REPO / 'observability/runtime/postlogin-risk-ratio-20261021-r1/risk-fit-ledger.private.json'
RUNTIME = REPO / 'observability/runtime/postlogin-project-runtime'


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def now():
    return datetime.now(timezone.utc).isoformat()


def read(name):
    return json.loads((OUTPUT / name).read_text())


def held():
    p = OUTPUT / 'operator-hold.private.json'
    return p.exists() and json.loads(p.read_text()).get('hold_new_units') is True


def runtime_hold(value):
    # The application only reads this minimal, non-secret publication. Historical
    # model/credential files and application database are not touched here.
    if RUNTIME.exists():
        p = RUNTIME / 'operator-hold.json'
        fd, pending = tempfile.mkstemp(dir=RUNTIME, prefix='.operator-hold-')
        os.fchmod(fd, 0o640)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump({'hold_new_units': value, 'updated_at_utc': now()}, stream)
                stream.flush();os.fsync(stream.fileno())
            os.replace(pending, p)
        finally:
            if os.path.exists(pending):os.unlink(pending)
        directory = os.open(RUNTIME, os.O_DIRECTORY);os.fsync(directory);os.close(directory)


def initialize():
    private_directory(OUTPUT)
    if (OUTPUT / 'budget.private.json').exists():
        if read('implementation-authorization-v1.receipt.private.json')['new_fit_cap'] != 0:
            raise ValueError('ZERO_FIT_IMPLEMENTATION_ONLY')
        return
    parent = json.loads((PARENT / 'budget.private.json').read_text())
    if parent['active_unit']:raise RuntimeError('PARENT_JOB_STILL_ACTIVE')
    authorization = {'status': 'USER_AUTHORIZED_IMPLEMENTATION', 'authorized_at_utc': now(),
        'user_request': 'Implement tích hợp model cũ và chặn có kiểm soát; tạm dừng/tiếp tục theo checkpoint.',
        'new_fit_cap': 0, 'maximum_new_job_seconds': 43200, 'checkpoint_reserve_seconds': 600,
        'maximum_new_sensitive_http_attempts': 1000, 'initial_external_provider_requests': 2,
        'artifact_byte_cap': 2 * 1024**3, 'temporary_byte_cap': 1024**3,
        'disk_reserve_bytes': 5000000000, 'cpu_cap': 4, 'memory_cap_bytes': 4 * 1024**3,
        'qualification_scope': 'PROJECT_LIMITED', 'quota_policy': 'NOT_USED',
        'historical_fit_ledger_sha256': digest(FIT_LEDGER), 'aws_changed': False,
        'training_99_day_campaign': False, 'presentation_and_practice_cases': 'PRESERVE'}
    commit(OUTPUT, authorization, phase='implementation-authorization-v1')
    publish(OUTPUT / 'budget.private.json', {'elapsed_seconds': parent['elapsed_seconds'],
        'inherited_job_seconds': parent['elapsed_seconds'], 'inherited_ledger': str(PARENT / 'budget.private.json'),
        'inherited_ledger_sha256': digest(PARENT / 'budget.private.json'),
        'cap_seconds': parent['elapsed_seconds'] + 43200, 'group_seconds': {},
        'checkpoint_reserve_seconds': 600, 'disk_reserve_bytes': 5000000000,
        'reserve_checkpoint_for_all_groups': True, 'otp_reserve_seconds': 0,
        'pilot_cap_seconds': 0, 'active_unit': None, 'recovered_interrupted_units': 0})
    publish(OUTPUT / 'operator-hold.private.json', {'hold_new_units': False, 'reason': 'USER_IMPLEMENTATION_REQUEST'})
    publish(OUTPUT / 'operator-state.private.json', {'status': 'IMPLEMENTATION_P0_PREFLIGHT',
        'phase': 'P0', 'new_fit_cap': 0, 'new_fits': 0, 'quota_policy': 'NOT_USED',
        'active_handle': None, 'auto_containment': False, 'aws_changed': False,
        'next_action': 'Snapshot relevant source, backup local database, then implement fixed-model serving.'})


def status():
    budget = read('budget.private.json');active = budget['active_unit']
    identity_path = OUTPUT / 'current-unit.private.json'
    identity = json.loads(identity_path.read_text()) if identity_path.exists() else {}
    same_boot = identity.get('boot_id') == boot_id()
    alive = bool(active and same_boot and active.get('pid') and process_start(active['pid']) == active.get('process_start'))
    result = {'status': 'PAUSE_REQUESTED' if held() and active else 'PAUSED' if held() else read('operator-state.private.json')['status'],
              'phase': read('operator-state.private.json').get('phase'), 'active_unit': active,
              'job_alive': alive, 'owner_boot_matches': same_boot, 'hold_new_units': held(),
              'new_job_seconds_committed': budget['elapsed_seconds'] - budget['inherited_job_seconds'],
              'new_fits': 0, 'disk_free_bytes': shutil.disk_usage(OUTPUT).free,
              'quota_policy': 'NOT_USED'}
    print(json.dumps(result))
    return result


def pause():
    publish(OUTPUT / 'operator-hold.private.json', {'hold_new_units': True, 'reason': 'EXPLICIT_USER_PAUSE', 'at_utc': now()})
    runtime_hold(True)
    budget = read('budget.private.json');active = budget['active_unit']
    metadata = read('current-unit.private.json') if (OUTPUT / 'current-unit.private.json').exists() else {}
    if (active and metadata.get('unit') == active['id'] and metadata.get('boot_id') == boot_id()
            and metadata.get('pause_mode') == 'interruptible' and active.get('pid')
            and process_start(active['pid']) == active.get('process_start')):
        try:os.killpg(active['pid'], signal.SIGTERM)
        except ProcessLookupError:pass
    state = read('operator-state.private.json')
    state.update(status='PAUSE_REQUESTED' if active else 'PAUSED',
                 next_action='Wait for current boundary/receipt, verify owned jobs stopped; user may resume from checkpoint.')
    publish(OUTPUT / 'operator-state.private.json', state)
    return status()


def resume():
    budget = read('budget.private.json');active = budget['active_unit']
    if active:
        raise RuntimeError('RECONCILE_ACTIVE_UNIT_BEFORE_RESUME_NO_BLIND_REPLAY')
    if digest(FIT_LEDGER) != read('implementation-authorization-v1.receipt.private.json')['historical_fit_ledger_sha256']:
        raise RuntimeError('HISTORICAL_FIT_LEDGER_CHANGED')
    publish(OUTPUT / 'operator-hold.private.json', {'hold_new_units': False, 'reason': 'EXPLICIT_USER_RESUME', 'at_utc': now()})
    state = read('operator-state.private.json');state.update(status='READY_TO_RESUME',
        runtime_revalidation_required=True,
        next_action='Recheck committed units and runtime identities; keep runtime hold until revalidation succeeds.')
    publish(OUTPUT / 'operator-state.private.json', state)
    return status()


def run_unit(args):
    with (OUTPUT / 'implementation-run.lock').open('a+') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if read('budget.private.json')['active_unit']:
            raise RuntimeError('OBSERVE_OR_RECONCILE_EXISTING_UNIT_FIRST')
        return _run_unit(args)


def _run_unit(args):
    if held():raise RuntimeError('EXPLICIT_OPERATOR_HOLD')
    if read('operator-state.private.json').get('boundary_audit_required') and not args.unit.startswith('job-reconcile-'):
        raise RuntimeError('BOUNDARY_AUDIT_REQUIRED_BEFORE_NORMAL_JOBS')
    authorization = read('implementation-authorization-v1.receipt.private.json')
    if authorization['new_fit_cap'] != 0:raise RuntimeError('ZERO_FIT_IMPLEMENTATION_ONLY')
    if not args.unit.startswith('job-'):
        previous = OUTPUT / (args.unit + '.receipt.private.json')
        if not previous.exists() or json.loads(previous.read_text()).get('unit') != args.unit:
            raise ValueError('NEW_JOB_NAMES_REQUIRE_JOB_PREFIX_TO_SEPARATE_CHILD_ARTIFACTS')
    if digest(FIT_LEDGER) != authorization['historical_fit_ledger_sha256']:
        raise RuntimeError('HISTORICAL_FIT_LEDGER_CHANGED')
    command = args.command[1:] if args.command and args.command[0] == '--' else args.command
    if not command:raise ValueError('EXPLICIT_COMMAND_REQUIRED')
    metadata = {'unit': args.unit, 'boot_id': boot_id(), 'controller_pid': os.getpid(),
                'controller_process_start': process_start(os.getpid()), 'pause_mode': args.pause_mode,
                'started_at_utc': now(), 'new_fit_cap': 0}
    publish(OUTPUT / 'current-unit.private.json', metadata)
    code = research_run(OUTPUT, args.unit, args.group, args.maximum_seconds, command,
                        [Path(__file__), FIT_LEDGER, *args.input])
    if digest(FIT_LEDGER) != authorization['historical_fit_ledger_sha256']:
        raise RuntimeError('UNEXPECTED_FIT_LEDGER_MUTATION')
    if held():
        state = read('operator-state.private.json');state.update(status='PAUSED', active_handle=None)
        publish(OUTPUT / 'operator-state.private.json', state)
    return code


def reconcile():
    # A dead process is not evidence that a state-changing HTTP request failed.
    # Reconcile accounting first; boundary jobs additionally require a DB audit.
    with (OUTPUT / 'research-step.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        budget = read('budget.private.json');active = budget['active_unit']
        if not active:return status()
        metadata = read('current-unit.private.json')
        if metadata['unit'] != active['id']:raise RuntimeError('UNIT_IDENTITY_RECONCILIATION_REQUIRED')
        same_boot = metadata['boot_id'] == boot_id()
        if same_boot and active.get('pid') and process_start(active['pid']) == active.get('process_start'):
            raise RuntimeError('LIVE_JOB_MUST_NOT_BE_REPLAYED')
        if same_boot and datetime.now(timezone.utc).timestamp() < datetime.fromisoformat(active['deadline_utc']).timestamp() + 10:
            raise RuntimeError('WAIT_INDEPENDENT_DEADLINE_BEFORE_LOST_JOB_RECOVERY')
        phase = 'lost-unit-recovery-' + str(budget['recovered_interrupted_units'] + 1)
        before = digest(OUTPUT / 'budget.private.json')
        budget['elapsed_seconds'] += active['cap_seconds']
        budget['group_seconds'][active['group']] = budget['group_seconds'].get(active['group'], 0) + active['cap_seconds']
        budget['recovered_interrupted_units'] += 1;budget['active_unit'] = None
        # Publish intent before the budget. Recovery is conservatively charged
        # and never represented as a successful or completed business operation.
        commit(OUTPUT, {'status': 'INTERRUPTED_UNIT_REQUIRES_REVALIDATION', 'unit': active,
            'budget_before_sha256': before, 'charged_seconds': active['cap_seconds'],
            'same_boot': same_boot, 'boundary_audit_required': metadata['pause_mode'] == 'boundary'}, phase=phase)
        state = read('operator-state.private.json');state.update(status='INTERRUPTED_REVALIDATION_REQUIRED',
            boundary_audit_required=metadata['pause_mode'] == 'boundary', runtime_revalidation_required=True,
            interrupted_unit_id=active['id'],
            next_action='Audit interrupted unit outputs and owned resources before any state-changing retry.')
        publish(OUTPUT / 'operator-state.private.json', state)
        publish(OUTPUT / 'budget.private.json', budget)
    return status()


def acknowledge_boundary(args):
    with (OUTPUT / 'implementation-run.lock').open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if read('budget.private.json')['active_unit']:raise RuntimeError('ACTIVE_UNIT_MUST_FINISH_FIRST')
        state=read('operator-state.private.json')
        proof=checked(OUTPUT,args.receipt)
        if (proof.get('status')!='BOUNDARY_OUTCOME_AUDIT_PASS'
                or proof.get('interrupted_unit_id')!=state.get('interrupted_unit_id')
                or proof.get('business_resolution') not in {'NO_SIDE_EFFECTS','COMMITTED_VERIFIED','NO_REPLAY_RECONCILED'}
                or proof.get('protected_state_verified') is not True
                or proof.get('owned_resources_verified') is not True):
            raise RuntimeError('MATCHING_DATABASE_OUTCOME_AND_RESOURCE_AUDIT_REQUIRED')
        runtime_hold(True)
        state.update(boundary_audit_required=False,runtime_revalidation_required=True,
                boundary_audit_receipt=args.receipt,status='BOUNDARY_RECONCILED_RUNTIME_HELD')
        publish(OUTPUT/'operator-state.private.json',state)
        return status()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__);sub = p.add_subparsers(dest='action', required=True)
    for name in ('initialize', 'status', 'hold', 'resume', 'reconcile'):sub.add_parser(name)
    audit=sub.add_parser('ack-boundary');audit.add_argument('--receipt',required=True)
    run = sub.add_parser('run');run.add_argument('--unit', required=True)
    run.add_argument('--group', choices=['setup', 'verification'], default='verification')
    run.add_argument('--maximum-seconds', type=int, required=True)
    run.add_argument('--pause-mode', choices=['interruptible', 'boundary'], required=True)
    run.add_argument('--input', type=Path, action='append', default=[]);run.add_argument('command', nargs=argparse.REMAINDER)
    args = p.parse_args()
    if args.action=='ack-boundary':acknowledge_boundary(args);raise SystemExit(0)
    if args.action == 'run':raise SystemExit(run_unit(args))
    {'initialize': initialize, 'status': status, 'hold': pause, 'resume': resume, 'reconcile': reconcile}[args.action]()
