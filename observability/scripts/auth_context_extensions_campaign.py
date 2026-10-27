#!/usr/bin/env python3
"""Offline campaign windows with durable checkpoints and independent recovery.

No deployment. Requires explicit --allow-elk-maintenance to operate on the three
registered ELK containers. Completed stages and fit/evaluation reservations are
never replayed. A failed window requires inspection, not an automatic retry.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import auth_context_research_runner as base

ELK = ('flare-otp-local-kibana-1', 'flare-otp-local-logstash-1',
       'flare-otp-local-elasticsearch-1')
PROTECTED = ('flare-otp-local-app-1', 'flare-otp-local-db-1',
             'flare-otp-local-redis-1', 'flare-otp-local-postlogin-worker-1',
             'flare-otp-local-gateway-1', 'flare-otp-local-nginx-1',
             'flare-otp-local-filebeat-1', 'flare-local-elk-mailpit-1')


def atomic(path, value):
    temporary = path.with_name(path.name + '.partial-' + str(os.getpid()))
    with temporary.open('x') as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True, allow_nan=False)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inspect(name):
    return json.loads(subprocess.check_output(['docker', 'inspect', name], timeout=20))[0]


def identity(value):
    return {'id': value['Id'], 'image': value['Image'],
            'started_at': value['State']['StartedAt'], 'running': value['State']['Running']}


def models():
    return {str(p.relative_to(base.PUBLICATIONS)): base.file_sha(p, 32*1024**2)
            for folder in (base.BASELINE, base.SHADOW) for p in sorted(folder.glob('*.json'))}


def process_identity(pid):
    try:
        # Start ticks disambiguate PID reuse; process names can contain spaces.
        return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def owned_containers(job):
    ids = subprocess.check_output(['docker', 'ps', '-aq'], timeout=20).decode().split()
    if not ids:
        return []
    values = json.loads(subprocess.check_output(['docker', 'inspect', *ids], timeout=20))
    return [v['Id'] for v in values
            if v['Name'].startswith('/auth-research-')
            and any(Path(m['Source']) == job or job in Path(m['Source']).parents
                    for m in v.get('Mounts', []) if m.get('Type') == 'bind')]


def recover(job, window):
    """Idempotent recovery shared by the driver and its detached watchdog."""
    with (window/'recovery.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (window/'recovery.json').exists():
            return json.loads((window/'recovery.json').read_bytes())
        state = json.loads((window/'maintenance.json').read_bytes())
        errors = []
        for container in owned_containers(job):
            result = subprocess.run(['docker', 'rm', '-f', container], timeout=30,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                errors.append('owned research container cleanup failed: '+container)
        restored = {}
        for name in reversed(state['stopped']):
            try:
                now = inspect(name); before = state['elk_before'][name]
                if now['Id'] != before['id'] or now['Image'] != before['image']:
                    raise RuntimeError('container identity changed')
                subprocess.run(['docker', 'start', name], check=True, timeout=45,
                               stdout=subprocess.DEVNULL)
                restored[name] = 'starting'
            except Exception as error:
                errors.append(name+': '+str(error))
        until = time.monotonic()+300
        while restored and time.monotonic() < until:
            for name in restored:
                v = inspect(name)
                restored[name] = v['State'].get('Health', {}).get(
                    'Status', 'running' if v['State']['Running'] else 'stopped')
            if all(s in ('healthy', 'running') for s in restored.values()):
                break
            time.sleep(5)
        unchanged = all(identity(inspect(n)) == prior for n, prior in state['protected_before'].items())
        result = {'restored': restored, 'errors': errors, 'models_unchanged': models() == state['models_before'],
                  'protected_unchanged': unchanged, 'at': time.time()}
        result['status'] = 'RESTORED' if (not errors and unchanged and result['models_unchanged']
                           and all(s in ('healthy', 'running') for s in restored.values())) else 'RECOVERY_NEEDS_ATTENTION'
        atomic(window/'recovery.json', result)
        return result


def watchdog(job, window, pid, start):
    # Independent session survives the driver being killed or its terminal closing.
    while not (window/'recovery.json').exists():
        state = json.loads((window/'maintenance.json').read_bytes())
        if process_identity(pid) != start or time.time() > state['deadline']:
            if process_identity(pid) == start:
                os.kill(pid, signal.SIGTERM)
            recover(job, window)
            return
        time.sleep(2)


def commands(kind, job):
    runner = [sys.executable, '-B', 'observability/scripts/auth_context_extensions_runner.py']
    def cmd(stage, cohort=None, smoke=False):
        args = runner+[stage, '--job', str(job)]
        if cohort:
            args += ['--cohort', cohort]
        if smoke:
            args += ['--smoke', '100']
        return args
    if kind == 'smoke':
        result = [('classpath', [sys.executable, '-B', 'observability/scripts/auth_context_research_classpath.py', '--job', str(job)])]
        for cohort in ('READY', 'COLD'):
            result += [(s+'-'+cohort.lower()+'-smoke', cmd(s, cohort, True)) for s in ('capture', 'parity')]
            result += [('smoke-'+cohort.lower(), cmd('smoke', cohort)),
                       ('fault-'+cohort.lower(), cmd('fault', cohort))]
        return result
    if kind in ('ready', 'cold'):
        return [(s+'-'+kind, cmd(s, kind.upper())) for s in ('capture', 'parity', 'select', 'evaluate')]
    if kind == 'http':
        return [('package', cmd('package')), ('http-test', cmd('http-test')), ('benchmark', cmd('benchmark'))]
    return [('soak', cmd('soak'))]


def run_window(job, kind):
    window = job/('window-'+kind)
    window.mkdir(mode=0o700)  # Never replay a failed or completed window.
    state = {'status': 'PREPARING', 'stopped': [], 'stages': [], 'started_at': time.time(),
             'deadline': time.time()+base.MAX_SECONDS,
             'protected_before': {n: identity(inspect(n)) for n in PROTECTED},
             'elk_before': {n: identity(inspect(n)) for n in ELK}, 'models_before': models()}
    if not all(v['running'] for v in state['elk_before'].values()):
        raise RuntimeError('all registered ELK containers must initially be running')
    atomic(window/'maintenance.json', state)
    with (window/'watchdog.log').open('x') as log:
        watcher = subprocess.Popen([sys.executable, '-B', str(Path(__file__).resolve()),
            '_watchdog', '--job', str(job), '--window', str(window), '--pid', str(os.getpid()),
            '--start', process_identity(os.getpid())], start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    child = None
    def interrupted(_sig, _frame):
        raise KeyboardInterrupt()
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        for name in ELK:
            if base.available_memory() >= base.ADMISSION_MEMORY:
                break
            state['stopped'].append(name)
            atomic(window/'maintenance.json', state)  # Journal intent before mutation.
            print('TEMPORARY_STOP', name, flush=True)
            subprocess.run(['docker', 'stop', '--time', '30', name], check=True, timeout=45,
                           stdout=subprocess.DEVNULL)
            time.sleep(2)
        base.resource_check(job, admission=True)
        for name, args in commands(kind, job):
            if time.time() > state['deadline'] or (window/'recovery.json').exists():
                raise RuntimeError('maintenance deadline or recovery triggered')
            state['phase'] = name; atomic(window/'maintenance.json', state)
            print('PHASE', name, flush=True)
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
            started = time.time()
            with (window/(name+'.log')).open('x') as log:
                child = subprocess.Popen(args, cwd=base.ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                while child.poll() is None:
                    if time.time() > state['deadline']:
                        raise RuntimeError('maintenance deadline exceeded')
                    time.sleep(2)
            code = child.returncode; child = None
            state['stages'].append({'stage': name, 'exit_code': code, 'seconds': time.time()-started})
            atomic(window/'maintenance.json', state)
            if code:
                raise RuntimeError(name+' failed; inspect immutable stage log')
        state['status'] = 'WINDOW_COMPLETED'
    except BaseException as error:
        state['status'] = 'STOP_INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'WINDOW_FAILED'
        state['error'] = str(error)
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait(timeout=10)
        atomic(window/'maintenance.json', state)
        recovery = recover(job, window)
        watcher.wait(timeout=10)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    atomic(job/'checkpoint.json', {'phase': kind, 'status': state['status'], 'recovery': recovery,
                                   'window': str(window), 'updated_at': time.time()})
    print(json.dumps({'status': state['status'], 'recovery': recovery}), flush=True)
    if state['status'] != 'WINDOW_COMPLETED' or recovery['status'] != 'RESTORED':
        raise RuntimeError(state.get('error', 'maintenance recovery needs attention'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind', choices=('smoke', 'ready', 'cold', 'http', 'soak', '_watchdog'))
    p.add_argument('--job', required=True, type=Path)
    p.add_argument('--allow-elk-maintenance', action='store_true')
    p.add_argument('--window', type=Path); p.add_argument('--pid', type=int); p.add_argument('--start')
    a = p.parse_args(); job = base.safe_path(a.job, base.RESEARCH_ROOT)
    if a.kind == '_watchdog':
        watchdog(job, base.safe_path(a.window, job), a.pid, a.start)
        return
    if not a.allow_elk_maintenance:
        p.error('explicit maintenance authorization flag required')
    with (job/'campaign.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run_window(job, a.kind)


if __name__ == '__main__':
    main()
