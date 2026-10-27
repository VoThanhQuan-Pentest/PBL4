#!/usr/bin/env python3
"""Isolated controlled-clock research corpus. Never connects to the application stack."""
import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import random
import secrets
import select
import shutil
import subprocess
import sys
import time
import urllib.request

import auth_context_lab_source as source
from auth_context_research_runner import WORKER_IMAGE
from auth_context_research_classpath import APP_IMAGE

ROOT = Path(__file__).resolve().parents[2]
RESEARCH_ROOT = Path('/home/quan/.codex/research/model-capability-assessment')
sys.path.insert(0, str(ROOT / 'ueba-worker'))
from app.auth_shadow_contract import validate

SEED = 20261027
QUOTAS = source.QUOTAS
KINDS = ('browse', 'forgot_otp', 'mobile', 'two_devices', 'reset_return',
         'high_traffic', 'transient_4xx', 'browser_update')
MAX_BYTES = 4 * 1024**3
ANCHORS = {s: datetime(2026, 8, 3, tzinfo=timezone.utc) + timedelta(days=21*i)
           for i, s in enumerate(QUOTAS)}


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def put(path, value):
    with path.open('x', encoding='utf-8') as f:
        os.chmod(path, 0o600)
        json.dump(value, f, sort_keys=True, separators=(',', ':'), allow_nan=False)
        f.flush()
        os.fsync(f.fileno())


def available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('STOP_RESOURCE: MemAvailable unavailable')


def budget(output, admission=False):
    if available() < (int(5.5 * 1024**3) if admission else 3 * 1024**3):
        raise RuntimeError('STOP_RESOURCE: insufficient available memory')
    if admission and shutil.disk_usage(output.parent).free < 9 * 1024**3:
        raise RuntimeError('STOP_RESOURCE: insufficient disk space')
    if output.exists() and source.allocated(output) > MAX_BYTES:
        raise RuntimeError('STOP_RESOURCE: artifact quota exceeded')


def classpath_fingerprint(classpath):
    result = []
    for item in classpath.split(os.pathsep):
        path = Path(item).resolve(strict=True)
        if path.is_file():
            result.append({'path': str(path), 'sha256': sha(path)})
        elif path.is_dir():
            entries = [(str(p.relative_to(path)), sha(p)) for p in sorted(path.rglob('*.class')) if p.is_file()]
            if not entries:
                raise ValueError('classpath directory has no class files')
            result.append({'path': str(path), 'classes_sha256': source.digest(entries), 'classes': len(entries)})
        else:
            raise ValueError('classpath item must be a regular file or directory')
    return result


def protocol(classpath):
    return {'format': 'AUTH_CONTEXT_RESEARCH_V2', 'seed': SEED,
            'provenance': 'CONTROLLED_CLOCK_LAB', 'schema': 7, 'features': 81,
            'expected_worker_image': WORKER_IMAGE, 'expected_producer_image': APP_IMAGE,
            'quotas': QUOTAS, 'normal_recipes': KINDS, 'behavior_families': ['case3', 'case4', 'case5'],
            'anchors_utc': {k: source.stamp(v) for k, v in ANCHORS.items()},
            'account_groups_per_split': 256, 'maximum_classifier_fits': 4,
            'recipes': [{'name': 'A', 'max_iter': 100, 'max_leaf_nodes': 15},
                        {'name': 'B', 'max_iter': 200, 'max_leaf_nodes': 31}],
            'seeds': [42, 43], 'maximum_cpus': 2, 'maximum_memory_bytes': 2 * 1024**3,
            'maximum_artifact_bytes': MAX_BYTES, 'classpath': classpath_fingerprint(classpath),
            'generator_sha256': sha(Path(__file__)), 'source_sha256': sha(Path(source.__file__))}


def labels(split, smoke=False):
    normal, behavior, operational = QUOTAS[split]
    if split == 'controls':
        entries = [('cold', 'cold')] * normal + [('missing', 'missing')] * behavior
    else:
        entries = [('routine', KINDS[i % len(KINDS)]) for i in range(normal)]
        entries += [(('case3', 'case4', 'case5')[i % 3], ('case3', 'case4', 'case5')[i % 3]) for i in range(behavior)]
        entries += [('operational', 'operational')] * operational
    random.Random(source.digest([SEED, split, 'ordering', bool(smoke)])).shuffle(entries)
    return entries


def replace_account(value, old, new):
    if isinstance(value, dict):
        return {k: replace_account(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [replace_account(v, old, new) for v in value]
    return new if value == old else value


def frame(split, index, kind, recipe, smoke=False):
    dataset = f'auth-research-v2-{SEED}' + ('-smoke' if smoke else '')
    raw, meta = source.frame(dataset, split, index, kind)
    old = meta['account_group']
    account = 'lab-account-' + source.digest([dataset, split, index % 256])[:24]
    raw = replace_account(raw, old, account)
    meta['account_group'] = account
    meta['recipe'] = recipe
    if kind != 'routine':
        return raw, meta
    # Start from the same observed session without the original random normal scenario.
    context = [e for e in raw['context'] if e['event_type'] in ('HTTP_REQUEST', 'AUTH') and e['action'] in ('READ', 'LOGIN')]
    login = next(e for e in context if e['event_type'] == 'AUTH')
    ip, ua, session = login['source_ip'], login['user_agent_family'], login['session_pseudonym']
    for event in context:
        if event['event_type'] == 'HTTP_REQUEST':
            event.update(source_ip=ip, user_agent_family=ua, session_pseudonym=session)
    raw['attempt'].update(source_ip=ip, user_agent_family=ua)
    if recipe == 'mobile':
        for event in context:
            if event['event_type'] == 'HTTP_REQUEST': event['source_ip'] = '172.26.0.8'
        raw['attempt']['source_ip'] = '172.26.0.8'
    elif recipe == 'two_devices':
        for i, event in enumerate(e for e in context if e['event_type'] == 'HTTP_REQUEST'):
            if i % 2:
                event.update(source_ip='172.26.0.8', user_agent_family='FIREFOX', session_pseudonym=source.digest([meta['episode_id'], 'second']))
    elif recipe == 'browser_update':
        for event in context:
            if event['event_type'] == 'HTTP_REQUEST': event['user_agent_family'] = 'FIREFOX'
        raw['attempt']['user_agent_family'] = 'FIREFOX'
    elif recipe == 'transient_4xx':
        for i, event in enumerate(e for e in context if e['event_type'] == 'HTTP_REQUEST'):
            if i % 3 == 0: event.update(http_status=404, outcome='FAILURE')
    elif recipe == 'high_traffic':
        requests = [e for e in context if e['event_type'] == 'HTTP_REQUEST']
        for i in range(50):
            event = dict(requests[i % len(requests)])
            event['event_id'] = 'event-' + source.digest([meta['episode_id'], 'extra', i])[:40]
            context.append(event)
    elif recipe in ('forgot_otp', 'reset_return'):
        event = dict(login)
        event['event_id'] = 'event-' + source.digest([meta['episode_id'], recipe])[:40]
        if recipe == 'reset_return':
            event.update(event_type='DOMAIN_ACTION', action='PASSWORD_RESET', outcome='SUCCESS', actor_user_id=None, target_user_id=account)
            event.pop('session_pseudonym', None); event.pop('session_issued_at', None)
            at = datetime.fromisoformat(login['event_timestamp'].replace('Z', '+00:00')) - timedelta(seconds=180)
        else:
            event.update(event_type='AUTH_INVESTIGATION', action='OTP_CHECK', outcome='FAILURE', route_group=raw['attempt']['action'], challenge_reference='challenge-' + source.digest([meta['episode_id'], recipe])[:24])
            at = datetime.fromisoformat(raw['attempt']['event_timestamp'].replace('Z', '+00:00')) - timedelta(seconds=40)
        event['event_timestamp'] = source.stamp(at)
        context.append(event)
    raw['context'] = sorted(context, key=lambda e: (e['event_timestamp'], e['event_id']))
    return raw, meta


def check_row(raw, meta, answer):
    if answer.get('before_current_outcome') is not True or answer.get('producer') != 'REAL_JAVA_EXTRACTOR_LOOPBACK_HARNESS':
        raise RuntimeError('producer contract differs')
    if any(e['event_timestamp'] >= raw['attempt']['event_timestamp'] for e in raw['context']):
        raise RuntimeError('future/current context event refused')
    if answer.get('status') != ('UNDETERMINED' if meta['family'] == 'missing' else 'OBSERVED'):
        raise RuntimeError('unexpected coverage')
    if meta['family'] == 'missing':
        if answer.get('snapshot'): raise RuntimeError('missing coverage must not be padded')
    else:
        snapshot = answer['snapshot']
        validate(snapshot, require_ready=meta['family'] != 'cold')
        if snapshot['snapshot_id'] != meta['episode_id'] or (meta['family'] == 'cold' and snapshot['baseline_established']):
            raise RuntimeError('snapshot identity or cold state differs')


def safe_output(output):
    output = output.absolute()
    if '..' in output.parts or RESEARCH_ROOT not in output.parents:
        raise RuntimeError('output must be a fresh directory under the research root')
    for parent in (output, *output.parents):
        if parent.is_symlink(): raise RuntimeError('output paths cannot contain symlinks')
    if output.exists(): raise RuntimeError('output must not already exist')
    if not output.parent.is_dir(): raise RuntimeError('output parent must already exist')
    return output


def producer(classpath, output):
    token = secrets.token_hex(24)
    token_file = output / ('token-' + secrets.token_hex(8) + '.private')
    with token_file.open('x', encoding='utf-8') as f:
        os.chmod(token_file, 0o600)
        f.write(token)
    log = (output / ('java-' + secrets.token_hex(8) + '.private.log')).open('x')
    process = subprocess.Popen(['java', '-Xmx384m', '-XX:ActiveProcessorCount=2', '-cp', classpath,
                                'com.flarefitness.backend.ops.AuthShadowLabCaptureServer', str(token_file)],
                               stdout=subprocess.PIPE, stderr=log, text=True)
    try:
        if not select.select([process.stdout], [], [], 20)[0]: raise RuntimeError('producer startup timeout')
        ready = json.loads(process.stdout.readline())
        return process, log, token_file, token, 'http://127.0.0.1:' + str(ready['port']) + '/capture'
    except BaseException:
        process.terminate(); process.wait(timeout=15); log.close(); token_file.unlink(missing_ok=True)
        raise


def capture(output, classpath, smoke):
    output = safe_output(output)
    budget(output, admission=True)
    proto = protocol(classpath)
    output.mkdir(mode=0o700)
    put(output / 'protocol.json', proto)
    manifest = {'format': 'AUTH_CONTEXT_LAB_SOURCE_V1', 'dataset_id': f'auth-research-v2-{SEED}' + ('-smoke' if smoke else ''),
                'status': 'CAPTURING', 'data_provenance': 'CONTROLLED_CLOCK_LAB', 'source_transport': 'LOOPBACK_FEATURE_HARNESS',
                'feature_schema_version': 7, 'generator_sha256': sha(Path(__file__)), 'protocol_sha256': sha(output / 'protocol.json'), 'splits': {}}
    process = log = token_file = None
    total = 0; started = time.monotonic(); last_budget = 0
    all_accounts = set(); all_sessions = set(); all_episodes = set()
    source.ANCHORS = ANCHORS
    try:
        process, log, token_file, token, url = producer(classpath, output)
        for split in QUOTAS:
            items = labels(split, smoke)
            if smoke: items = items[:smoke]
            numeric = output / (split + '.jsonl.gz'); rawfile = output / (split + '-raw.jsonl.gz')
            counts = Counter(); accounts = set(); sessions = set()
            with gzip.open(numeric, 'xt', encoding='utf-8') as rows, gzip.open(rawfile, 'xt', encoding='utf-8') as raws:
                numeric.chmod(0o600); rawfile.chmod(0o600)
                for index, (kind, recipe) in enumerate(items):
                    now = time.monotonic()
                    if now - started > 5400: raise RuntimeError('capture deadline')
                    if now - last_budget >= 2: budget(output); last_budget = now
                    raw, meta = frame(split, index, kind, recipe, bool(smoke))
                    if meta['episode_id'] in all_episodes or meta['session_group'] in all_sessions:
                        raise RuntimeError('duplicate episode or session')
                    all_episodes.add(meta['episode_id']); all_sessions.add(meta['session_group'])
                    body = json.dumps(raw, separators=(',', ':'), allow_nan=False).encode()
                    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'X-Lab-Token': token}, method='POST')
                    with urllib.request.urlopen(request, timeout=15) as response: answer = json.loads(response.read(65536))
                    check_row(raw, meta, answer)
                    row = meta | {'status': answer['status'], 'snapshot': answer['snapshot'], 'reason': answer['reason'],
                                  'source_event_id': answer['source_event_id'], 'source_sha256': hashlib.sha256(body).hexdigest()}
                    rows.write(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n')
                    raws.write(json.dumps({'episode_id': meta['episode_id'], 'raw': raw}, separators=(',', ':'), allow_nan=False) + '\n')
                    counts[kind] += 1; accounts.add(meta['account_group']); sessions.add(meta['session_group']); total += 1
            if all_accounts & accounts: raise RuntimeError('account groups overlap between splits')
            all_accounts.update(accounts)
            manifest['splits'][split] = {'records': len(items), 'counts': dict(counts), 'file': numeric.name, 'sha256': sha(numeric),
                                         'raw_file': rawfile.name, 'raw_sha256': sha(rawfile), 'account_groups': sorted(accounts),
                                         'session_groups_sha256': source.digest(sorted(sessions))}
        if not smoke and (total != 100000 or any(len(v['account_groups']) < 200 for v in manifest['splits'].values())):
            raise RuntimeError('incomplete quotas or account groups')
        budget(output)
        manifest.update(status='SMOKE_ONLY' if smoke else 'SOURCE_CAPTURE_COMPLETE', records=total,
                        seconds=round(time.monotonic()-started, 2), artifact_bytes=source.allocated(output))
        put(output / 'manifest.json', manifest)
        print(json.dumps({'status': manifest['status'], 'records': total}))
    except BaseException as exc:
        put(output / 'failure.json', {'status': 'STOP_RESOURCE' if 'STOP_RESOURCE' in str(exc) else 'SOURCE_CAPTURE_FAILED', 'records': total, 'reason': str(exc)})
        raise
    finally:
        if process:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
            log.close(); token_file.unlink(missing_ok=True)


def parity(data, classpath, application_jar_sha256):
    # Existing exhaustive producer parity; the external research supervisor enforces
    # the two-second resource monitor and process limits for the entire child tree.
    from auth_context_lab_parity import run
    data = data.absolute()
    if ('..' in data.parts or RESEARCH_ROOT not in data.parents
            or any(p.is_symlink() for p in (data, *data.parents))):
        raise RuntimeError('data must be an isolated research directory without symlinks')
    if (data / 'producer-parity.json').exists() or (data / 'producer-parity.json').is_symlink():
        raise RuntimeError('parity receipt already exists')
    for name in ('parity-token.private', 'parity-java.private.log', 'producer-parity.bound.partial'):
        if (data / name).exists() or (data / name).is_symlink():
            raise RuntimeError('parity temporary path already exists')
    budget(data, admission=True)
    manifest = json.loads((data / 'manifest.json').read_bytes())
    if sha(data / 'protocol.json') != manifest.get('protocol_sha256'): raise RuntimeError('protocol changed')
    if protocol(classpath) != json.loads((data / 'protocol.json').read_bytes()): raise RuntimeError('extractor or generator changed')
    if set(manifest.get('splits', {})) != set(QUOTAS): raise RuntimeError('incomplete corpus splits')
    for split, entry in manifest.get('splits', {}).items():
        if split not in QUOTAS or entry['file'] != split + '.jsonl.gz' or entry['raw_file'] != split + '-raw.jsonl.gz':
            raise RuntimeError('unexpected corpus path')
        for name, key in ((entry['file'], 'sha256'), (entry['raw_file'], 'raw_sha256')):
            path = data / name
            if path.is_symlink() or sha(path) != entry[key]: raise RuntimeError('corpus checksum differs')
    if len(application_jar_sha256) != 64 or any(c not in '0123456789abcdef' for c in application_jar_sha256): raise ValueError('expected lowercase SHA-256')
    if application_jar_sha256 not in [v.get('sha256') for v in classpath_fingerprint(classpath)]: raise RuntimeError('application jar SHA not in classpath')
    try:
        run(data, classpath, application_jar_sha256)
    finally:
        (data / 'parity-java.private.log').unlink(missing_ok=True)
    receipt = data / 'producer-parity.json'
    result = json.loads(receipt.read_bytes())
    # Re-export proves agreement with this pinned harness. Deployment identity
    # requires separate evidence and must never be inferred from a caller SHA.
    result.update(status='HARNESS_REEXPORT_PARITY_PASS',
                  manifest_sha256=sha(data / 'manifest.json'), protocol_sha256=sha(data / 'protocol.json'))
    temp = data / 'producer-parity.bound.partial'
    put(temp, result)
    os.replace(temp, receipt)


def main():
    if os.environ.get('AUTH_RESEARCH_SUPERVISED') != '1':
        raise SystemExit('Use the resource-bounded auth_context_research_runner.py supervisor')
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    c = sub.add_parser('capture'); c.add_argument('--output', type=Path, required=True); c.add_argument('--java-classpath', required=True); c.add_argument('--smoke-per-split', type=int, default=0)
    q = sub.add_parser('parity'); q.add_argument('--data', type=Path, required=True); q.add_argument('--java-classpath', required=True); q.add_argument('--application-jar-sha256', required=True)
    a = p.parse_args()
    if a.command == 'capture':
        if not 0 <= a.smoke_per_split <= 100: p.error('smoke per split must be 0..100')
        capture(a.output, a.java_classpath, a.smoke_per_split)
    else: parity(a.data, a.java_classpath, a.application_jar_sha256)


if __name__ == '__main__': main()
