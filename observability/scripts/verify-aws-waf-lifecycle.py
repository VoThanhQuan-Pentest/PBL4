#!/usr/bin/env python3
"""Low-volume signature approval, three-hit ban and recovery checks on the Terraform-owned Web EIP."""
import argparse
from datetime import datetime, timezone
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
AUTO_SIGNATURE_BLOCK_REASON = 'Three or more approved signature matches in one minute'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def all_ip_blocks(client):
    rows = []
    for page_number in range(10000):
        page = client.request('GET', f'/api/siem/ip-blocks?size=100&page={page_number}')
        rows.extend(page.get('content', []))
        if not page.get('has_next'):
            return rows
    raise RuntimeError('IP block list exceeded the safety pagination limit')


def current_block(row):
    if row.get('revoked_at'):
        return False
    try:
        expires = datetime.fromisoformat(row['expires_at'])
    except (KeyError, TypeError, ValueError):
        return False
    if expires.tzinfo is not None:
        expires = expires.astimezone(timezone.utc).replace(tzinfo=None)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return expires > now


def latest_signature(client, signature_id):
    for page_number in range(100):
        page = client.request('GET', f'/api/siem/signatures?size=100&page={page_number}')
        for row in page.get('content', []):
            if row.get('id') == signature_id:
                return row
        if not page.get('has_next'):
            break
    raise RuntimeError('Temporary test signature disappeared before cleanup')


def wait_signature_state(client, signature_id, expected, attempts=30):
    for _ in range(attempts):
        item = latest_signature(client, signature_id)
        if item['status'] == expected:
            return item
        time.sleep(1)
    raise RuntimeError(f'Gateway did not ACK the expected signature state: {expected}')


def cleanup_artifacts(client, authenticated_clients, source_ip, baseline_block_ids, signature_id):
    """Best-effort cleanup that only revokes this run's newly-created auto block."""
    errors = []
    if client in authenticated_clients and source_ip and baseline_block_ids is not None:
        try:
            for block in all_ip_blocks(client):
                if (block.get('id') not in baseline_block_ids
                        and block.get('ip_address') == source_ip
                        and block.get('source_type') == 'SIGNATURE'
                        and block.get('reason') == AUTO_SIGNATURE_BLOCK_REASON
                        and current_block(block)):
                    client.request('POST',
                                   f"/api/siem/ip-blocks/{block['id']}/revoke?version={block['version']}", {})
        except Exception as error:  # Keep attempting signature and session cleanup if this API call fails.
            errors.append(f'IP-block cleanup failed ({type(error).__name__})')

    if client in authenticated_clients and signature_id:
        try:
            item = latest_signature(client, signature_id)
            if item['status'] != 'DISABLED':
                client.request('POST',
                               f"/api/siem/signatures/{signature_id}/disable?version={item['version']}", {})
                wait_signature_state(client, signature_id, 'DISABLED')
        except Exception as error:
            errors.append(f'Temporary signature cleanup failed ({type(error).__name__})')

    for authenticated in reversed(authenticated_clients):
        try:
            authenticated.request('POST', '/api/auth/logout', {})
        except Exception as error:
            errors.append(f'Session logout failed ({type(error).__name__})')
    return errors


def write_private_json(path, value):
    os.umask(0o077)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def validate_private_credentials(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Credentials must be a regular private file')
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError('Credentials must be owned by this user and inaccessible to group/others')
    state = json.loads(path.read_text())
    for role in ('l1', 'l2'):
        if not all(state.get('accounts', {}).get(role, {}).get(key) for key in ('username', 'password')):
            raise ValueError(f'Missing private {role.upper()} operator credentials')
    return state


def run_workflow(l1, l2, target, source_ip, signature_created):
    path = '/__flare_515_signature_probe_' + str(time.time_ns())
    opener = urllib.request.build_opener(soc.NoRedirect())
    probes = []

    def probe(relative, phase):
        trace = ''
        try:
            with opener.open(target + relative, timeout=10) as response:
                status = response.status
                trace = response.headers.get('X-Request-ID', '')
                response.read(4096)
        except urllib.error.HTTPError as error:
            status = error.code
            trace = error.headers.get('X-Request-ID', '')
            error.close()
        probes.append(dict(phase=phase, status=status, trace_id=trace,
                           observed_at=datetime.now(timezone.utc).isoformat()))
        return status

    signature = l1.request('POST', '/api/siem/signatures',
        dict(kind='PATH_EXACT', http_method='GET', match_value=path, severity='HIGH'))
    signature_id = signature['id']
    signature_created(signature_id)

    def latest():
        return latest_signature(l2, signature_id)

    def wait_state(status):
        return wait_signature_state(l2, signature_id, status)

    require(signature['status'] == 'DRAFT' and probe(path, 'DRAFT') == 200,
            'Draft must not block the canary')
    tested = l2.request('POST',
        f"/api/siem/signatures/{signature_id}/test-default?version={signature['version']}", {})
    require(tested['passed'] and latest()['status'] == 'TESTED'
            and probe(path, 'TESTED_NOT_APPROVED') == 200,
            'Testing must not activate the signature')
    item = latest()
    try:
        l1.request('POST', f"/api/siem/signatures/{signature_id}/activate?version={item['version']}", {})
    except urllib.error.HTTPError as error:
        require(error.code == 403, 'L1 activation must return 403')
        error.close()
    else:
        raise RuntimeError('L1 approval unexpectedly succeeded')
    l2.request('POST', f"/api/siem/signatures/{signature_id}/activate?version={item['version']}", {})
    wait_state('ACTIVE')
    first_hit = time.monotonic()
    for index in range(3):
        require(probe(path, f'ACTIVE_MATCH_{index + 1}') == 403,
                'Active signature must deny each match')
    require(time.monotonic() - first_hit < 60,
            'Three hits must be within the configured window')
    require(probe('/api/health', 'NORMAL_REQUEST_WHILE_BANNED') == 403,
            'IP ban must deny normal traffic')

    block = None
    for _ in range(30):
        block = next((row for row in all_ip_blocks(l2)
                      if row['ip_address'] == source_ip
                      and row['source_type'] == 'SIGNATURE'
                      and row['reason'] == AUTO_SIGNATURE_BLOCK_REASON
                      and not row.get('revoked_at')), None)
        if block:
            break
        time.sleep(1)
    require(block is not None, 'Signature ban must be persisted')
    duration = (datetime.fromisoformat(block['expires_at'])
                - datetime.fromisoformat(block['started_at'])).total_seconds()
    require(duration == 900, 'Signature ban duration must be 15 minutes')
    l2.request('POST', f"/api/siem/ip-blocks/{block['id']}/revoke?version={block['version']}", {})
    for _ in range(30):
        if probe('/api/health', 'RECOVERY_AFTER_REVOKE') == 200:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Recovery did not restore normal traffic')
    item = latest()
    l2.request('POST', f"/api/siem/signatures/{signature_id}/disable?version={item['version']}", {})
    wait_state('DISABLED')
    require(probe(path, 'DISABLED') == 200, 'Disabled canary must pass')
    return dict(passed=True, environment='AWS', signature_id=signature_id, source_ip=source_ip,
                ban_seconds=duration, l1_approval_denied=True, recovery_succeeded=True,
                canary_final_status='DISABLED', probes=probes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    credentials_path = args.credentials.absolute()
    state = validate_private_credentials(credentials_path)
    runtime = (ROOT / 'observability/runtime').resolve()
    if args.output.name in ('', '.', '..'):
        raise ValueError('Evidence output must name a new file')
    output = args.output.parent.resolve() / args.output.name
    if (not output.is_relative_to(runtime) or output.exists() or output.is_symlink()):
        raise ValueError('Evidence output must be a new file under observability/runtime')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_stat = output.parent.stat()
    if parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077:
        raise ValueError('Evidence directory must be owned and accessible only by this user')
    lock_path = output.parent / '.verify-aws-waf-lifecycle.lock'
    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    lock_stream = os.fdopen(lock_descriptor, 'r+')
    try:
        fcntl.flock(lock_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock_stream.close()
        raise RuntimeError('Another WAF lifecycle verification is active') from error

    outputs = json.loads(subprocess.check_output(
        ['terraform', '-chdir=terraform', 'output', '-json'], cwd=ROOT))
    web_ip = ipaddress.IPv4Address(outputs['web_elastic_ip']['value'])
    require(web_ip.is_global, 'Terraform Web EIP must be public')
    target = 'http://' + str(web_ip)
    global soc
    spec = importlib.util.spec_from_file_location('soc', ROOT / 'observability/scripts/aws-soc.py')
    soc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(soc)

    clients = {role: soc.Client('http://127.0.0.1:18089') for role in ('l1', 'l2')}
    authenticated = []
    source_ip = None
    baseline_block_ids = None
    signature_id = []
    result = None
    failure = None
    try:
        for role in ('l1', 'l2'):
            clients[role].login(state['accounts'][role])
            authenticated.append(clients[role])
        l1, l2 = clients['l1'], clients['l2']
        with urllib.request.urlopen('https://checkip.amazonaws.com', timeout=5) as response:
            source_ip = str(ipaddress.IPv4Address(response.read(64).decode().strip()))
        require(ipaddress.IPv4Address(source_ip).is_global, 'Public operator IP required')
        baseline_blocks = all_ip_blocks(l2)
        require(not any(row.get('ip_address') == source_ip and current_block(row)
                        for row in baseline_blocks),
                'Operator IP already has an active block; refusing to run the lifecycle test')
        baseline_block_ids = {row.get('id') for row in baseline_blocks}
        result = run_workflow(l1, l2, target, source_ip, signature_id.append)
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors = cleanup_artifacts(clients.get('l2'), authenticated, source_ip,
                                           baseline_block_ids,
                                           signature_id[0] if signature_id else None)

    if failure is not None:
        if cleanup_errors:
            print('; '.join(cleanup_errors), file=sys.stderr)
        raise failure
    if cleanup_errors:
        raise RuntimeError('; '.join(cleanup_errors))
    write_private_json(output, result)
    print(json.dumps({'passed': True, 'environment': 'AWS',
                      'probe_count': len(result['probes']),
                      'l1_approval_denied': result['l1_approval_denied'],
                      'recovery_succeeded': result['recovery_succeeded'],
                      'canary_final_status': result['canary_final_status']}))


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        error.close()
        raise SystemExit(f'API returned HTTP {error.code}; body intentionally omitted')
