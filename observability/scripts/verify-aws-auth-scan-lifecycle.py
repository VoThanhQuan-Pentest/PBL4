#!/usr/bin/env python3
"""Low-volume AWS test for failed-login enrichment and two-minute endpoint-scan blocking.

The test uses only a synthetic nonexistent username and 50 unique static-file
404s across two adjacent minute buckets. It refuses an already-blocked source
IP and revokes only new, known automatic blocks caused during this run.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import http.cookiejar
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
SCAN_BLOCK_REASON = 'Endpoint enumeration repeated in separate minute windows'
REPUTATION_SCAN_REASON = 'Endpoint scan corroborated by recent independent abuse reports'
SIGNATURE_BLOCK_REASON = 'Three or more approved signature matches in one minute'
AUTO_BLOCK_REASONS = {
    ('SCAN', SCAN_BLOCK_REASON),
    ('SCAN', REPUTATION_SCAN_REASON),
    ('SIGNATURE', SIGNATURE_BLOCK_REASON),
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def current_block(row):
    if row.get('revoked_at'):
        return False
    try:
        expiry = datetime.fromisoformat(row['expires_at'])
    except (KeyError, TypeError, ValueError):
        return False
    if expiry.tzinfo is not None:
        expiry = expiry.astimezone(timezone.utc).replace(tzinfo=None)
    return expiry > datetime.now(timezone.utc).replace(tzinfo=None)


def all_ip_blocks(client):
    rows = []
    for page_number in range(10000):
        page = client.request('GET', f'/api/siem/ip-blocks?size=100&page={page_number}')
        rows.extend(page.get('content', []))
        if not page.get('has_next'):
            return rows
    raise RuntimeError('IP block list exceeded the safety pagination limit')


def new_test_blocks(rows, source_ip, baseline_ids):
    return [row for row in rows if row.get('id') not in baseline_ids
            and row.get('ip_address') == source_ip
            and (row.get('source_type'), row.get('reason')) in AUTO_BLOCK_REASONS
            and current_block(row)]


def cleanup_test_blocks(client, authenticated_clients, source_ip, baseline_ids):
    """Revoke only new scan/signature blocks with the exact known lab reasons."""
    errors = []
    revoked = []
    if client in authenticated_clients and source_ip and baseline_ids is not None:
        try:
            for block in new_test_blocks(all_ip_blocks(client), source_ip, baseline_ids):
                client.request('POST',
                               f"/api/siem/ip-blocks/{block['id']}/revoke?version={block['version']}", {})
                revoked.append(block['id'])
        except Exception as error:
            errors.append(f'IP-block cleanup failed ({type(error).__name__})')
    return revoked, errors


def logout_clients(authenticated_clients):
    errors = []
    for authenticated in reversed(authenticated_clients):
        try:
            authenticated.request('POST', '/api/auth/logout', {})
        except Exception as error:
            errors.append(f'Session logout failed ({type(error).__name__})')
    return errors


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class PublicWebProbe:
    def __init__(self, origin):
        self.origin = origin.rstrip('/')
        cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(cookies))

    def request(self, method, path, *, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        request_headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) FlareLabOwnedTest/1.0'}
        request_headers.update(headers or {})
        if body is not None:
            request_headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.origin + path, data=data,
                                         headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=8) as response:
                response.read(4096)
                return response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            return status

    def failed_login(self, username, password):
        with self.opener.open(self.origin + '/api/auth/csrf', timeout=8) as response:
            token = json.loads(response.read(4096)).get('token')
        require(isinstance(token, str) and token, 'CSRF token was not returned')
        return self.request('POST', '/api/auth/login',
                            body={'username': username, 'password': password},
                            headers={'X-XSRF-TOKEN': token})


def wait_public_status(public, path, expected, attempts=30):
    observed = None
    for _ in range(attempts):
        try:
            observed = public.request('GET', path)
        except (OSError, urllib.error.URLError):
            observed = None
        if observed == expected:
            return observed
        time.sleep(1)
    raise RuntimeError(f'Public endpoint did not converge to HTTP {expected}')


def wait_until(timestamp):
    while True:
        remaining = (timestamp - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def next_minute_probe_start(now=None):
    now = now or datetime.now(timezone.utc)
    minute = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    return minute + timedelta(seconds=5)


def next_adjacent_minute_probe_start(first_start):
    return first_start + timedelta(minutes=1, seconds=25)


def reputation_can_block_one_scan(rows):
    return any(row.get('provider') == 'ABUSEIPDB' and row.get('status') == 'FRESH'
               and row.get('data_provenance') == 'REAL'
               and (row.get('abuse_score') or 0) >= 80
               and (row.get('total_reports') or 0) >= 3
               and (row.get('distinct_reporters') or 0) >= 2 for row in rows)


def query_web_db(ssh_host, sql):
    command = [
        'ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=8', ssh_host,
        "cd /opt/flare && observability/scripts/aws-compose.sh web exec -T db sh -ceu 'MYSQL_PWD=\"$MYSQL_PASSWORD\" exec mysql -Ns -u \"$MYSQL_USER\" \"$MYSQL_DATABASE\"'",
    ]
    try:
        result = subprocess.run(command, input=sql, capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError('Read-only AWS telemetry query failed; SQL output omitted') from None
    if result.returncode:
        raise RuntimeError('Read-only AWS telemetry query failed; SQL output omitted')
    return result.stdout.strip().splitlines()


def telemetry_counts(ssh_host, source_ip, since):
    # source_ip is canonical IPv4 and since is generated by this process.
    query = f"""
SELECT 'auth_failures',COUNT(*) FROM siem_security_events
 WHERE source_ip='{source_ip}' AND event_type='AUTH' AND outcome='FAILURE'
 AND event_timestamp>='{since}';
SELECT 'failed_login_lookups',COUNT(*) FROM siem_ip_lookup_requests
 WHERE ip_address='{source_ip}' AND reason='FAILED_LOGIN_BURST'
 AND requested_at>='{since}';
SELECT 'failed_login_lookup_done',COUNT(*) FROM siem_ip_lookup_requests
 WHERE ip_address='{source_ip}' AND reason='FAILED_LOGIN_BURST' AND status='DONE'
 AND requested_at>='{since}';
SELECT 'scan_signals',COUNT(*) FROM siem_prevention_events
 WHERE ip_address='{source_ip}' AND event_type='SCAN_SIGNAL'
 AND occurred_at>='{since}';
SELECT 'provider_attempts',COUNT(*) FROM siem_ip_provider_attempts
 WHERE ip_address='{source_ip}' AND attempted_at>='{since}';
"""
    rows = query_web_db(ssh_host, query)
    result = {}
    for line in rows:
        fields = line.split('\t')
        if len(fields) == 2 and fields[1].isdigit():
            result[fields[0]] = int(fields[1])
    if set(result) != {'auth_failures', 'failed_login_lookups', 'failed_login_lookup_done',
                       'scan_signals', 'provider_attempts'}:
        raise RuntimeError('Read-only AWS telemetry query returned an incomplete result')
    return result


def lookup_job_status(ssh_host, request_id):
    if not isinstance(request_id, str) or re.fullmatch(r'[A-Za-z0-9-]{1,64}', request_id) is None:
        raise RuntimeError('Lookup request identifier was invalid')
    rows = query_web_db(ssh_host,
        f"SELECT status FROM siem_ip_lookup_requests WHERE id='{request_id}';")
    return rows[0] if len(rows) == 1 else None


def provider_rows_ready(rows):
    return {row.get('provider') for row in rows
            if row.get('status') == 'FRESH' and row.get('data_provenance') == 'REAL'} == {'IPINFO', 'ABUSEIPDB'}


def provider_observation_map(rows):
    return {row.get('provider'): row.get('observed_at') for row in rows
            if row.get('status') == 'FRESH' and row.get('data_provenance') == 'REAL'
            and row.get('provider') in ('IPINFO', 'ABUSEIPDB')}


def private_credentials(path):
    if (any(part.is_symlink() for part in (path, *path.parents))
            or not path.is_file()):
        raise ValueError('Credentials must be a regular private file')
    metadata = path.stat()
    if (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077
            or metadata.st_nlink != 1 or metadata.st_size > 1024 * 1024):
        raise ValueError('Credentials must be owned by this user and inaccessible to group/others')
    state = json.loads(path.read_text())
    for key in ('l2',):
        if not all(state.get('accounts', {}).get(key, {}).get(field) for field in ('username', 'password')):
            raise ValueError(f'Missing private {key.upper()} operator credentials')
    return state


def write_private_json(path, value):
    os.umask(0o077)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError('Evidence directory must be owned and accessible only by this user')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    state = private_credentials(args.credentials.absolute())
    output = args.output.parent.resolve() / args.output.name
    runtime = (ROOT / 'observability/runtime').resolve()
    if (not output.is_relative_to(runtime) or output.exists() or output.is_symlink()
            or args.output.name in ('', '.', '..')):
        raise ValueError('Evidence output must be a new file under observability/runtime')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = output.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError('Evidence directory must be owned and accessible only by this user')
    lock_path = output.parent / '.verify-aws-auth-scan-lifecycle.lock'
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    lock_stat = os.fstat(descriptor)
    if (not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.getuid()
            or lock_stat.st_mode & 0o077 or lock_stat.st_nlink != 1):
        os.close(descriptor)
        raise RuntimeError('Test lock file must be private and owned by this user')
    lock = os.fdopen(descriptor, 'r+')
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        lock.close()
        raise RuntimeError('Another AWS auth/scan lifecycle test is active') from error

    terraform = json.loads(subprocess.check_output(
        ['terraform', '-chdir=terraform', 'output', '-json'], cwd=ROOT))
    web_ip = str(ipaddress.IPv4Address(terraform['web_elastic_ip']['value']))
    ssh_command = terraform['ssh_web_command']['value'].split()
    require(len(ssh_command) >= 2 and ssh_command[0] == 'ssh', 'Terraform Web SSH output is invalid')
    ssh_host = ssh_command[-1]
    require(re.fullmatch(r'[A-Za-z0-9._-]+@[0-9.]+', ssh_host) is not None,
            'Terraform Web SSH host must be an explicit user@IPv4')
    spec = importlib.util.spec_from_file_location('aws_soc', ROOT / 'observability/scripts/aws-soc.py')
    soc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(soc)
    l2 = soc.Client('http://127.0.0.1:18089')
    authenticated = []
    source_ip = None
    baseline_ids = None
    result = None
    failure = None
    try:
        l2.login(state['accounts']['l2'])
        authenticated.append(l2)
        with urllib.request.urlopen('https://checkip.amazonaws.com', timeout=5) as response:
            source_ip = str(ipaddress.IPv4Address(response.read(64).decode().strip()))
        require(ipaddress.IPv4Address(source_ip).is_global, 'Public operator IP required')
        target = 'http://' + web_ip
        public = PublicWebProbe(target)
        require(public.request('GET', '/api/health') == 200, 'AWS Web health must be available before the test')
        baseline_rows = all_ip_blocks(l2)
        require(not any(row.get('ip_address') == source_ip and current_block(row) for row in baseline_rows),
                'Operator IP already has an active block; refusing to run')
        baseline_ids = {row.get('id') for row in baseline_rows}
        started = datetime.now(timezone.utc).replace(microsecond=0)
        started_sql = started.strftime('%Y-%m-%d %H:%M:%S')
        recent_lookup = query_web_db(ssh_host,
            f"SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address='{source_ip}' "
            "AND requested_at>UTC_TIMESTAMP()-INTERVAL 5 MINUTE;")
        require(recent_lookup == ['0'],
                'A recent provider lookup would deduplicate the FAILED_LOGIN_BURST trigger; wait and retry later')
        recent_scans = query_web_db(ssh_host,
            f"SELECT COUNT(*) FROM siem_prevention_events WHERE ip_address='{source_ip}' "
            "AND event_type='SCAN_SIGNAL' AND occurred_at>UTC_TIMESTAMP()-INTERVAL 3 MINUTE;")
        require(recent_scans == ['0'],
                'A recent scan signal would confound the two-window acceptance; wait and retry later')
        intelligence_before = l2.request('GET', f'/api/siem/ip-intelligence?ip={source_ip}')
        provider_can_corroborate_one_scan = reputation_can_block_one_scan(intelligence_before)

        username = 'aws_lab_missing_' + uuid.uuid4().hex[:10]
        password = 'NotARealAccount-' + uuid.uuid4().hex
        login_statuses = []
        for _ in range(6):
            login_statuses.append(public.failed_login(username, password))
            time.sleep(4)
        require(all(status in (401, 429) for status in login_statuses),
                'Unexpected response during synthetic failed-login sequence')
        require(sum(status == 401 for status in login_statuses) >= 5,
                'At least five explicit invalid-credential responses are required')

        auth_state = None
        provider_rows = []
        for _ in range(30):
            auth_state = telemetry_counts(ssh_host, source_ip, started_sql)
            provider_rows = l2.request('GET', f'/api/siem/ip-intelligence?ip={source_ip}')
            ready_providers = {row['provider'] for row in provider_rows
                               if row.get('status') == 'FRESH' and row.get('data_provenance') == 'REAL'}
            if (auth_state['auth_failures'] >= 5 and auth_state['failed_login_lookups'] >= 1
                    and auth_state['failed_login_lookup_done'] >= 1
                    and ready_providers == {'IPINFO', 'ABUSEIPDB'}):
                break
            time.sleep(2)
        require(auth_state['auth_failures'] >= 5 and auth_state['failed_login_lookups'] >= 1
                and auth_state['failed_login_lookup_done'] >= 1,
                'Five failed logins did not complete the expected lookup job')
        ready_providers = {row['provider'] for row in provider_rows
                           if row.get('status') == 'FRESH' and row.get('data_provenance') == 'REAL'}
        require(ready_providers == {'IPINFO', 'ABUSEIPDB'},
                'Both IP reputation providers must return FRESH/REAL for the operator IP')
        require(not any(row.get('ip_address') == source_ip and current_block(row)
                        for row in all_ip_blocks(l2)),
                'Failed logins alone unexpectedly created an IP block')
        intelligence_after = l2.request('GET', f'/api/siem/ip-intelligence?ip={source_ip}')
        provider_can_corroborate_one_scan = (provider_can_corroborate_one_scan
                                              or reputation_can_block_one_scan(intelligence_after))
        require(not provider_can_corroborate_one_scan,
                'Current FRESH AbuseIPDB data could block a single scan window; refusing a confounded two-window test')

        first_start = next_minute_probe_start()
        second_start = next_adjacent_minute_probe_start(first_start)
        scan_times = []
        scan_statuses = []
        early_scan_blocks = []
        nonce = uuid.uuid4().hex[:12]

        def clear_early_blocks():
            early = new_test_blocks(all_ip_blocks(l2), source_ip, baseline_ids)
            if not early:
                return
            revoked_early, errors = cleanup_test_blocks(l2, authenticated, source_ip, baseline_ids)
            require(not errors, '; '.join(errors))
            require({row['id'] for row in early}.issubset(set(revoked_early)),
                    'An early scan block could not be revoked before the next test window')
            early_scan_blocks.extend(row['reason'] for row in early)
            wait_public_status(public, '/api/health', 200)

        for window_index in range(2):
            window_start = first_start if window_index == 0 else second_start
            wait_until(window_start)
            if window_index == 1:
                clear_early_blocks()
            scan_times.append(window_start.isoformat())
            window_end = window_start.replace(second=0, microsecond=0) + timedelta(minutes=1)
            for request_index in range(25):
                require(datetime.now(timezone.utc) < window_end,
                        'Endpoint-scan probes would spill into a different minute window')
                path = f'/assets/aws515-scan-{nonce}-{window_index}-{request_index}.css'
                status = public.request('GET', path)
                require(datetime.now(timezone.utc) < window_end,
                        'Endpoint-scan response completed outside its assigned minute window')
                scan_statuses.append(status)
                require(status == 404, 'Owned missing-asset probe did not return HTTP 404')
            if window_index == 0:
                wait_seconds = max(1, (second_start - datetime.now(timezone.utc)).total_seconds() - 5)
                deadline = time.monotonic() + wait_seconds
                first_signal_seen = False
                while time.monotonic() < deadline:
                    current = telemetry_counts(ssh_host, source_ip, started_sql)
                    clear_early_blocks()
                    if current['scan_signals'] >= 1:
                        first_signal_seen = True
                        break
                    time.sleep(2)
                require(first_signal_seen,
                        'First endpoint-scan signal was not persisted before the adjacent minute window')

        scan_block = None
        for _ in range(45):
            scan_block = next((row for row in new_test_blocks(all_ip_blocks(l2), source_ip, baseline_ids)
                               if row.get('source_type') == 'SCAN'
                               and row.get('reason') == SCAN_BLOCK_REASON), None)
            if scan_block:
                break
            time.sleep(2)
        require(scan_block is not None, 'Two adjacent endpoint-scan windows did not create the expected temporary block')
        scan_state = telemetry_counts(ssh_host, source_ip, started_sql)
        require(scan_state['scan_signals'] >= 2, 'Both scan windows were not persisted as distinct signals')
        duration = (datetime.fromisoformat(scan_block['expires_at'])
                    - datetime.fromisoformat(scan_block['started_at'])).total_seconds()
        require(duration == 600, 'Endpoint-scan block duration must be 10 minutes')
        blocked_health = wait_public_status(public, '/api/health', 403)

        revoked, cleanup_errors = cleanup_test_blocks(l2, authenticated, source_ip, baseline_ids)
        require(not cleanup_errors, '; '.join(cleanup_errors))
        require(scan_block['id'] in revoked, 'Test scan block was not revoked by cleanup')
        recovered = wait_public_status(public, '/api/health', 200)
        final_state = telemetry_counts(ssh_host, source_ip, started_sql)
        require(not new_test_blocks(all_ip_blocks(l2), source_ip, baseline_ids),
                'A new test automatic block remains active after cleanup')

        cache_provider_rows = l2.request('GET', f'/api/siem/ip-intelligence?ip={source_ip}')
        cache_observations_before = provider_observation_map(cache_provider_rows)
        require(set(cache_observations_before) == {'IPINFO', 'ABUSEIPDB'},
                'Both providers must have fresh real cache entries before cache acceptance')
        cache_check_time = started + timedelta(minutes=6)
        for row in cache_provider_rows:
            expiry = datetime.fromisoformat(row['expires_at'])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            require(expiry > cache_check_time + timedelta(seconds=10),
                    'Provider cache expires before the bounded cache-reuse check')
        wait_until(cache_check_time)
        cache_recent_lookup = query_web_db(ssh_host,
            f"SELECT COUNT(*) FROM siem_ip_lookup_requests WHERE ip_address='{source_ip}' "
            "AND requested_at>UTC_TIMESTAMP()-INTERVAL 5 MINUTE;")
        require(cache_recent_lookup == ['0'],
                'A recent lookup would deduplicate the independent provider-cache check')
        attempts_before_cache = telemetry_counts(ssh_host, source_ip, started_sql)['provider_attempts']
        cache_request = l2.request('POST',
            f'/api/siem/ip-intelligence/lookup?ip={source_ip}&reason=AWS_CACHE_VERIFY', {})
        cache_request_id = cache_request.get('request_id')
        duplicate_request = l2.request('POST',
            f'/api/siem/ip-intelligence/lookup?ip={source_ip}&reason=AWS_CACHE_VERIFY', {})
        require(cache_request_id and duplicate_request.get('request_id') == cache_request_id,
                'Duplicate lookup did not reuse the queued request')
        cache_job_status = None
        for _ in range(30):
            cache_job_status = lookup_job_status(ssh_host, cache_request_id)
            if cache_job_status == 'DONE':
                break
            time.sleep(2)
        require(cache_job_status == 'DONE', 'Cache lookup job did not finish')
        cache_rows_after = l2.request('GET', f'/api/siem/ip-intelligence?ip={source_ip}')
        cache_observations_after = provider_observation_map(cache_rows_after)
        attempts_after_cache = telemetry_counts(ssh_host, source_ip, started_sql)['provider_attempts']
        cache_reused = (cache_observations_after == cache_observations_before
                        and attempts_after_cache == attempts_before_cache)
        require(cache_reused, 'Fresh IP reputation lookup did not reuse both provider cache entries')
        result = {
            'passed': True,
            'environment': 'AWS',
            'data_provenance': 'REAL_SOURCE_IP_SYNTHETIC_REQUESTS',
            'source_ip': source_ip,
            'failed_login_statuses': login_statuses,
            'auth_failure_events': final_state['auth_failures'],
            'failed_login_lookup_requests': final_state['failed_login_lookups'],
            'failed_login_lookup_done': final_state['failed_login_lookup_done'],
            'provider_results': [{key: row.get(key) for key in
                                  ('provider', 'status', 'data_provenance', 'observed_at')}
                                 for row in provider_rows],
            'provider_corroboration_may_block_single_scan': provider_can_corroborate_one_scan,
            'early_scan_blocks_revoked': early_scan_blocks,
            'provider_cache_reused': cache_reused,
            'provider_attempts_during_cache_check': attempts_after_cache - attempts_before_cache,
            'duplicate_lookup_request_reused': True,
            'cache_check_completed_at_utc': datetime.now(timezone.utc).isoformat(),
            'active_block_after_login_only': False,
            'scan_window_starts_utc': scan_times,
            'scan_requests_per_window': 25,
            'scan_statuses': scan_statuses,
            'persisted_scan_signals': final_state['scan_signals'],
            'scan_block_seconds': duration,
            'blocked_health_status': blocked_health,
            'block_revoked': True,
            'recovery_health_status': recovered,
            'active_test_blocks_after_cleanup': 0,
        }
    except BaseException as error:
        failure = error
    finally:
        revoked, cleanup_errors = cleanup_test_blocks(l2, authenticated, source_ip, baseline_ids)
        cleanup_errors.extend(logout_clients(authenticated))
    if failure is not None:
        if cleanup_errors:
            print('; '.join(cleanup_errors), file=sys.stderr)
        raise failure
    if cleanup_errors:
        raise RuntimeError('; '.join(cleanup_errors))
    write_private_json(output, result)
    print(json.dumps({key: result[key] for key in
                      ('passed', 'environment', 'auth_failure_events', 'failed_login_lookup_requests',
                       'failed_login_lookup_done',
                       'active_block_after_login_only', 'persisted_scan_signals', 'scan_block_seconds',
                       'block_revoked', 'recovery_health_status', 'provider_cache_reused',
                       'duplicate_lookup_request_reused')}))


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        error.close()
        raise SystemExit(f'API returned HTTP {error.code}; response body omitted')
    except (ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit('AWS auth/scan verification failed: ' + type(error).__name__ + '; sensitive data omitted') from None
