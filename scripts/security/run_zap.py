#!/usr/bin/env python3
"""Bounded CI-only DAST; detailed alerts are encrypted before artifact upload."""
import http.cookiejar
import json
import os
import re
from pathlib import Path
import secrets
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from ci_scope import require_ci_scope

IMAGE = 'ghcr.io/zaproxy/zaproxy:stable@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'
BASE = 'https://app.soc.test:8443'
# Control stays inside the scanner namespace: internal networks deliberately do not publish host ports.
CONTROL_SCRIPT = """
import json, sys, urllib.parse, urllib.request
try:
    data = json.load(sys.stdin)
    url = 'http://127.0.0.1:8080/JSON/' + data['component'] + '/' + data['action'] + '/?'
    url += urllib.parse.urlencode(data['parameters'])
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with client.open(url, timeout=15) as response:
        body = response.read(8*1024*1024+1)
    if len(body) > 8*1024*1024: raise ValueError('Response bound exceeded')
    print(json.dumps(json.loads(body)))
except Exception:
    sys.exit('Scanner control request failed; details withheld')
"""


def bounded_json(client, url, *, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with client.open(request, timeout=15) as response:
            body = response.read(8 * 1024 * 1024 + 1)
    except Exception:
        raise RuntimeError('ASVS HTTP control/probe failed; details withheld to protect session data') from None
    if len(body) > 8 * 1024 * 1024:
        raise RuntimeError('ASVS response exceeded its bound')
    return json.loads(body)


def login(username, password):
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), urllib.request.HTTPCookieProcessor(jar))
    mailbox = 'http://127.0.0.1:8025'
    before = {m['ID'] for m in bounded_json(client, mailbox + '/api/v1/messages')['messages']}
    csrf = bounded_json(client, BASE + '/api/auth/csrf')['token']
    # Browser checks may have just logged in as this same synthetic user.
    # Keep the real account cooldown, and wait rather than weakening policy.
    time.sleep(61)
    challenge = bounded_json(client, BASE + '/api/auth/login', data=json.dumps({'username': username, 'password': password}).encode(),
                 headers={'Content-Type': 'application/json', 'X-XSRF-TOKEN': csrf})
    if not challenge.get('challenge_id'): raise RuntimeError('DAST requires OTP-enabled login')
    expected_mail = {'e2e_customer': 'customer.e2e@flarefitness.test', 'e2e_admin': 'admin.e2e@flarefitness.test'}[username]
    code = None
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        messages = bounded_json(client, mailbox + '/api/v1/messages')['messages']
        message = next((m for m in messages if m['ID'] not in before and m['Subject'] == 'Flare - OTP dang nhap'
                        and any(to['Address'] == expected_mail for to in m['To'])), None)
        if message:
            detail = bounded_json(client, mailbox + '/api/v1/message/' + message['ID'])
            match = re.search(r'\b[0-9]{6}\b', detail['Text'])
            if match: code = match.group(); break
        time.sleep(1)
    if code is None: raise RuntimeError('Synthetic OTP was not delivered in time')
    bounded_json(client, BASE + '/api/auth/login/otp',
        data=json.dumps({'challenge_id': challenge['challenge_id'], 'otp_code': code}).encode(),
        headers={'Content-Type': 'application/json', 'X-XSRF-TOKEN': csrf})
    csrf = bounded_json(client, BASE + '/api/auth/csrf')['token']
    if bounded_json(client, BASE + '/api/auth/me')['username'] != username:
        raise RuntimeError('DAST authentication did not identify its synthetic account')
    return '; '.join(c.name + '=' + c.value for c in jar), csrf


def encrypt(source, destination, certificate):
    result = subprocess.run(['openssl', 'cms', '-encrypt', '-aes-256-gcm', '-binary', '-outform', 'DER',
        '-in', str(source), '-out', str(destination), str(certificate)], capture_output=True)
    if result.returncode:
        raise RuntimeError('Private evidence encryption failed; raw evidence will not be uploaded')


def main():
    project, root = require_ci_scope()
    output = Path(os.environ['RUNNER_TEMP'])/'asvs-results'
    output.mkdir(mode=0o700, exist_ok=True)
    api_key = secrets.token_hex(32)
    name = project + '-zap'
    network = project + '_asvs-scanner'
    def api(component, action, **parameters):
        payload = json.dumps({'component': component, 'action': action,
                              'parameters': {'apikey': api_key, **parameters}}).encode()
        try:
            response = subprocess.run(['docker', 'exec', '-i', name, 'python3', '-c', CONTROL_SCRIPT],
                                      input=payload, capture_output=True, timeout=20)
            if response.returncode: raise RuntimeError('Scanner control is unavailable')
            result = json.loads(response.stdout)
        except (subprocess.TimeoutExpired, ValueError):
            raise RuntimeError('Scanner control failed; details withheld to protect session data') from None
        if isinstance(result, dict) and 'code' in result:
            raise RuntimeError('Scanner control rejected a required setting')
        return result

    def replace(label, header, value):
        api('replacer', 'action/addRule', description=label, enabled='true', matchType='REQ_HEADER',
            matchRegex='false', matchString=header, replacement=value,
            url=r'^https://app\.soc\.test:8443/.*')

    # Image pull occurs outside the isolated target network; the scanner itself has no external route.
    subprocess.run(['docker', 'pull', IMAGE], check=True, stdout=subprocess.DEVNULL)
    started = subprocess.run(['docker', 'run', '-d', '--name', name, '--network', network,
        '--memory', '2g', '--cpus', '2', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '-e', 'JAVA_OPTS=-Xmx1024m', IMAGE,
        'zap.sh', '-daemon', '-host', '0.0.0.0', '-port', '8080',
        '-config', 'api.key=' + api_key, '-config', 'api.addrs.addr.name=.*',
        '-config', 'api.addrs.addr.regex=true', '-config', 'autoupdate.checkOnStart=false'], capture_output=True)
    if started.returncode: raise RuntimeError('Isolated scanner failed to start')
    all_alerts = []
    scanned = []
    try:
        ready = False
        startup_deadline = time.monotonic() + 180
        while time.monotonic() < startup_deadline:
            try:
                api('core', 'view/version'); ready = True; break
            except RuntimeError: time.sleep(2)
        if not ready: raise RuntimeError('Scanner did not become ready within three minutes')
        api('ascan', 'action/setOptionThreadPerHost', Integer='1')
        api('ascan', 'action/setOptionDelayInMs', Integer='500')
        api('ascan', 'action/setOptionMaxScanDurationInMins', Integer='3')
        api('ascan', 'action/setOptionMaxRuleDurationInMins', Integer='1')
        rules = api('ascan', 'view/scanners')['scanners']
        selected = [r for r in rules if r['name'] in {'SQL Injection', 'SQL Injection - MySQL',
            'Cross Site Scripting (Reflected)', 'Path Traversal', 'Server Side Request Forgery', 'Remote OS Command Injection'}]
        if not any(r['name'] == 'SQL Injection' for r in selected) or not any('Cross Site Scripting' in r['name'] for r in selected):
            raise RuntimeError('Required SQL/XSS scanner rules are unavailable')
        api('ascan', 'action/disableAllScanners')
        api('ascan', 'action/enableScanners', ids=','.join(str(r['id']) for r in selected))
        targets = [
            ('anonymous', None, None, ['/api/products/query?q=asvs&page=0&size=5',
                                      '/api/reviews/products/e2e-product-fb-010/page?page=0&size=5']),
            ('customer', 'e2e_customer', 'CustomerE2E#1', ['/api/profile', '/api/sync/me/cart']),
            ('admin', 'e2e_admin', 'AdminE2E#1', ['/api/admin/users/page?page=0&size=5', '/api/siem/status']),
        ]
        for role, username, password, paths in targets:
            if username:
                cookie, csrf = login(username, password)
                replace('asvs-cookie', 'Cookie', cookie)
                replace('asvs-csrf', 'X-XSRF-TOKEN', csrf)
            for path in paths:
                # Only these predefined GET paths are scanned; there is no user-provided URL or crawler.
                observed = api('core', 'action/accessUrl', url=BASE + path, followRedirects='false')
                messages = observed.get('accessUrl', [])
                if not any(re.match(r'^HTTP/\S+ 200\b', m.get('responseHeader', '')) for m in messages):
                    raise RuntimeError('A DAST target did not return an authenticated successful response')
                scan = api('ascan', 'action/scan', url=BASE + path, recurse='false', method='GET')['scan']
                deadline = time.monotonic() + 240
                while int(api('ascan', 'view/status', scanId=scan)['status']) < 100:
                    if time.monotonic() >= deadline: raise RuntimeError('A bounded scan exceeded its deadline')
                    time.sleep(3)
                scanned.append({'role': role, 'path': path.split('?')[0], 'method': 'GET', 'timeboxed': True})
            if username:
                api('replacer', 'action/removeRule', description='asvs-cookie')
                api('replacer', 'action/removeRule', description='asvs-csrf')
        deadline = time.monotonic() + 120
        while int(api('pscan', 'view/recordsToScan')['recordsToScan']) > 0:
            if time.monotonic() >= deadline: raise RuntimeError('Passive analysis did not finish')
            time.sleep(2)
        all_alerts = api('core', 'view/alerts', baseurl=BASE, start='0', count='10000')['alerts']
        # A capped API page must never be mistaken for complete alert evidence.
        if len(all_alerts) >= 10000: raise RuntimeError('Alert bound exceeded; review incomplete evidence privately')
        counts = {str(risk): sum(str(a.get('riskcode')) == str(risk) for a in all_alerts) for risk in range(4)}
        private = output/'zap-private.json'
        private.write_text(json.dumps({'source_sha': os.environ['GITHUB_SHA'], 'targets': scanned,
            'alerts': all_alerts, 'note': 'Timeboxed DAST is not exhaustive ASVS verification.'}))
        private.chmod(0o600)
        encrypt(private, output/'zap-private.cms', root/'security/asvs/evidence-recipient.crt')
        private.unlink()
        result = {'source_sha': os.environ['GITHUB_SHA'], 'scan_status': 'COMPLETED_TIMEBOXED',
            'target_count': len(scanned), 'risk_counts': counts, 'max_target_requests_per_second': 2,
            'asvs_l2_established': False, 'production_model_qualified': False}
        (output/'zap-summary.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result))
        if counts['3']:
            raise RuntimeError('High-risk DAST alerts require private validation before release')
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__': main()
