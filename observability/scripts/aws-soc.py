#!/usr/bin/env python3
"""AWS lab operator workflow, through existing APIs and a loopback origin only."""
import argparse
from datetime import datetime, timedelta, timezone
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class Client:
    def __init__(self, origin):
        url = urllib.parse.urlsplit(origin)
        if url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost') or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
            raise ValueError('Use the loopback AWS web tunnel or the EC2 loopback listener')
        self.origin = origin.rstrip('/')
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, body=None):
        headers = {'Content-Type': 'application/json'}
        if method not in ('GET', 'HEAD'):
            headers['X-XSRF-TOKEN'] = self.request('GET', '/api/auth/csrf')['token']
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        with self.opener.open(req, timeout=20) as response:
            raw = response.read(2 * 1024 * 1024)
            return json.loads(raw) if raw else None

    def login(self, credential):
        for attempt in range(3):
            try:
                return self.request('POST', '/api/auth/login', {key: credential[key] for key in ('username', 'password')})
            except urllib.error.HTTPError as error:
                if error.code != 429 or attempt == 2:
                    raise
                error.close()
                time.sleep(65)

def private_json(path, value, first=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if first:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output)
    else:
        temporary = path.with_name(path.name + '.next')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output)
        os.replace(temporary, path)

def provision(args, state):
    root = Path(__file__).resolve().parents[2]
    if root != Path('/opt/flare') or 'FLARE_ENVIRONMENT=aws-lab' not in (root / '.env').read_text().splitlines():
        raise ValueError('Provision operators only on AWS Web via SSH')
    bootstrap = json.loads(args.bootstrap.read_text())
    if not state:
        state.update(dataset=args.dataset, bootstrap_id=bootstrap['id'], accounts={})
        private_json(args.credentials, state, first=True)
    if state['dataset'] != args.dataset or state['bootstrap_id'] != bootstrap['id']:
        raise ValueError('Credential file belongs to another dataset/bootstrap')
    client = Client(args.url)
    client.login(state['accounts'].get('admin', bootstrap) if state.get('bootstrap_disabled') else bootstrap)
    for key, role in (('admin', 'Admin'), ('l1', 'SOC L1'), ('l2', 'SOC L2')):
        if key not in state['accounts']:
            state['accounts'][key] = {'username': f'aws_{args.dataset}_{key}',
                                      'password': 'Aa1#' + secrets.token_urlsafe(24), 'role': role}
            private_json(args.credentials, state)
        credential = state['accounts'][key]
        existing = [user for user in client.request('GET', '/api/admin/users') if user['username'] == credential['username']]
        if existing:
            verify = Client(args.url)
            verify.login(credential)  # Adopt only an account whose saved credential works.
            verify.request('POST', '/api/auth/logout', {})
            credential['id'] = existing[0]['id']
        else:
            result = client.request('POST', '/api/admin/users', dict(credential,
                                    ho_ten=f'AWS demo {role}', status='Hoat dong'))
            credential['id'] = result['id']
        private_json(args.credentials, state)
    permanent = Client(args.url)
    permanent.login(state['accounts']['admin'])
    permanent.request('GET', '/api/admin/users/page?size=1')
    catalog = permanent.request('GET', '/api/admin/products')
    for index, name in enumerate(('Áo thể thao demo', 'Giày thể thao demo', 'Bóng tập demo'), 1):
        sku = f'AWS-DEMO-{args.dataset}-{index}'
        if not any(product.get('sku') == sku for product in catalog):
            permanent.request('POST', '/api/admin/products', {
                'ten_san_pham': name, 'sku': sku, 'danh_muc': 'Demo', 'thuong_hieu': 'Flare Lab',
                'size': 'M', 'mau': 'Demo', 'gia_nhap': 10000, 'gia_ban': 20000,
                'ton_kho': 50, 'trang_thai': 'Đang bán', 'ghi_chu': 'Synthetic AWS lab catalog'})
    if not state.get('bootstrap_disabled'):
        if not state['bootstrap_id'].startswith('aws-bootstrap-'):
            raise ValueError('Refuse to retire an unrelated account')
        permanent.request('DELETE', '/api/admin/users/' + state['bootstrap_id'])
        state['bootstrap_disabled'] = True
        private_json(args.credentials, state)
    print('Operational Admin, L1 and L2 created; temporary bootstrap retired. Credentials stay in the private file.')

def verify(args, state):
    admin = None
    for key in ('admin', 'l1', 'l2'):
        client = Client(args.url)
        client.login(state['accounts'][key])
        client.request('GET', '/api/siem/status')
        if key == 'l1':
            try:
                client.request('POST', '/api/siem/signatures/absent-preflight/activate?version=0', {})
            except urllib.error.HTTPError as error:
                if error.code != 403:
                    raise
                error.close()
            else:
                raise RuntimeError('L1 activation was not denied')
        if key == 'admin':
            admin = client
        else:
            client.request('POST', '/api/auth/logout', {})
    customer_file = args.customer_credentials or Path(__file__).resolve().parents[2] / f"observability/runtime/private-credentials/customers-{state['dataset']}.json"
    customer = Client(args.url)
    customer.login(json.loads(customer_file.read_text())[0])
    try:
        customer.request('GET', '/api/siem/status')
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise
        error.close()
    else:
        raise RuntimeError('Customer SIEM access was not denied')
    finally:
        customer.request('POST', '/api/auth/logout', {})
    ueba = admin.request('GET', '/api/siem/ueba/status')
    protection = admin.request('GET', '/api/siem/prevention/status')
    passed = (ueba.get('worker_available') is True and ueba.get('model_available') is True
              and ueba.get('active_model_provenance') == 'DEMO_ONLY'
              and protection.get('gateway_state') == 'APPLIED'
              and protection.get('active_signatures', 0) > 0
              and protection.get('ipinfo_state') == 'CONFIGURED'
              and protection.get('abuse_ip_db_state') == 'CONFIGURED')
    intel = admin.request('GET', '/api/siem/ip-intelligence?ip=8.8.4.4')
    admin.request('POST', '/api/auth/logout', {})
    passed = passed and {row['provider'] for row in intel if row['status'] == 'FRESH' and row['data_provenance'] == 'REAL'} == {'IPINFO', 'ABUSEIPDB'}
    print(json.dumps({'passed': passed, 'scope': 'aws-soc-api', 'rbac': True,
                      'ueba': ueba, 'prevention': protection,
                      'provider_results': [{key: row[key] for key in ('provider', 'status', 'data_provenance', 'observed_at')} for row in intel]}))
    if not passed:
        raise SystemExit(1)

def train(args, state):
    admin = Client(args.url)
    admin.login(state['accounts']['admin'])
    # Server requires windows to be at least 15 minutes old; retain one minute of clock margin.
    now = (datetime.now(timezone.utc) - timedelta(minutes=16)).replace(tzinfo=None)
    job = admin.request('POST', '/api/siem/ueba/training-jobs',
                        {'from': (now - timedelta(days=14)).isoformat(), 'to': now.isoformat()})
    for _ in range(120):
        job = admin.request('GET', '/api/siem/ueba/training-jobs/' + job['id'])
        if job['status'] in ('SUCCEEDED', 'FAILED', 'ACTIVE'):
            break
        time.sleep(5)
    if job['status'] != 'SUCCEEDED' or job.get('data_provenance') != 'DEMO_ONLY':
        raise RuntimeError('Candidate did not succeed as DEMO_ONLY; inspect training job in JavaFX')
    activated = admin.request('POST', '/api/siem/ueba/models/' + job['model_version'] + '/activate', {})
    print(json.dumps({'job_id': job['id'], 'model_version': job['model_version'],
                      'status': activated['status'], 'data_provenance': activated['data_provenance']}))

def signature(args, state):
    client = Client(args.url)
    client.login(state['accounts']['l2'])
    def find():
        rows = client.request('GET', '/api/siem/signatures?size=100')['content']
        return next((row for row in rows if row['kind'] == 'PATH_EXACT' and row.get('match_value') == '/.env' and row.get('http_method') == 'GET'), None)
    item = find() or client.request('POST', '/api/siem/signatures',
        {'kind': 'PATH_EXACT', 'http_method': 'GET', 'match_value': '/.env', 'severity': 'HIGH'})
    if item['status'] in ('DRAFT', 'DISABLED'):
        result = client.request('POST', f"/api/siem/signatures/{item['id']}/test-default?version={item['version']}", {})
        if not result['passed']:
            raise RuntimeError('Signature fixture failed')
        item = find()
    if item['status'] == 'TESTED':
        client.request('POST', f"/api/siem/signatures/{item['id']}/activate?version={item['version']}", {})
    for _ in range(20):
        item = find()
        if item['status'] == 'ACTIVE':
            print(json.dumps({'signature_id': item['id'], 'status': 'ACTIVE'}))
            return
        time.sleep(2)
    raise RuntimeError('Gateway did not acknowledge the signature')

def lookup(args, state):
    client = Client(args.url)
    client.login(state['accounts']['l2'])
    client.request('POST', '/api/siem/ip-intelligence/lookup?ip=8.8.4.4&reason=AWS_ACCEPTANCE', {})
    for _ in range(18):
        rows = client.request('GET', '/api/siem/ip-intelligence?ip=8.8.4.4')
        if len(rows) == 2 and all(row['status'] == 'FRESH' and row['data_provenance'] == 'REAL' for row in rows):
            print(json.dumps({'passed': True, 'providers': [row['provider'] for row in rows]}))
            return
        time.sleep(5)
    raise RuntimeError('Provider acceptance not fresh; inspect IP intelligence in JavaFX')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('provision', 'verify', 'train', 'signature', 'lookup'))
    p.add_argument('--url', default='http://127.0.0.1:18088')
    p.add_argument('--credentials', type=Path, required=True)
    p.add_argument('--bootstrap', type=Path)
    p.add_argument('--customer-credentials', type=Path)
    p.add_argument('--dataset', default='aws-demo')
    args = p.parse_args()
    if not re.fullmatch('[a-z0-9][a-z0-9_-]{3,23}', args.dataset):
        p.error('Invalid dataset ID')
    if args.action == 'provision' and args.bootstrap is None:
        p.error('Provision requires --bootstrap')
    os.umask(0o077)
    state = json.loads(args.credentials.read_text()) if args.credentials.exists() else {}
    {'provision': provision, 'verify': verify, 'train': train, 'signature': signature, 'lookup': lookup}[args.action](args, state)

if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as failure:
        failure.close()
        raise SystemExit(f'API returned HTTP {failure.code}; response body intentionally omitted')
    except (ValueError, KeyError, RuntimeError) as failure:
        raise SystemExit(str(failure))
