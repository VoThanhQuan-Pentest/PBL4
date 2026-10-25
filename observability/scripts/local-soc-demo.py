#!/usr/bin/env python3
"""Loopback-only SOC workflow fixtures; never trains or pretends to detect attacks.

Public disposable credentials are intentional, like the project's E2E fixtures.
Only the existing flare-otp-local database is supported. Existing accounts,
passwords, cases and customer data are never reset or overwritten.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / 'observability/runtime/local-soc-demo-20261022'
DB = 'flare-otp-local-db-1'
ORIGIN = 'http://127.0.0.1:8088'
ACCOUNTS = {
    'l1': {'id': 'soc-demo-l1', 'username': 'demo_soc_l1', 'password': 'DemoSocL1#2026!', 'role': 'SOC L1'},
    'l2': {'id': 'soc-demo-l2', 'username': 'demo_soc_l2', 'password': 'DemoSocL2#2026!', 'role': 'SOC L2'},
    'customer': {'id': 'soc-demo-customer', 'username': 'demo_soc_customer', 'password': 'DemoCustomer#2026!', 'role': 'customer'},
}
PRACTICE_CUSTOMER = {'id': 'soc-practice-customer', 'username': 'practice_soc_customer',
                     'password': 'PracticeCustomer#2026!', 'role': 'customer'}
PRACTICE_CASES = {
    'L1': ('SOC-PRACTICE-L1', True, 'L1_BENIGN_CLOSURE'),
    'L2': ('SOC-PRACTICE-L2', False, 'L1_ESCALATE_L2_RESPONSE'),
    'RETURN': ('SOC-PRACTICE-RETURN', False, 'L2_RETURN_TO_L1_AND_REESCALATE'),
    'REOPEN': ('SOC-PRACTICE-REOPEN', True, 'L1_CLOSE_REOPEN_AND_CLOSE'),
}


def literal(value):
    # No untrusted text is interpreted as SQL; string values travel as UTF8 hex.
    return "CONVERT(X'" + str(value).encode().hex() + "' USING utf8mb4) COLLATE utf8mb4_unicode_ci"


def sql(statement):
    result = subprocess.run([
        'docker', 'exec', '-i', DB, 'sh', '-ceu',
        'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql --default-character-set=utf8mb4 -N -s -u "$MYSQL_USER" "$MYSQL_DATABASE"'],
        input=statement, text=True, capture_output=True, timeout=30, check=True)
    return result.stdout.strip()


def guard():
    labels = json.loads(subprocess.check_output(
        ['docker', 'inspect', DB, '--format', '{{json .Config.Labels}}'], text=True, timeout=15))
    if labels.get('com.docker.compose.project') != 'flare-otp-local':
        raise RuntimeError('REFUSE_NON_LOCAL_DEMO_DATABASE')
    if subprocess.check_output(['docker', 'inspect', DB, '--format', '{{.State.Running}}'], text=True).strip() != 'true':
        raise RuntimeError('START_LOCAL_SITE_FIRST')
    with urllib.request.urlopen(ORIGIN + '/api/health', timeout=10) as response:
        if response.status != 200:raise RuntimeError('LOCAL_SITE_UNHEALTHY')


def start_stack():
    names = ['flare-otp-local-' + name + '-1' for name in ('db', 'redis', 'app', 'nginx')]
    # Validate every target before starting anything; never create or replace a
    # deployment, read an env file, or rerun a password-resetting seed profile.
    for name in names:
        labels = json.loads(subprocess.check_output(
            ['docker', 'inspect', name, '--format', '{{json .Config.Labels}}'], text=True, timeout=15))
        if labels.get('com.docker.compose.project') != 'flare-otp-local':
            raise RuntimeError('REFUSE_UNRELATED_CONTAINER')
    for name in names:
        subprocess.run(['docker', 'start', name], check=True, stdout=subprocess.DEVNULL, timeout=30)
        deadline = time.monotonic() + 180
        while True:
            state = json.loads(subprocess.check_output(
                ['docker', 'inspect', name, '--format', '{{json .State}}'], text=True, timeout=15))
            if state['Running'] and state.get('Health', {}).get('Status', 'healthy') == 'healthy':break
            if not state['Running'] or time.monotonic() >= deadline:
                raise RuntimeError('CONTAINER_NOT_READY: ' + name)
            time.sleep(2)
        print('READY ' + name, flush=True)


def publish(name, value):
    from ueba_research_artifacts import publish as atomic_publish, private_directory
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(STATE)
    atomic_publish(STATE / name, value, maximum=64 * 1024)


def client():
    # Reuse the project's cookie/CSRF HTTP client; importing never runs AWS code.
    spec = importlib.util.spec_from_file_location('local_soc_http', ROOT / 'observability/scripts/aws-soc.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.Client(ORIGIN)


def prepare_accounts(accounts=None, profile_id='soc-demo-customer-profile', phone='0000000993'):
    accounts = ACCOUNTS if accounts is None else accounts
    for key, account in accounts.items():
        identity = sql('SELECT id,username,role,is_deleted FROM tbl_nguoi_dung WHERE id=' + literal(account['id'])
                       + ' OR username=' + literal(account['username']) + ';')
        if identity:
            if identity.split('\t') != [account['id'], account['username'], account['role'], '0']:
                raise RuntimeError('DEMO_ACCOUNT_COLLISION_NO_OVERWRITE: ' + key)
            continue
        prehash = base64.b64encode(hashlib.sha256(account['password'].encode()).digest()).rstrip(b'=').decode()
        hashed = subprocess.run(['htpasswd', '-niBC', '12', 'demo'], input=prehash + '\n',
                                text=True, capture_output=True, check=True, timeout=15).stdout.strip().split(':', 1)[1]
        encoded = '{bcrypt-sha256}' + hashed
        values = [account['id'], account['username'], encoded, account['role'],
                  'Demo ' + key.upper(), account['username'] + '@example.test', 'Hoat dong']
        sql('INSERT INTO tbl_nguoi_dung (id,username,password,role,ho_ten,email,trang_thai,is_deleted,auth_version) VALUES ('
            + ','.join(map(literal, values)) + ',0,0);')
    target = accounts['customer']
    name = 'SOC Practice Customer' if target['id'] == PRACTICE_CUSTOMER['id'] else 'Demo SOC Customer'
    sql('INSERT INTO tbl_khach_hang (id,user_id,ten_khach,sdt,email,kenh,nhan,dia_chi,ghi_chu,tong_chi_tieu,hang_khach_hang,is_deleted) '
        'SELECT ' + ','.join(literal(x) for x in [profile_id, target['id'], name])
        + ',' + literal(phone) + ',' + ','.join(literal(x) for x in [target['username'] + '@example.test', 'Local demo', 'DEMO_ONLY',
                                                  'Local demonstration', 'Controlled SOC workflow fixture'])
        + ',0,' + literal('Thuong') + ',0 WHERE NOT EXISTS (SELECT 1 FROM tbl_khach_hang WHERE user_id='
        + literal(target['id']) + ');')


def new_case(benign=False, *, practice_kind=None, statements=None):
    suffix = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    if practice_kind is not None:
        prefix, benign, case_type = PRACTICE_CASES[practice_kind]
        identifier = 'soc-practice-' + suffix
        target = PRACTICE_CUSTOMER
    else:
        prefix = 'SOC-DEMO-L1' if benign else 'SOC-DEMO-L2'
        identifier = 'soc-demo-' + suffix
        target = ACCOUNTS['customer']
        case_type = 'L1_BENIGN_CLOSURE' if benign else 'L1_ESCALATE_L2_RESPONSE'
    title = prefix + ' ' + suffix + ' | Controlled account workflow'
    explanation = ('DEMO_ONLY_WORKFLOW_FIXTURE: manually provisioned case for L1/L2 workflow and session revocation. '
                   'Not an output of the trained model; no confirmed real attack or fabricated Elastic evidence.')
    columns = ('id,grouping_key,rule_id,source_ip,bucket_start,title,source_severity,score,severity,classification,'
               'classification_reason,missing_data,status,conclusion,queue_tier,origin,incident_nature,target_user_id,'
               'first_seen,last_seen,ngay_tao,updated_at,version')
    values = [literal(identifier), literal(identifier), literal('SOC_DEMO_WORKFLOW'), literal('192.0.2.25'),
              'UTC_TIMESTAMP(6)', literal(title), literal('low' if benign else 'high'), '20' if benign else '80',
              literal('LOW' if benign else 'HIGH'), literal('POTENTIAL_NOISE' if benign else 'INVESTIGATE'),
              literal(explanation), '0' if benign else '1', literal('NEW'), literal('UNREVIEWED'), literal('L1'), literal('UEBA'),
              literal('ACCOUNT_BEHAVIOR_ANOMALY'), literal(target['id']),
              'UTC_TIMESTAMP(6)', 'UTC_TIMESTAMP(6)', 'UTC_TIMESTAMP(6)', 'UTC_TIMESTAMP(6)', '0']
    statement = 'INSERT INTO siem_incidents (' + columns + ') VALUES (' + ','.join(values) + ');'
    if statements is None:sql(statement)
    else:statements.append(statement)
    return {'incident_id': identifier, 'title': title, 'data_provenance': 'DEMO_ONLY_WORKFLOW_FIXTURE',
            'target_user_id': target['id'], 'model_inference_performed': False, 'case_type': case_type}


def reserved_demo_snapshot():
    from ueba_research_artifacts import private_directory
    private_directory(STATE)
    result = {'pointer_sha256': {}, 'cases': {}}
    for name in ['latest-case.private.json', 'latest-benign-case.private.json']:
        path = STATE / name
        if name == 'latest-benign-case.private.json' and not path.exists():continue
        if path.is_symlink():raise RuntimeError('UNSAFE_PRESENTATION_POINTER')
        raw = path.read_bytes();value = json.loads(raw)
        identifier = value['incident_id']
        if not identifier.startswith('soc-demo-'):raise RuntimeError('PRESENTATION_POINTER_NOT_DEMO_CASE')
        result['pointer_sha256'][name] = hashlib.sha256(raw).hexdigest()
        row = sql("SELECT JSON_OBJECT('id',id,'status',status,'tier',queue_tier,'assignee',assignee_user_id,"
                  "'conclusion',conclusion,'version',version,'updated_at',updated_at,"
                  "'notes',(SELECT COUNT(*) FROM siem_incident_notes WHERE incident_id=i.id),"
                  "'history',(SELECT COUNT(*) FROM siem_incident_history WHERE incident_id=i.id),"
                  "'responses',(SELECT COUNT(*) FROM siem_response_actions WHERE incident_id=i.id)) "
                  'FROM siem_incidents i WHERE id=' + literal(identifier) + ';')
        if not row:raise RuntimeError('PRESENTATION_CASE_MISSING')
        result['cases'][identifier] = json.loads(row)
    result['demo_customer_sha256'] = sql("SELECT SHA2(CAST(JSON_OBJECT('id',id,'password',password,"
        "'email',email,'role',role,'auth_version',auth_version,'deleted',is_deleted) AS CHAR),256) "
        'FROM tbl_nguoi_dung WHERE id=' + literal(ACCOUNTS['customer']['id']) + ';')
    return result


def practice():
    pointer=STATE/'latest-practice.private.json'
    if pointer.exists():
        current=json.loads(pointer.read_text())
        if len(current.get('cases',[]))==1:
            case=current['cases'][0]
            if sql('SELECT COUNT(*) FROM siem_incidents WHERE id='+literal(case['incident_id'])
                   +' AND target_user_id='+literal(PRACTICE_CUSTOMER['id'])+';')=='1':return current
    before = reserved_demo_snapshot()
    accounts = {**ACCOUNTS, 'customer': PRACTICE_CUSTOMER}
    prepare_accounts(accounts, profile_id='soc-practice-customer-profile', phone='0000000994')
    statements = []
    cases = [new_case(practice_kind='L2', statements=statements)]
    sql('START TRANSACTION;\n' + '\n'.join(statements) + '\nCOMMIT;')
    connection = client();response = connection.login(PRACTICE_CUSTOMER)
    if response['user']['id'] != PRACTICE_CUSTOMER['id']:raise RuntimeError('WRONG_PRACTICE_IDENTITY')
    if connection.request('GET', '/api/auth/me')['id'] != PRACTICE_CUSTOMER['id']:
        raise RuntimeError('PRACTICE_LOGIN_NOT_VALID')
    connection.request('POST', '/api/auth/logout', {})
    after = reserved_demo_snapshot()
    if after != before:raise RuntimeError('PRESENTATION_STATE_CHANGED_DURING_PRACTICE_SETUP_REVIEW_REQUIRED')
    for case in cases:
        value = sql("SELECT status,queue_tier,COALESCE(assignee_user_id,''),version FROM siem_incidents WHERE id="
                    + literal(case['incident_id']) + ';')
        if value != 'NEW\tL1\t\t0':raise RuntimeError('PRACTICE_CASE_NOT_READY')
    result = {'status': 'PRACTICE_CASES_READY_PRESENTATION_UNCHANGED',
              'cases': cases, 'practice_customer_username': PRACTICE_CUSTOMER['username'],
              'practice_customer_login_verified': True, 'presentation_before': before,
              'presentation_after': after, 'new_fits': 0}
    publish('practice-batch-' + uuid.uuid4().hex + '.private.json', result)
    publish('latest-practice.private.json', result)
    return result


def rehearse():
    case = new_case();prefix = '/api/siem/incidents/' + case['incident_id']
    clients = {key: client() for key in ACCOUNTS}
    for key, connection in clients.items():
        response = connection.login(ACCOUNTS[key])
        if response['user']['id'] != ACCOUNTS[key]['id']:raise RuntimeError('WRONG_DEMO_IDENTITY')
    def current(connection):return connection.request('GET', prefix)['incident']
    def transition(connection, action, reason=None, conclusion=None):
        body = {'expected_version': current(connection)['version'], 'action': action}
        if reason:body['reason'] = reason
        if conclusion:body['conclusion'] = conclusion
        return connection.request('POST', prefix + '/transitions', body)
    checks = []
    def expect_denied(operation, status):
        try:operation()
        except urllib.error.HTTPError as error:
            if error.code != status:raise
            error.close();return
        raise AssertionError('EXPECTED_PERMISSION_DENIAL')
    one, two, customer = clients['l1'], clients['l2'], clients['customer']
    expect_denied(lambda: customer.request('GET', '/api/siem/capabilities'), 403)
    checks.append('customer_cannot_access_soc')
    benign = new_case(benign=True);benign_prefix = '/api/siem/incidents/' + benign['incident_id']
    item = one.request('GET', benign_prefix)['incident']
    item = one.request('POST', benign_prefix + '/transitions', {'expected_version': item['version'], 'action': 'CLAIM'})
    item = one.request('POST', benign_prefix + '/transitions', {'expected_version': item['version'], 'action': 'CLOSE',
        'reason': 'DEMO_ONLY: controlled benign fixture, L1 can resolve this LOW case.', 'conclusion': 'FALSE_POSITIVE'})
    assert item['status'] == 'CLOSED' and item['queue_tier'] == 'L1'
    checks.append('l1_can_claim_and_close_low_benign_case')
    assert transition(one, 'CLAIM')['status'] == 'IN_PROGRESS'
    expect_denied(lambda: transition(one, 'CLOSE', 'Demo L1 must not close HIGH case.', 'TRUE_POSITIVE'), 403)
    checks.append('l1_cannot_close_high_case')
    note = one.request('POST', prefix + '/notes', {'content': 'DEMO_ONLY: L1 reviewed the controlled fixture; escalation required.'})
    escalated = transition(one, 'ESCALATE', 'DEMO_ONLY: controlled suspicious case requires L2 review.')
    assert escalated['queue_tier'] == 'L2' and escalated['status'] == 'NEW' and not escalated.get('assignee_user_id')
    expect_denied(lambda: transition(one, 'CLAIM'), 403)
    checks.append('l1_to_l2_resets_assignment_and_enforces_tier')
    assert transition(two, 'CLAIM')['assignee_user_id'] == ACCOUNTS['l2']['id']
    response = two.request('POST', prefix + '/response-actions', {
        'expected_version': current(two)['version'], 'request_id': str(uuid.uuid4()),
        'reason': 'DEMO_ONLY: revoke only the dedicated demo customer sessions.'})
    expect_denied(lambda: customer.request('GET', '/api/auth/me'), 401)
    fresh_customer = client();fresh_customer.login(ACCOUNTS['customer'])
    assert fresh_customer.request('GET', '/api/auth/me')['id'] == ACCOUNTS['customer']['id']
    fresh_customer.request('POST', '/api/auth/logout', {})
    checks.append('old_customer_session_rejected_new_login_allowed')
    closed = transition(two, 'CLOSE', 'DEMO_ONLY: controlled workflow completed; not a real confirmed attack.', 'TRUE_POSITIVE')
    assert closed['status'] == 'CLOSED'
    history = two.request('GET', prefix + '/history')
    pairs = {(x['action'], x.get('actor_user_id')) for x in history}
    required = {('CLAIM', ACCOUNTS['l1']['id']), ('ESCALATE', ACCOUNTS['l1']['id']),
                ('CLAIM', ACCOUNTS['l2']['id']), ('CLOSE', ACCOUNTS['l2']['id']),
                ('CUSTOMER_SESSIONS_REVOKED', ACCOUNTS['l2']['id'])}
    assert required <= pairs
    assert any(n['id'] == note['id'] for n in two.request('GET', prefix)['notes'])
    checks.append('notes_and_actor_history_persisted')
    for connection in [one, two]:connection.request('POST', '/api/auth/logout', {})
    result = {'status': 'LOCAL_SOC_REHEARSAL_PASS', **case, 'checks': checks,
              'final_status': closed['status'], 'benign_case_id': benign['incident_id'],
              'new_fits': 0, 'personal_accounts_modified': False}
    publish('rehearsal-' + case['incident_id'] + '.private.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['start', 'prepare', 'new-case', 'rehearse', 'practice', 'status'])
    args = parser.parse_args()
    if args.action == 'start':start_stack()
    guard()
    if args.action == 'status':
        print('LOCAL_SITE_HEALTHY ' + ORIGIN)
        for name in ['latest-case.private.json', 'latest-benign-case.private.json', 'latest-practice.private.json']:
            if (STATE / name).exists():print((STATE / name).read_text())
        return
    if args.action == 'practice':
        result = practice()
        print(json.dumps({key: result.get(key) for key in
                          ['status', 'cases', 'practice_customer_username', 'practice_customer_login_verified']},
                         ensure_ascii=False));return
    prepare_accounts()
    if args.action == 'rehearse':
        print(json.dumps(rehearse(), ensure_ascii=False));return
    for benign, name in [(False, 'latest-case.private.json')]:
        pointer = STATE / name
        if args.action != 'new-case' and pointer.exists():
            old = json.loads(pointer.read_text())
            current = sql('SELECT status,queue_tier,COALESCE(assignee_user_id,\'\') FROM siem_incidents WHERE id='
                          + literal(old['incident_id']) + ';')
            if current:
                print(json.dumps(old));continue
        case = new_case(benign=benign);publish(name, case)
        print(json.dumps(case, ensure_ascii=False))


if __name__ == '__main__':
    main()
