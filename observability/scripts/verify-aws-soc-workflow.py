#!/usr/bin/env python3
"""Exercise L1/L2 on one explicitly selected synthetic AWS UEBA incident.

When the operational SOC accounts and the incident fixture were provisioned
from different synthetic datasets, pass --fixture-dataset explicitly.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.error

ROOT = Path(__file__).resolve().parents[2]

def fixture_scope(operator_dataset, fixture_dataset=None):
    generator = load('seed-ueba-demo')
    if not isinstance(operator_dataset, str) or not generator.DATASET_RE.fullmatch(operator_dataset):
        raise ValueError('Invalid operator dataset')
    selected = operator_dataset if fixture_dataset is None else fixture_dataset
    if not isinstance(selected, str) or not generator.DATASET_RE.fullmatch(selected):
        raise ValueError('Invalid synthetic fixture dataset')
    return selected, {generator.account_id(selected, index) for index in range(1, 6)}

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / f'observability/scripts/{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--incident-id', required=True)
    parser.add_argument('--credentials', type=Path, required=True)
    parser.add_argument('--fixture-dataset',
                        help='Synthetic customer dataset owning the incident target (defaults to operator dataset)')
    parser.add_argument('--url', default='http://127.0.0.1:8089')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if ROOT != Path('/opt/flare') or 'FLARE_ENVIRONMENT=aws-lab' not in (ROOT / '.env').read_text().splitlines():
        parser.error('Run only on AWS Web via SSH')
    if not re.fullmatch('[A-Za-z0-9_-]{1,100}', args.incident_id):
        parser.error('Invalid incident identifier')
    state = json.loads(args.credentials.read_text())
    try:
        operator_dataset = state.get('dataset')
        fixture_dataset, allowed = fixture_scope(operator_dataset, args.fixture_dataset)
    except ValueError:
        parser.error('Invalid operator or fixture dataset')
    soc = load('aws-soc')
    clients = {role: soc.Client(args.url) for role in ('l1', 'l2')}
    for role, client in clients.items():
        client.login(state['accounts'][role])
    prefix = '/api/siem/incidents/' + args.incident_id
    def current(client):
        return client.request('GET', prefix)['incident']
    def transition(client, action, reason=None, conclusion=None):
        item = current(client)
        body = dict(expected_version=item['version'], action=action)
        if reason is not None:
            body['reason'] = reason
        if conclusion is not None:
            body['conclusion'] = conclusion
        return client.request('POST', prefix + '/transitions', body)
    item = current(clients['l1'])
    if item['origin'] != 'UEBA' or item['target_user_id'] not in allowed or item['queue_tier'] != 'L1':
        raise RuntimeError('Refuse to mutate a non-fixture incident or an incident already in L2')
    if item['status'] == 'NEW' and not item.get('assignee_user_id'):
        item = transition(clients['l1'], 'CLAIM')
    if item['status'] != 'IN_PROGRESS' or item['assignee_user_id'] != state['accounts']['l1']['id']:
        raise RuntimeError('Fixture must be assigned to this L1 operator')
    try:
        transition(clients['l1'], 'CLOSE', 'Controlled demo: L1 cannot confirm a high-risk incident', 'TRUE_POSITIVE')
    except urllib.error.HTTPError as error:
        if error.code != 403:
            raise
        error.close()
    else:
        raise RuntimeError('L1 close was not denied')
    note = clients['l1'].request('POST', prefix + '/notes', {
        'content': 'AWS acceptance: synthetic DEMO_ONLY abnormal behavior reviewed by SOC L1.'})
    escalated = transition(clients['l1'], 'ESCALATE', 'Synthetic UEBA anomaly requires SOC L2 review.')
    if escalated['queue_tier'] != 'L2' or escalated['status'] != 'NEW' or escalated.get('assignee_user_id'):
        raise RuntimeError('Escalation did not reset the L2 assignment')
    claimed = transition(clients['l2'], 'CLAIM')
    if claimed['assignee_user_id'] != state['accounts']['l2']['id']:
        raise RuntimeError('L2 claim not persisted')
    closed = transition(clients['l2'], 'CLOSE', 'Confirmed synthetic attack fixture; not a real-world attack.', 'TRUE_POSITIVE')
    history = clients['l2'].request('GET', prefix + '/history')
    # SYSTEM-created history rows legitimately omit an actor; human actions must still match below.
    pairs = {(row['action'], row.get('actor_user_id')) for row in history}
    expected = {('CLAIM', state['accounts']['l1']['id']), ('ESCALATE', state['accounts']['l1']['id']),
                ('CLAIM', state['accounts']['l2']['id']), ('CLOSE', state['accounts']['l2']['id'])}
    notes = clients['l2'].request('GET', prefix)['notes']
    if not expected.issubset(pairs) or not all(row.get('created_at') for row in history):
        raise RuntimeError('Workflow history lacks expected actor/action/timestamp')
    if not any(row['id'] == note['id'] and row['author_user_id'] == state['accounts']['l1']['id'] for row in notes):
        raise RuntimeError('L1 note not persisted')
    if closed['status'] != 'CLOSED' or closed['conclusion'] != 'TRUE_POSITIVE':
        raise RuntimeError('L2 closure not persisted')
    result = dict(passed=True, environment='AWS', data_provenance='DEMO_ONLY',
                  operator_dataset=operator_dataset, fixture_dataset=fixture_dataset,
                  incident_id=args.incident_id,
                  l1_close_denied=True, note_persisted=True, final_status=closed['status'],
                  history=[{key: row.get(key) for key in ('action', 'actor_user_id', 'created_at')} for row in history])
    os.umask(0o077)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
    for client in clients.values():
        client.request('POST', '/api/auth/logout', {})
    print(json.dumps(result))

if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as failure:
        failure.close()
        raise SystemExit(f'API returned HTTP {failure.code}; body intentionally omitted')
    except (ValueError, KeyError, RuntimeError) as failure:
        raise SystemExit(str(failure))
