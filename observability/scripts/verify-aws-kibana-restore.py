#!/usr/bin/env python3
"""Import the lab's private backup into a new temporary Kibana space without altering the primary space."""
import argparse
import base64
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backup', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if ROOT != Path('/opt/flare'):
        p.error('Run on AWS Monitor')
    password = (ROOT / '.secrets/observability/monitor/elasticsearch.password').read_text().strip()
    auth = 'Basic ' + base64.b64encode(('elastic:' + password).encode()).decode()
    space = 'flare-restore-' + secrets.token_hex(6)
    def request(method, path, body=None, content_type='application/json'):
        data = body if isinstance(body, bytes) else None if body is None else json.dumps(body).encode()
        req = urllib.request.Request('http://127.0.0.1:5601' + path, data=data, method=method,
            headers={'Authorization':auth, 'kbn-xsrf':'flare-restore-check', 'Content-Type':content_type,
                     'Elastic-Api-Version':'2023-10-31'})
        with urllib.request.urlopen(req,timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    request('POST','/api/spaces/space',dict(id=space,name='Isolated restore verification',description='Disposable owned lab backup check'))
    prefix = '/s/' + space
    try:
        boundary = 'flare-' + secrets.token_hex(12)
        def multipart(filename, payload):
            return (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                    'Content-Type: application/ndjson\r\n\r\n').encode() + payload + f'\r\n--{boundary}--\r\n'.encode()
        imported = request('POST',prefix+'/api/saved_objects/_import?overwrite=false',
            multipart('saved-objects.ndjson',(args.backup/'saved-objects.ndjson').read_bytes()),
            'multipart/form-data; boundary='+boundary)
        if not imported.get('success'):
            raise RuntimeError('Saved object import failed')
        rules=[]
        for line in (args.backup/'detection-rules.ndjson').read_text().splitlines():
            value=json.loads(line)
            if value.get('rule_id'):
                value['enabled']=False
                rules.append(value)
        payload=('\n'.join(json.dumps(row) for row in rules)+'\n').encode()
        request('POST',prefix+'/api/detection_engine/rules/_import?overwrite=false',
            multipart('detection-rules.ndjson',payload),'multipart/form-data; boundary='+boundary)
        dashboards=request('GET',prefix+'/api/saved_objects/_find?type=dashboard&per_page=100')
        restored_rules=request('GET',prefix+'/api/detection_engine/rules/_find?per_page=100')
        if any(row['enabled'] for row in restored_rules['data']):
            request('POST',prefix+'/api/detection_engine/rules/_bulk_action',
                    dict(action='disable',ids=[row['id'] for row in restored_rules['data']]))
            restored_rules=request('GET',prefix+'/api/detection_engine/rules/_find?per_page=100')
        # Modern Kibana assigns globally unique destination IDs when copying between spaces.
        expected_dashboards={json.loads(line)['attributes']['title']
            for line in (args.backup/'saved-objects.ndjson').read_text().splitlines()
            if json.loads(line).get('type')=='dashboard'}
        restored_dashboards=[row['attributes']['title'] for row in dashboards['saved_objects']]
        passed=expected_dashboards.issubset(set(restored_dashboards)) \
            and len(restored_rules['data'])==6 and all(not row['enabled'] for row in restored_rules['data'])
        result=dict(passed=passed,environment='AWS',method='Isolated temporary Kibana space; restored rules disabled',
                    dashboard_count=len(restored_dashboards),rule_count=len(restored_rules['data']),
                    rules_disabled=all(not row['enabled'] for row in restored_rules['data']),primary_space_unchanged=True)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x') as stream:
            json.dump(result,stream,indent=2)
        print(json.dumps(result))
        if not passed: raise SystemExit(1)
    finally:
        request('DELETE','/api/spaces/space/'+space)
        print('Disposable restored space removed; private backup and primary flare-lab space retained.')

if __name__ == '__main__':
    try: main()
    except urllib.error.HTTPError as failure:
        failure.close()
        raise SystemExit(f'Kibana returned HTTP {failure.code}; credential/body omitted')
