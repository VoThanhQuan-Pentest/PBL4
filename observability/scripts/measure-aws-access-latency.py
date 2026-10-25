#!/usr/bin/env python3
"""Measure 30 to 100 benign owned-lab probes until each trace is searchable in ELK."""
import argparse
import csv
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
REMOTE = r'''
import base64,json,ssl,sys,urllib.request
query=json.load(sys.stdin)
password=open('/opt/flare/.secrets/observability/monitor/siem-reader.password').read().strip()
ctx=ssl.create_default_context(cafile='/opt/flare/.secrets/observability/monitor/ca.crt')
request=urllib.request.Request('https://10.20.10.20:9200/logs-nginx.access-lab/_search',
    data=json.dumps(query).encode(),headers={'Content-Type':'application/json',
    'Authorization':'Basic '+base64.b64encode(('flare_siem_reader:'+password).encode()).decode()})
with urllib.request.urlopen(request,context=ctx,timeout=8) as response:
    hits=json.load(response)['hits']['hits']
print(json.dumps({'found':bool(hits)}))
'''

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=100,
                        help='Number of probes (30 to 100; default: 100)')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 30 <= args.samples <= 100:
        parser.error('Use 30 to 100 samples')
    outputs = json.loads(subprocess.check_output(['terraform', '-chdir=terraform', 'output', '-json'], cwd=ROOT, text=True))
    web = outputs['web_elastic_ip']['value']
    monitor = outputs['monitor_elastic_ip']['value']
    if not all(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', value) for value in (web, monitor)):
        parser.error('Terraform outputs must contain explicit IPv4 addresses')
    target = 'http://' + web + '/api/health'
    ssh_options = shlex.split(os.environ.get('SSH_OPTIONS', '-o BatchMode=yes -o StrictHostKeyChecking=accept-new'))
    opener = urllib.request.build_opener(NoRedirect())
    os.umask(0o077)
    dest = args.output or ROOT / 'observability/runtime' / ('aws-access-latency-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '.csv')
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    results = []
    with dest.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('sample', 'started_at', 'trace_id', 'http_status', 'visible_seconds', 'passed'))
        writer.writeheader()
        for index in range(args.samples):
            started = time.monotonic()
            timestamp = datetime.now(timezone.utc).isoformat()
            trace, status, visible = '', 0, None
            try:
                with opener.open(target, timeout=10) as response:
                    status = response.status
                    trace = response.headers.get('X-Request-ID', '')
                    response.read(4096)
                if status != 200 or not re.fullmatch('[a-fA-F0-9]{32}', trace):
                    raise ValueError('Probe did not return a valid trace')
                query = {'size': 1, '_source': False, 'query': {'term': {'trace.id': trace}}}
                while time.monotonic() - started <= 25:
                    result = subprocess.run(['ssh', *ssh_options,
                        '-o', 'ConnectTimeout=8', 'ubuntu@' + monitor, 'python3 -c ' + shlex.quote(REMOTE)],
                        input=json.dumps(query), capture_output=True, text=True, timeout=18)
                    if result.returncode:
                        raise RuntimeError('Monitor query failed; credentials intentionally omitted')
                    if json.loads(result.stdout)['found']:
                        visible = round(time.monotonic() - started, 3)
                        break
                    time.sleep(1)
            except (OSError, ValueError, RuntimeError, urllib.error.HTTPError, subprocess.TimeoutExpired):
                pass
            row = dict(sample=index + 1, started_at=timestamp, trace_id=trace,
                       http_status=status, visible_seconds='' if visible is None else visible,
                       passed=status == 200 and visible is not None and visible <= 15)
            results.append(row)
            writer.writerow(row)
            stream.flush()
            print(f"Sample {index + 1}/{args.samples}: {'PASS' if row['passed'] else 'FAIL'}", flush=True)
            time.sleep(1)
    values = [row['visible_seconds'] for row in results if row['visible_seconds'] != '']
    summary = dict(environment='AWS', samples=args.samples, passed=all(row['passed'] for row in results),
        method='Request initiation to first Elasticsearch search hit including SSH query overhead',
        percentile_method='nearest_rank', p50_seconds=percentile(values, .5), p95_seconds=percentile(values, .95),
        failed_samples=sum(not row['passed'] for row in results), target=target, raw_csv=str(dest))
    with dest.with_suffix('.summary.json').open('x') as stream:
        json.dump(summary, stream, indent=2)
    print(json.dumps(summary))
    if not summary['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
