#!/usr/bin/env python3
"""Re-export every sealed raw episode with the candidate JDK21 backend classes before any model fit."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import subprocess
import time
import urllib.request


def run(data,classpath,jar_sha):
    manifest=json.loads((data/'manifest.json').read_bytes())
    if manifest.get('status')!='SOURCE_CAPTURE_COMPLETE' or manifest.get('records')!=100000:raise RuntimeError('Complete sealed source required')
    output=data/'producer-parity.json'
    if output.exists():raise RuntimeError('Parity receipt already exists')
    token=secrets.token_hex(24);key=data/'parity-token.private';key.write_text(token);key.chmod(0o600);count=0;started=time.monotonic()
    with (data/'parity-java.private.log').open('w') as error:
        process=subprocess.Popen(['java','-Xmx384m','-XX:ActiveProcessorCount=2','-cp',classpath,'com.flarefitness.backend.ops.AuthShadowLabCaptureServer',str(key)],stdout=subprocess.PIPE,stderr=error,text=True)
        try:
            if not select.select([process.stdout],[],[],20)[0]:raise RuntimeError('Producer startup deadline')
            port=json.loads(process.stdout.readline())['port'];url='http://127.0.0.1:'+str(port)+'/capture'
            for split,entry in manifest['splits'].items():
                for name,hash_key in [(entry['file'],'sha256'),(entry['raw_file'],'raw_sha256')]:
                    if hashlib.sha256((data/name).read_bytes()).hexdigest()!=entry[hash_key]:raise RuntimeError('Source bytes changed')
                with gzip.open(data/entry['file'],'rt',encoding='utf-8') as numeric,gzip.open(data/entry['raw_file'],'rt',encoding='utf-8') as raw:
                    for line in numeric:
                        row=json.loads(line);source=json.loads(raw.readline());assert row['episode_id']==source['episode_id']
                        body=json.dumps(source['raw'],separators=(',',':')).encode();request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','X-Lab-Token':token},method='POST')
                        with urllib.request.urlopen(request,timeout=15) as response:actual=json.loads(response.read(65536))
                        if actual['snapshot']!=row['snapshot'] or actual['status']!=row['status']:raise RuntimeError('Deployed producer numeric/schema/coverage parity differs')
                        count+=1
                        if time.monotonic()-started>5400:raise RuntimeError('Parity deadline')
                    if raw.read(1):raise RuntimeError('Raw source extra rows')
            if count!=100000:raise RuntimeError('Incomplete parity')
            value={'status':'DEPLOYED_PRODUCER_REEXPORT_PARITY_PASS','records':count,'application_jar_sha256':jar_sha,'feature_schema_version':7,'feature_count':81,'comparison':'all snapshot keys,65 prefix,16 new values and coverage','seconds':round(time.monotonic()-started,2),'model_fits':0,'evaluation_scores_opened':False}
            with output.open('x') as out:os.chmod(output,0o600);json.dump(value,out,indent=2);out.flush();os.fsync(out.fileno())
            print(json.dumps(value))
        finally:
            process.terminate()
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
            key.unlink(missing_ok=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',type=Path,required=True);p.add_argument('--java-classpath',required=True);p.add_argument('--application-jar-sha256',required=True);a=p.parse_args();run(a.data,a.java_classpath,a.application_jar_sha256)
