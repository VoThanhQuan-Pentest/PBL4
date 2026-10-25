"""Real loopback HTTP tests with the exported model; all fit methods forbidden."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from app.postlogin_contract import FEATURE_NAMES, EVALUATION_UNIT


@unittest.skipUnless(os.environ.get('POSTLOGIN_TEST_MODEL_DIR'), 'requires explicit fixed-model export, never fits fixtures')
class PostloginServingTest(unittest.TestCase):
    serving_only = False
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory();root = Path(cls.temp.name)
        cls.directory = root / 'model';shutil.copytree(os.environ['POSTLOGIN_TEST_MODEL_DIR'], cls.directory)
        cls.token = 'postlogin-zero-fit-http-test-token-0000000001'
        token = root / 'token';token.write_text(cls.token);token.chmod(0o600)
        models = root / 'legacy-models';models.mkdir(mode=0o700)
        with socket.socket() as probe:probe.bind(('127.0.0.1', 0));cls.port = probe.getsockname()[1]
        cls.base = f'http://127.0.0.1:{cls.port}'
        env = os.environ.copy();env.update(UEBA_POSTLOGIN_SERVING_ONLY=str(cls.serving_only).lower(),
            UEBA_SERVICE_TOKEN_FILE=str(token), UEBA_MODEL_DIR=str(models),
            UEBA_POSTLOGIN_MODEL_DIR=str(cls.directory),
            UEBA_POSTLOGIN_MANIFEST_SHA256=hashlib.sha256((cls.directory / 'manifest.json').read_bytes()).hexdigest())
        program = """from sklearn.ensemble import HistGradientBoostingClassifier
from app.normal_support import NormalSupportScorer
def forbidden(*args,**kwargs):raise AssertionError('HTTP_SERVING_ATTEMPTED_FIT')
HistGradientBoostingClassifier.fit=forbidden
NormalSupportScorer.fit=forbidden
import uvicorn
uvicorn.run('app.main:app',host='127.0.0.1',port=PORT,workers=1,log_level='error')
""".replace('PORT', str(cls.port))
        cls.process = subprocess.Popen([sys.executable, '-c', program], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(150):
                if cls.process.poll() is not None:raise RuntimeError('test worker exited')
                try:
                    with urllib.request.urlopen(cls.base + '/health', timeout=1) as response:
                        if json.loads(response.read())['postlogin']['available']:return
                except (urllib.error.URLError, TimeoutError):pass
                time.sleep(.1)
            raise RuntimeError('test worker startup deadline')
        except Exception:
            cls.process.terminate();cls.process.wait(timeout=10);cls.temp.cleanup();raise

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate();cls.process.wait(timeout=10);cls.temp.cleanup()

    def snapshot(self):
        values = [0.] * 65;values[37] = values[39] = 1.
        return {'snapshot_id': 'http-project-snapshot-001', 'evaluation_unit': EVALUATION_UNIT,
                'feature_schema_version': 6, 'feature_names': list(FEATURE_NAMES), 'features': values,
                'as_of': datetime.now(timezone.utc).isoformat(), 'baseline_established': False,
                'trusted_window_count': 0}

    def request(self, path='/internal/v1/postlogin/score', payload=None, authenticated=True):
        headers = {'Content-Type': 'application/json'}
        if authenticated:headers['X-UEBA-Token'] = self.token
        body = None if payload is None else json.dumps(payload).encode()
        with urllib.request.urlopen(urllib.request.Request(self.base + path, data=body, headers=headers), timeout=10) as response:
            return json.loads(response.read())

    def test_fixed_model_scoring_and_legacy_health_are_separate(self):
        health = self.request('/health')
        self.assertEqual(health['supported_feature_schemas'], [1, 2, 3, 4])
        self.assertFalse(health['model_available']);self.assertTrue(health['postlogin']['available'])
        result = self.request(payload={'snapshots': [self.snapshot()]})
        self.assertEqual(result['qualification_scope'], 'PROJECT_LIMITED')
        self.assertEqual(result['feature_schema_version'], 6)
        row = result['assessments'][0]
        self.assertEqual(row['snapshot_id'], self.snapshot()['snapshot_id'])
        self.assertEqual(row['cohort'], 'COLD');self.assertEqual(row['threshold'], 99.9995)
        self.assertLessEqual(row['normal_percentile'], 100)
        self.assertNotIn('probability_of_compromise', row)

    def test_authentication_required(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(payload={'snapshots': [self.snapshot()]}, authenticated=False)
        self.assertEqual(error.exception.code, 403)

    def test_snapshot_rejects_outcomes_wrong_width_future_and_duplicate_ids(self):
        for change in [{'features': [0.] * 61}, {'otp': 'not-a-code'}, {'baseline_established': True},
                       {'features': [float('nan')] * 65},
                       {'as_of': (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}]:
            with self.subTest(fields=tuple(change)), self.assertRaises(urllib.error.HTTPError) as error:
                self.request(payload={'snapshots': [self.snapshot() | change]})
            self.assertEqual(error.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(payload={'snapshots': [self.snapshot(), self.snapshot()]})
        self.assertEqual(error.exception.code, 400)

    def test_batch_and_legacy_schema_limits(self):
        for snapshots in [[], [self.snapshot()] * 33]:
            with self.assertRaises(urllib.error.HTTPError) as error:self.request(payload={'snapshots': snapshots})
            self.assertEqual(error.exception.code, 422)
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/internal/v1/score', {'feature_schema_version': 6, 'feature_names': list(FEATURE_NAMES), 'vectors': [[0.] * 65]})
        self.assertEqual(error.exception.code, 422)

    def test_streaming_body_limit_including_chunked_requests(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            connection.putrequest('POST', '/internal/v1/postlogin/score')
            connection.putheader('Content-Length', str(512 * 1024 + 1));connection.endheaders()
            response = connection.getresponse();self.assertEqual(response.status, 413);response.read()
        finally:connection.close()
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            connection.request('POST', '/internal/v1/postlogin/score', body=(b'x' * 65536 for _ in range(9)),
                               headers={'Content-Type': 'application/json'}, encode_chunked=True)
            response = connection.getresponse();self.assertEqual(response.status, 413);response.read()
        finally:connection.close()

    def test_tampered_publication_fails_closed_without_mutating_source(self):
        path = self.directory / 'model-state.json';original = path.read_bytes()
        try:
            path.write_bytes(original + b' ')
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(payload={'snapshots': [self.snapshot()]})
            self.assertEqual(error.exception.code, 503)
            self.assertFalse(self.request('/health')['postlogin']['available'])
        finally:path.write_bytes(original)
        self.assertEqual(len(self.request(payload={'snapshots': [self.snapshot()]})['assessments']), 1)


class PostloginServingOnlyTest(PostloginServingTest):
    serving_only = True

    def test_batch_and_legacy_schema_limits(self):
        for snapshots in [[], [self.snapshot()] * 33]:
            with self.assertRaises(urllib.error.HTTPError) as error:self.request(payload={'snapshots': snapshots})
            self.assertEqual(error.exception.code, 422)
        for path in ['/internal/v1/train', '/internal/v1/train-catalog', '/internal/v1/activate', '/internal/v1/score']:
            with self.assertRaises(urllib.error.HTTPError) as error:self.request(path, {})
            self.assertEqual(error.exception.code, 404)
        self.assertTrue(self.request('/health')['serving_only'])
        self.assertFalse(any((Path(self.temp.name) / 'legacy-models').iterdir()))


if __name__ == '__main__':unittest.main()
