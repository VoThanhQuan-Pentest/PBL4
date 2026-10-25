import csv
import importlib.util
import io
import itertools
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, call, patch


ROOT = Path(__file__).resolve().parents[2]


def load_harness():
    spec = importlib.util.spec_from_file_location(
        'measure_aws_access_latency',
        ROOT / 'observability/scripts/measure-aws-access-latency.py',
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AwsAccessLatencyTest(unittest.TestCase):
    def test_default_and_explicit_100_samples_preserve_probe_bounds(self):
        for arguments, samples in (([], 100), (['--samples', '100'], 100),
                                   (['--samples', '30'], 30)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as directory:
                module = load_harness()
                dest = Path(directory) / 'mock-access-latency.csv'
                opener = MagicMock()
                response = opener.open.return_value.__enter__.return_value
                response.status = 200
                response.headers = {'X-Request-ID': 'a' * 32}
                outputs = json.dumps({
                    'web_elastic_ip': {'value': '192.0.2.10'},
                    'monitor_elastic_ip': {'value': '192.0.2.20'},
                })
                ticks = itertools.count()
                with patch.object(sys, 'argv', ['measure-aws-access-latency', *arguments,
                                               '--output', str(dest)]), \
                        patch.object(module.subprocess, 'check_output', return_value=outputs), \
                        patch.object(module.subprocess, 'run', return_value=SimpleNamespace(
                            returncode=0, stdout='{"found": true}')) as remote, \
                        patch.object(module.urllib.request, 'build_opener', return_value=opener), \
                        patch.object(module.time, 'monotonic', side_effect=lambda: next(ticks) / 10), \
                        patch.object(module.time, 'sleep') as sleep, \
                        patch.object(module.os, 'umask'), \
                        patch('builtins.print'):
                    module.main()

                with dest.open(newline='') as stream:
                    rows = list(csv.DictReader(stream))
                summary = json.loads(dest.with_suffix('.summary.json').read_text())
                self.assertEqual(len(rows), samples)
                self.assertEqual([int(row['sample']) for row in rows], list(range(1, samples + 1)))
                self.assertEqual(summary['samples'], samples)
                self.assertEqual(summary['failed_samples'], 0)
                self.assertTrue(summary['passed'])
                self.assertEqual(opener.open.call_args_list,
                                 [call('http://192.0.2.10/api/health', timeout=10)] * samples)
                self.assertEqual(remote.call_count, samples)
                for invocation in remote.call_args_list:
                    self.assertIn('ConnectTimeout=8', invocation.args[0])
                    self.assertIn('ubuntu@192.0.2.20', invocation.args[0])
                    self.assertEqual(invocation.kwargs['timeout'], 18)
                    self.assertEqual(json.loads(invocation.kwargs['input'])['query'],
                                     {'term': {'trace.id': 'a' * 32}})
                self.assertEqual(sleep.call_args_list, [call(1)] * samples)

    def test_out_of_bounds_samples_fail_before_any_external_operation(self):
        for value in ('-1', '0', '29', '101', '100000', 'invalid'):
            with self.subTest(samples=value):
                module = load_harness()
                with patch.object(sys, 'argv', ['measure-aws-access-latency', '--samples', value]), \
                        patch.object(module.subprocess, 'check_output') as outputs, \
                        patch.object(module.subprocess, 'run') as remote, \
                        patch.object(module.urllib.request, 'build_opener') as opener, \
                        patch('sys.stderr', new=io.StringIO()), \
                        self.assertRaises(SystemExit) as exit_result:
                    module.main()
                self.assertEqual(exit_result.exception.code, 2)
                outputs.assert_not_called()
                remote.assert_not_called()
                opener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
