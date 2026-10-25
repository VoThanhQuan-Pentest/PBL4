"""Bounded real Java fixture/resume tests; no full corpus, model or holdout."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/generate-ueba-hybrid-strict.py'
SPEC = importlib.util.spec_from_file_location('isolated_full_strict_writer', PATH)
writer = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = writer; SPEC.loader.exec_module(writer)


class StrictWriterTest(unittest.TestCase):
    def test_adapter_holdout_projection_and_final_view_never_parse_numeric_json(self):
        from unittest.mock import Mock
        blob = b'NOT_JSON_BUT_CHECKSUM_BOUND_UNOPENED_BYTES'
        checksum = hashlib.sha256(blob).hexdigest()
        descriptor = {'id': 'holdout-fixture-000000', 'path': 'shards/holdout-fixture-000000.json', 'sha256': checksum}
        class Original:
            def split(self, name): return {'shards': [descriptor]}
            def _read(self, path, maximum): return blob
            def iter_shards(self, name): yield ('normal-fixture', [{'fully_validated': True}])
        producer = SimpleNamespace(ShardedDataset=Original, promote=Mock(), MAX_SHARD_BYTES=1000,
            hashlib=hashlib, read_file=lambda path, maximum: blob, digest=lambda path: checksum)
        writer.blind_standard_final_view(producer)
        view = producer.ShardedDataset()
        self.assertEqual(list(view.iter_shards('holdout')), [])
        self.assertEqual(list(view.iter_shards('fold1-fit')), [('normal-fixture', [{'fully_validated': True}])])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'shards').mkdir(); committed = root / 'committed'; committed.mkdir()
            (committed / (descriptor['id'] + '.json')).write_bytes(blob)
            producer.promote(root, committed, {'split': 'holdout', 'shards': [descriptor]})
            self.assertEqual((root / descriptor['path']).read_bytes(), blob)
        producer.promote(root, committed, {'split': 'fold1-fit', 'shards': []})

    def test_host_refused_before_generation(self):
        with patch.dict(os.environ, {'UEBA_DIAGNOSTIC_IMAGE_ID': ''}), patch.object(writer.prep, 'frozen_producer') as producer:
            with self.assertRaises(ValueError): writer.run('fresh-hybrid-test-a01', Path('/unavailable'))
        producer.assert_not_called()

    def test_actual_three_fold_java_interrupted_pending_resumes_and_refuses_tamper(self):
        if os.environ.get('UEBA_DIAGNOSTIC_IMAGE_ID') != writer.prep.IMAGE:
            self.skipTest('explicit pinned Java fixture invocation required')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'owned'
            with self.assertRaisesRegex(RuntimeError, 'interruption before commit'):
                writer.run('fresh-hybrid-test-a01', output, scoped_test=True, interrupt_after_export=True)
            self.assertTrue(list((output / 'labels-fold1/pending').iterdir()))
            result = writer.run('fresh-hybrid-test-a01', output, scoped_test=True, resume=True)
            self.assertEqual(result['status'], 'COMPLETE_UNQUALIFIED_SCOPED_TEST')
            self.assertEqual(result['folds_completed'], [1, 2, 3])
            self.assertEqual(result['holdout_numeric_records_read'], 0)
            self.assertTrue(list((output / 'labels-fold1/abandoned').iterdir()))
            producer = writer.prep.frozen_producer()
            for fold in (1, 2, 3):
                root = output / f'labels-fold{fold}'
                manifest_path = root / 'manifest.private.json'
                normal, labeled, manifest = writer.load_hybrid_strict_fit(root, producer.digest(manifest_path), allow_scoped_test=True)
                self.assertEqual((len(normal), len(labeled)), (2, 5))
                self.assertTrue(manifest['isolation_proof']['actual_score_only_splits_scanned'])
                with self.assertRaises(ValueError): writer.load_hybrid_strict_fit(root, producer.digest(manifest_path))
            self.assertEqual(writer.run('fresh-hybrid-test-a01', output, scoped_test=True, resume=True)['folds_completed'], [1, 2, 3])
            shard = next((output / 'labels-fold1/supplement').glob('*.json'))
            with shard.open('ab') as stream: stream.write(b' ')
            with self.assertRaises(ValueError): writer.run('fresh-hybrid-test-a01', output, scoped_test=True, resume=True)


if __name__ == '__main__': unittest.main()
