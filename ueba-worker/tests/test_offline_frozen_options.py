"""Explicit offline bindings and whole-lifetime lock propagation, no holdout."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.frozen_evaluation import _evaluate, evaluate


class OfflineFrozenOptionsTest(unittest.TestCase):
    def test_stage_lock_spans_consumer_and_releases_on_failure(self):
        events = []
        @contextmanager
        def lock(directory, stage, *, enabled=False):
            self.assertEqual((directory, stage, enabled), (Path('/source/standard'), 'evaluation', True))
            events.append('locked')
            try:
                yield
            finally:
                events.append('released')
        def consumer(*args, **kwargs):
            self.assertEqual(events, ['locked'])
            self.assertEqual(kwargs, {'progress': None, 'expected_sha256': 'a' * 64,
                                      'expected_archive_sha256': 'b' * 64})
            raise ValueError('fixture consumer failure')
        with patch('app.pipeline_lock.coordinated_stage', side_effect=lock), \
                patch('app.frozen_evaluation._evaluate', side_effect=consumer):
            with self.assertRaisesRegex(ValueError, 'fixture consumer failure'):
                evaluate(Path('/source/standard'), Path('/java'), expected_sha256='a' * 64,
                         expected_archive_sha256='b' * 64, coordinated=True)
        self.assertEqual(events, ['locked', 'released'])

    def test_default_reader_is_unchanged_and_pilot_still_refused_before_holdout(self):
        dataset = SimpleNamespace(manifest={'stage': 'PILOT'})
        with patch('app.frozen_evaluation.ShardedDataset', return_value=dataset) as ordinary, \
                patch('app.owned_dataset.open_owned_dataset') as archived:
            with self.assertRaisesRegex(ValueError, 'pilot'):
                _evaluate(Path('/source/standard'), Path('/java'))
            ordinary.assert_called_once_with(Path('/source/standard'))
            archived.assert_not_called()

    def test_two_explicit_hashes_reach_factory_without_ordinary_fallback(self):
        dataset = SimpleNamespace(manifest={'stage': 'PILOT'})
        with patch('app.frozen_evaluation.ShardedDataset') as ordinary, \
                patch('app.owned_dataset.open_owned_dataset', return_value=dataset) as archived:
            with self.assertRaisesRegex(ValueError, 'pilot'):
                _evaluate(Path('/source/standard'), Path('/java'), expected_sha256='a' * 64,
                          expected_archive_sha256='b' * 64)
            archived.assert_called_once_with(Path('/source/standard'), expected_sha256='a' * 64,
                                             expected_archive_sha256='b' * 64)
            ordinary.assert_not_called()


if __name__ == '__main__':
    unittest.main()
