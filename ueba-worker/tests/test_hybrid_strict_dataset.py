"""Boundary controls only; SCOPED_TEST is never strict training admission."""
from pathlib import Path
import tempfile
import unittest

from app.hybrid_strict_dataset import private_read, validate_standard_manifest


class HybridStrictDatasetTest(unittest.TestCase):
    def test_reader_rejects_holdout_before_io(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in ('holdout.json', 'shards/holdout-000000.json', '../manifest.private.json'):
                with self.subTest(path=path), self.assertRaises(ValueError): private_read(Path(directory), path, 10)

    def test_pilot_cannot_become_full_strict_source(self):
        with self.assertRaises(ValueError):
            validate_standard_manifest({'dataset_id': 'fresh-hybrid-a01', 'feature_schema_version': 4,
                'telemetry_contract_version': 3, 'data_provenance': 'DEMO_ONLY', 'stage': 'PILOT'}, 'fresh-hybrid-a01')


if __name__ == '__main__': unittest.main()
