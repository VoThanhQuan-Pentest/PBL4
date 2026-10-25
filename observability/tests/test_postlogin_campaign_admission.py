from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from postlogin_campaign_admission import capacity_screen
from postlogin_preparation_audit import full_population
from app.postlogin_contract import source_protocol


class CapacityTest(unittest.TestCase):
    def test_population_shared_normal_and_fixed_phase_limits(self):
        rows = capacity_screen(source_protocol('postlogin-lab-strict-v2-20261021'),
                               {k: .24 for k in full_population()})
        self.assertEqual(sum(r['rows'] for r in rows), 19257500)
        self.assertEqual(rows[0]['rows'], 81500)
        self.assertEqual(rows[1]['fixed_collection_seconds'], 3 * 86400)
        self.assertFalse(rows[1]['single_serial_producer_fits_window'])
        self.assertEqual(rows[1]['arithmetic_concurrency_lower_bound_not_verified_speedup'], 3)
        self.assertEqual(rows[-1]['fixed_collection_seconds'], 14 * 86400)
        self.assertIsNone(rows[0]['single_serial_producer_fits_window'])

    def test_missing_or_nonfinite_measurements_cannot_admit_a_schedule(self):
        protocol = source_protocol('postlogin-lab-strict-v2-20261021')
        with self.assertRaises(ValueError):capacity_screen(protocol, {})
        values = {k: .2 for k in full_population()};values['COLD/normal'] = float('nan')
        with self.assertRaises(ValueError):capacity_screen(protocol, values)


if __name__ == '__main__':
    unittest.main()
