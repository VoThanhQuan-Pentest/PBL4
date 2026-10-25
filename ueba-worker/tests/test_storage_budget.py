from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.storage_budget import RESERVE_BYTES, require_headroom


class StorageBudgetTest(unittest.TestCase):
    def test_exact_boundary_and_missing_headroom_refuse_before_allocation(self):
        with patch('app.storage_budget.shutil.disk_usage', return_value=SimpleNamespace(free=RESERVE_BYTES + 128)):
            self.assertEqual(require_headroom(Path('/owned'), 128)['planned_bytes'], 128)
            with self.assertRaisesRegex(ValueError, 'reserve'):
                require_headroom(Path('/owned'), 129)

    def test_unbounded_or_noninteger_allocations_never_inspect_disk(self):
        with patch('app.storage_budget.shutil.disk_usage') as disk:
            for value in (-1, True, 1.0, 64 * 1024 ** 3 + 1):
                with self.assertRaises(ValueError): require_headroom(Path('/owned'), value)
            disk.assert_not_called()

    def test_reserve_is_not_silently_disabled_for_zero_allocation(self):
        with patch('app.storage_budget.shutil.disk_usage', return_value=SimpleNamespace(free=RESERVE_BYTES - 1)):
            with self.assertRaises(ValueError): require_headroom(Path('/owned'))


if __name__ == '__main__': unittest.main()
