from datetime import datetime, timedelta, timezone
import unittest
from nvd_feed import validate_metadata


class NvdFeedTest(unittest.TestCase):
    def test_recent_official_metadata_is_required(self):
        now = datetime(2026, 10, 26, tzinfo=timezone.utc)
        def metadata(age):
            return 'lastModifiedDate:' + (now-age).isoformat() + '\nsha256:' + 'a'*64
        self.assertEqual((now-timedelta(hours=12)).isoformat(), validate_metadata(metadata(timedelta(hours=12)), now))
        for age in (timedelta(hours=49), -timedelta(minutes=3)):
            with self.assertRaises(ValueError): validate_metadata(metadata(age), now)
        with self.assertRaises(ValueError): validate_metadata('lastModifiedDate:2026-10-26T00:00:00Z', now)
