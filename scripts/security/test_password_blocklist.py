import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PasswordCorpusTest(unittest.TestCase):
    def test_packaged_lookup_is_complete_sorted_and_matches_its_pinned_provenance(self):
        binary = (ROOT/'backend/src/main/resources/security/password-blocklist.bin').read_bytes()
        metadata = json.loads((ROOT/'security/passwords/source.json').read_text())
        self.assertEqual(metadata['sha256'], hashlib.sha256(binary).hexdigest())
        self.assertEqual(metadata['bytes'], len(binary))
        self.assertEqual(0, len(binary) % 32)
        digests = [binary[i:i+32] for i in range(0, len(binary), 32)]
        self.assertEqual(metadata['entries'], len(digests))
        self.assertEqual(sorted(set(digests)), digests)
        self.assertGreaterEqual(next(s['eligible_entries'] for s in metadata['sources'] if s['name'] == 'xato'), 3000)
        self.assertIn(hashlib.sha256(b'123456789012').digest(), digests)
        self.assertTrue(any('/Leaked-Databases/' in s['url'] for s in metadata['sources']))
        self.assertIn('MIT License', (ROOT/'security/passwords/LICENSE-SecLists').read_text())
