import sys
import json
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import auth_context_research_v2 as research


class ResearchCorpusTests(unittest.TestCase):
    def setUp(self):
        research.source.ANCHORS = research.ANCHORS

    def test_quotas_and_normal_groups_are_preregistered(self):
        for split, (normal, behavior, operational) in research.QUOTAS.items():
            entries = research.labels(split)
            self.assertEqual(entries, research.labels(split))
            counts = Counter(kind for kind, _ in entries)
            if split == 'controls':
                self.assertEqual(counts, {'cold': normal, 'missing': behavior})
            else:
                self.assertEqual(counts, {'routine': normal, 'case3': behavior // 3,
                                          'case4': behavior // 3, 'case5': behavior // 3,
                                          'operational': operational})
                self.assertEqual(set(recipe for kind, recipe in entries if kind == 'routine'), set(research.KINDS))
                self.assertEqual(len(set(Counter(recipe for kind, recipe in entries if kind == 'routine').values())), 1)

    def test_split_identity_chronology_and_normal_scenarios(self):
        accounts = []
        for split in research.QUOTAS:
            groups = {research.frame(split, i, 'routine', 'browse')[1]['account_group'] for i in range(256)}
            self.assertEqual(len(groups), 256)
            self.assertTrue(all(groups.isdisjoint(existing) for existing in accounts))
            accounts.append(groups)
        for earlier, later in zip(research.ANCHORS.values(), list(research.ANCHORS.values())[1:]):
            self.assertGreaterEqual((later - earlier).days, 15)
        for recipe in research.KINDS:
            raw, metadata = research.frame('train', 1, 'routine', recipe)
            self.assertEqual(raw['attempt']['actor_user_id'], metadata['account_group'])
            self.assertEqual(metadata['recipe'], recipe)
            self.assertTrue(all(e['event_timestamp'] < raw['attempt']['event_timestamp'] for e in raw['context']))
            self.assertNotIn('context_label', raw)

    def test_smoke_namespace_differs(self):
        self.assertNotEqual(research.frame('train', 0, 'routine', 'browse')[1]['episode_id'],
                            research.frame('train', 0, 'routine', 'browse', True)[1]['episode_id'])

    def test_protocol_round_trip_preserves_identity_and_detects_changes(self):
        with patch.object(research, 'classpath_fingerprint', return_value=[]):
            original = research.protocol('unused')
        restored = json.loads(json.dumps(original))
        self.assertTrue(research.same_protocol(original, restored))
        restored['maximum_classifier_fits'] = 5
        self.assertFalse(research.same_protocol(original, restored))

    def test_capture_rejects_path_outside_research_root(self):
        with self.assertRaisesRegex(RuntimeError, 'research root'):
            research.safe_output(Path('/tmp/not-a-research-capture'))
        with self.assertRaisesRegex(RuntimeError, 'research root'):
            research.safe_output(research.RESEARCH_ROOT / '..' / 'escape')


if __name__ == '__main__':
    unittest.main()
