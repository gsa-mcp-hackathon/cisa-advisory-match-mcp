"""Release-line ambiguity must not turn a numeric comparison into a finding."""
import unittest
from test_matching import document, inventory
from advisory_matcher.matching import match_device


class VersionSeriesSafetyTests(unittest.TestCase):
    def test_multiple_one_sided_release_limits_need_review(self):
        source = document([('p1', 'vers:intdot/<8.2.35'),
                           ('p2', 'vers:intdot/<8.3.36'),
                           ('p3', 'vers:intdot/<8.4.23')])
        for version in ('8.2.34', '8.2.35', '8.3.36', '8.5.0', '7.4.0'):
            with self.subTest(version=version):
                result = match_device(inventory(version), source)[0]
                self.assertEqual(result['assessment'], 'needs_review')
                self.assertFalse(result['cvss'])
                self.assertTrue(all(item['assessment'] == 'needs_review' for item in result['evidence']))
                self.assertIn('release', result['evidence'][0]['reason'])

    def test_multiple_lower_bounds_also_need_review(self):
        source = document([('p1', '>=3.2'), ('p2', '>=4.1')])
        self.assertEqual(match_device(inventory('4.2'), source)[0]['assessment'], 'needs_review')

    def test_separately_bounded_intervals_still_work(self):
        source = document([('p1', 'vers:intdot/>=1|<2'), ('p2', 'vers:intdot/>=3|<4')])
        self.assertEqual(match_device(inventory('3.2'), source)[0]['assessment'], 'affected_range_match')
        self.assertEqual(match_device(inventory('2.5'), source)[0]['assessment'], 'outside_affected_range')

    def test_distinct_ids_with_same_boundary_do_not_invent_ambiguity(self):
        source = document([('p1', '<4'), ('p2', '<4')])
        self.assertEqual(match_device(inventory('3.2'), source)[0]['assessment'], 'affected_range_match')


if __name__ == '__main__':
    unittest.main()
