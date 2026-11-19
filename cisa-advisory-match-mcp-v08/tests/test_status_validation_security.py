"""Malformed source status must fail closed, not become a negative match."""
import unittest
from test_matching import document, inventory
from advisory_matcher.matching import match_device

class StatusValidationTests(unittest.TestCase):
    def test_non_object_vulnerability_does_not_disappear(self):
        source = document(); source['vulnerabilities'] = [None]
        with self.assertRaises(ValueError): match_device(inventory(), source)

    def test_malformed_product_status_does_not_disappear(self):
        for statuses in (None, [], {'known_affected': 'p1'},
                         {'known_affected': ['other', None]},
                         {'known_affected': ['other', '']},
                         {'known_affected': ['other', {'id':'p1'}]}):
            source = document(); source['vulnerabilities'][0]['product_status'] = statuses
            with self.subTest(statuses=statuses):
                with self.assertRaises(ValueError): match_device(inventory(), source)

    def test_other_product_valid_status_still_returns_no_finding(self):
        source = document(statuses={'known_affected':['other']})
        self.assertEqual(match_device(inventory(), source), [])

    def test_empty_status_object_is_uncertain_not_negative(self):
        source = document(statuses={})
        self.assertEqual(match_device(inventory(), source)[0]['assessment'], 'needs_review')

if __name__ == '__main__': unittest.main()
