import unittest
from advisory_matcher.it_index import search_snapshot


def document():
    return {'document': {'tracking': {'id': 'VA-26-295-01'}},
            'product_tree': {'branches': [{'category':'vendor', 'name':'Acme', 'branches': [
                {'category':'product_name', 'name':'Control Server', 'branches': [
                    {'category':'product_version', 'name':'8.2', 'product': {'product_id':'p1', 'name':'Acme Control Server 8.2'}},
                    {'category':'product_version', 'name':'8.3', 'product': {'product_id':'p2', 'name':'Acme Control Server 8.3'}}]}]}]},
            'vulnerabilities': [{'cve':'CVE-2026-1234','product_status': {'known_affected':['p1'], 'fixed':['p2']}}]}

class IndexTests(unittest.TestCase):
    def test_candidate_statuses_are_source_data_not_applicability(self):
        r=search_snapshot([document()], 'ACME', 'control-server')
        self.assertEqual(r['candidate_count'], 2)
        self.assertEqual(r['candidates'][0]['direct_source_statuses'][0]['status'], 'known_affected')
        self.assertEqual(r['candidates'][1]['direct_source_statuses'][0]['status'], 'fixed')
        self.assertEqual(r['applicability'], 'not_assessed')
        self.assertEqual(r['corpus_coverage'], 'unknown')

    def test_no_result_never_claims_absence(self):
        r=search_snapshot([document()], 'wrong', 'control')
        self.assertEqual(r['candidate_count'], 0)
        self.assertIn('does not mean no advisory', r['warning'])

    def test_bad_records_are_counted_and_not_partially_indexed(self):
        d=document();d['product_tree']['branches'].append({'category':'bad'})
        r=search_snapshot([d, document()], 'acme', 'server')
        self.assertEqual((r['documents_checked'], r['documents_skipped']), (1,1))
        self.assertEqual(r['candidate_count'], 2)

    def test_relationship_and_result_caps_are_reported(self):
        d=document();d['product_tree']['relationships']=[{'x':'y'}]
        r=search_snapshot([d]*30, 'acme','server')
        self.assertEqual(r['documents_with_unhandled_relationships_or_flat_products'],30)
        self.assertEqual((len(r['candidates']),r['candidates_omitted']),(50,10))

    def test_queries_are_bounded(self):
        for query in ('', ' '*20, 'x'*121, None):
            with self.assertRaises(ValueError): search_snapshot([document()], query, 'server')
        with self.assertRaises(ValueError): search_snapshot([document()]*501, 'a','b')

    def test_vendor_token_boundaries(self):
        self.assertEqual(search_snapshot([document()], 'ac', 'server')['candidate_count'], 0)

if __name__ == '__main__': unittest.main()
