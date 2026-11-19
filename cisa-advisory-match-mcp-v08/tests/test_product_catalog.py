import json, tempfile, unittest
from pathlib import Path
from advisory_matcher.catalog_index import build_catalog, search_catalog

def advisory():
    return {'document': {'title':'Example advisory','tracking':{'id':'sample'}}, 'product_tree': {'branches': [{'category':'vendor','name':'Acme','branches':[{'category':'product_name','name':'Control Server','branches':[{'category':'product_version','name':'1.2','product':{'product_id':'p1','name':'Acme Control Server 1.2'}}]}]}]}}

class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name)/'source';self.dest=Path(self.t.name)/'catalog.sqlite3'
        for scope in ('IT','OT'):
            folder=self.root/'csaf_files'/scope/'white';(folder/'2026').mkdir(parents=True)
            (folder/'2026'/'sample.json').write_text(json.dumps(advisory()))
            (folder/'index.txt').write_text('2026/sample.json\n')
    def tearDown(self): self.t.cleanup()
    def test_index_and_retrieve_candidates_both_sources(self):
        manifest=build_catalog(self.root,self.dest,revision='a'*40);self.assertEqual(manifest['sources']['IT']['indexed'],1)
        r=search_catalog(self.dest,'control server','acme');self.assertEqual(r['candidate_count'],2)
        self.assertEqual(r['applicability'],'not_assessed');self.assertFalse(r['coverage_complete']);self.assertIn('not verified',r['warning'])
    def test_reports_missing_and_unsafe_index_entries(self):
        folder=self.root/'csaf_files'/'IT'/'white';(folder/'index.txt').write_text('2026/sample.json\n2026/missing.json\n../secret.json\n2026/sample.json\n')
        m=build_catalog(self.root,self.dest);self.assertEqual((m['sources']['IT']['indexed'],m['sources']['IT']['failed']),(1,3))
    def test_human_review_for_complex_product_trees(self):
        folder=self.root/'csaf_files'/'IT'/'white';doc=advisory();doc['product_tree']['relationships']=[{'example':'unprocessed'}];(folder/'2026'/'sample.json').write_text(json.dumps(doc))
        m=build_catalog(self.root,self.dest);self.assertEqual(m['sources']['IT']['complex_documents'],1)
    def test_empty_query_and_scope_rejected(self):
        build_catalog(self.root,self.dest)
        for kwargs in ({'product':''},{'product':'  '},{'product':'server','scope':'X'},{'product':'server','limit':100}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):search_catalog(self.dest,**kwargs)
    def test_literal_token_boundary_and_filter(self):
        build_catalog(self.root,self.dest)
        self.assertEqual(search_catalog(self.dest,'control','ac')['candidate_count'],0)
        self.assertEqual(search_catalog(self.dest,'control','acme',scope='OT')['candidate_count'],1)
        self.assertEqual(search_catalog(self.dest,'missing')['candidate_count'],0)
    def test_result_limit_prefers_distinct_advisories_over_duplicate_rows(self):
        folder=self.root/'csaf_files'/'IT'/'white'; doc=advisory()
        versions=doc['product_tree']['branches'][0]['branches'][0]['branches']
        versions.append({'category':'product_version','name':'2.0','product':{'product_id':'p2','name':'Acme Control Server 2.0'}})
        (folder/'2026'/'sample.json').write_text(json.dumps(doc))
        other=advisory();other['document']['tracking']['id']='second'
        (folder/'2026'/'second.json').write_text(json.dumps(other))
        (folder/'index.txt').write_text('2026/sample.json\n2026/second.json\n')
        build_catalog(self.root,self.dest)
        result=search_catalog(self.dest,'Control Server','Acme',scope='IT',limit=2)
        self.assertEqual(result['candidate_count'],3)
        self.assertEqual([c['advisory_id'] for c in result['candidates']],['sample','second'])
        self.assertEqual(result['candidates_omitted'],1)
    def test_reject_duplicate_product_id_per_document(self):
        folder=self.root/'csaf_files'/'IT'/'white';doc=advisory();node=doc['product_tree']['branches'][0]['branches'][0]['branches'][0];node['branches']=[dict(node)];(folder/'2026'/'sample.json').write_text(json.dumps(doc))
        m=build_catalog(self.root,self.dest);self.assertEqual(m['sources']['IT']['failed'],1)
    def test_no_overwrite_or_missing_index(self):
        build_catalog(self.root,self.dest)
        with self.assertRaises(FileExistsError):build_catalog(self.root,self.dest)
        (self.root/'csaf_files'/'OT'/'white'/'index.txt').unlink()
        other=self.dest.with_name('other.db')
        with self.assertRaises(ValueError):build_catalog(self.root,other)
        self.assertFalse(other.exists())
    def test_reject_symlink_and_duplicate_json(self):
        folder=self.root/'csaf_files'/'IT'/'white';(folder/'2026'/'sample.json').write_text('{"document":{},"document":{}}')
        m=build_catalog(self.root,self.dest);self.assertEqual(m['sources']['IT']['failed'],1)

if __name__=='__main__':unittest.main()
