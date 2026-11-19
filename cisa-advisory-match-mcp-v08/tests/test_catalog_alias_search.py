import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from advisory_matcher.aliases import AliasCatalog
from advisory_matcher.catalog_index import build_catalog, search_catalog


def mapping(id, names, mode='equivalent', vendors=None):
    result={'id':id,'names':names,'mode':mode,'source_urls':['https://example.org/reference'],
            'rationale':'Documented test name.','source_title':'Test reference'}
    if vendors is not None:
        result['vendors']=vendors
    return result


def record(vendor, product, ident):
    return {'category':'vendor','name':vendor,'branches':[{'category':'product_name','name':product,
        'product':{'product_id':ident,'name':product}}]}


class CatalogAliasSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        root=Path(self.tmp.name)/'source'
        self.db=Path(self.tmp.name)/'catalog.sqlite3'
        branches=[record('Acme','Server Old','p1'),record('Acme','Server New','p2'),
                  record('Acme Incorporated','Server New','p3'),record('Other','Server Old','p4')]
        doc={'document':{'title':'A','tracking':{'id':'sample'}},'product_tree':{'branches':branches}}
        for scope in ('IT','OT'):
            folder=root/'csaf_files'/scope/'white'; (folder/'2026').mkdir(parents=True)
            (folder/'2026'/'sample.json').write_text(json.dumps(doc));(folder/'index.txt').write_text('2026/sample.json\n')
        build_catalog(root,self.db)
        data={'schema_version':1,'version':'test','vendors':[
            mapping('vendor-acme',['Acme','Acme Incorporated'])],
            'products':[mapping('product-old',['Server New','Server Old'],'candidate',['Acme']),
                        mapping('product-next',['Server Old','Server Ancient'],'candidate',['Acme'])]}
        self.catalog=AliasCatalog(data)
        self.mock=patch('advisory_matcher.aliases.get_catalog',return_value=self.catalog)
        self.mock.start()

    def tearDown(self):
        self.mock.stop();self.tmp.cleanup()

    def test_scoped_direct_alias_with_provenance_and_literal_first(self):
        result=search_catalog(self.db,'Server New','Acme',scope='IT',limit=3)
        self.assertEqual(result['candidate_count'],3)
        self.assertEqual(result['candidates'][0]['product_id'],'p2')
        self.assertEqual(result['candidates'][0]['match_basis'],'normalized literal phrase')
        alias=result['candidates'][2]
        self.assertEqual(alias['product_id'],'p1')
        self.assertEqual(alias['match_basis'],'documented alias phrase')
        self.assertTrue(alias['identity_review_required'])
        self.assertEqual(alias['alias_mappings'][0]['mode'],'candidate')
        self.assertEqual(alias['alias_mappings'][0]['source_urls'],['https://example.org/reference'])
        self.assertEqual(result['candidates_omitted'],0)
        self.assertEqual(result['applicability'],'not_assessed')
        self.assertFalse(result['coverage_complete'])

    def test_vendor_alias_does_not_expand_to_other_vendor(self):
        r=search_catalog(self.db,'Server New','Acme Incorporated',scope='IT')
        self.assertEqual({x['product_id'] for x in r['candidates']},{'p1','p2','p3'})
        self.assertNotIn('p4',{x['product_id'] for x in r['candidates']})

    def test_no_manufacturer_no_alias_and_no_transitive_expansion(self):
        r=search_catalog(self.db,'Server New',scope='IT')
        self.assertEqual({x['product_id'] for x in r['candidates']},{'p2','p3'})
        ancient=search_catalog(self.db,'Server Ancient','Acme',scope='IT')
        self.assertEqual({x['product_id'] for x in ancient['candidates']},{'p1'})

    def test_ambiguous_vendor_is_reviewed_and_not_chained_with_product_alias(self):
        data={'schema_version':1,'version':'test','vendors':[
            mapping('vendor-acme',['Acme','Acme Incorporated'],'candidate')],
            'products':[mapping('product-old',['Server New','Server Old'],'candidate',['Acme'])]}
        with patch('advisory_matcher.aliases.get_catalog',return_value=AliasCatalog(data)):
            result=search_catalog(self.db,'Server New','Acme Incorporated',scope='IT')
        self.assertEqual({x['product_id'] for x in result['candidates']},{'p2','p3'})
        vendor_lead=next(x for x in result['candidates'] if x['product_id']=='p2')
        self.assertTrue(vendor_lead['identity_review_required'])
        self.assertEqual(vendor_lead['alias_mappings'][0]['mode'],'candidate')

    def test_bare_product_phrase_matches_full_product_name(self):
        r=search_catalog(self.db,'Server','Acme',scope='IT',limit=1)
        self.assertEqual(len(r['candidates']),1)
        self.assertEqual(r['candidate_count'],3)
        self.assertEqual(r['candidates_omitted'],2)

if __name__=='__main__': unittest.main()
