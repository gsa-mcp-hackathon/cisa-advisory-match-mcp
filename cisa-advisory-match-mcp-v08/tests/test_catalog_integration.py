"""Catalog policy regressions and independent, recorded CISA advisory cases.

Catalog pair tests establish implementation consistency, not field accuracy.
The four real advisory documents are small examples, not corpus validation.
"""
import asyncio
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path

import pytest

from advisory_matcher.aliases import get_catalog
from advisory_matcher.matching import match_device
from advisory_matcher.service import run_inventory
from fake_client import FakeClient, ADVISORY_ID

ROOT = Path(__file__).parents[1]
DATA = json.loads((ROOT / 'advisory_matcher/data/aliases.json').read_text())


def equivalent_cases():
    for category in ('vendors', 'products'):
        for record in DATA[category]:
            if record['mode'] != 'equivalent':
                continue
            for left, right in itertools.combinations(record['names'], 2):
                yield category, record, left, right


@pytest.mark.parametrize('category,record,left,right', list(equivalent_cases()), ids=lambda value: value.get('id') if isinstance(value, dict) else str(value))
def test_every_documented_equivalent_pair_resolves_without_historical_conflicts(category, record, left, right):
    catalog = get_catalog()
    if category == 'vendors':
        result = catalog.compare_identity(left, 'test-only exact model', right, 'test-only exact model')
    else:
        result = catalog.compare_identity(record['vendors'][0], left, record['vendors'][0], right)
    assert result['matched'] and not result['needs_review'], result
    assert result['match_type'] == 'verified_alias'
    assert result['mappings'] and all(m['source_urls'] for m in result['mappings'])


@pytest.mark.parametrize('filename,vendor,entered,canonical,version,expected', [
    ('icsa-23-150-01.json', 'Advantech', 'WebAccess SCADA', 'WebAccess/SCADA', '8.4.5', 'affected_range_match'),
    ('icsa-23-150-01.json', 'Advantech Co., Ltd.', 'Advantech WebAccess SCADA', 'WebAccess/SCADA', '8.4.5', 'affected_range_match'),
    ('icsa-24-086-04.json', 'Rockwell Automation', 'FactoryTalk View Machine Edition', 'FactoryTalk View ME', '13', 'affected_range_match'),
    ('icsa-25-028-04.json', 'Rockwell Automation', 'FactoryTalk View SE', 'FactoryTalk View Site Edition', '14.0', 'affected_range_match'),
    ('icsa-25-028-04.json', 'Rockwell Automation', 'RSView SE', 'FactoryTalk View Site Edition', '14.0', 'needs_review'),
])
def test_alias_matches_against_unchanged_real_csaf_documents(filename,vendor,entered,canonical,version,expected):
    doc = json.loads((ROOT / 'tests/fixtures' / filename).read_text())
    before = deepcopy(doc)
    item = {'asset_id':'fictional-alias-case','manufacturer':vendor,'product':entered,'version':version}
    results = match_device(item, doc)
    assert results and all(r['assessment'] == expected for r in results)
    entry = results[0]['evidence'][0]
    assert canonical in entry['model_names']
    assert entry['input_identity']['product'] == entered
    assert entry['identity_matches'][0]['mappings']
    if expected == 'needs_review':
        assert not results[0]['cvss']
    assert doc == before


@pytest.mark.parametrize('filename,vendor,product', [
    ('icsa-23-150-01.json','Advantech','WebAccess/CNC'),
    ('icsa-24-086-04.json','Rockwell Automation','FactoryTalk View SE'),
    ('icsa-25-028-04.json','Rockwell Automation','FactoryTalk View ME'),
    ('icsa-25-028-04.json','Schneider Electric','FactoryTalk View SE'),
])
def test_real_csaf_does_not_match_sibling_products_or_wrong_vendors(filename,vendor,product):
    doc=json.loads((ROOT/'tests/fixtures'/filename).read_text())
    assert match_device({'manufacturer':vendor,'product':product,'version':'13'},doc) == []


def test_discovery_uses_documented_vendor_alias_to_find_missed_original_name():
    class AliasOnlyClient(FakeClient):
        async def call_tool(self,name,args):
            result=await super().call_tool(name,args)
            if name=='cisa_search_ics_advisories' and args['vendor'] != 'Honeywell':
                return {'results':[],'hasMore':False,'totalCount':0}
            return result
    client=AliasOnlyClient()
    item={'asset_id':'fictional-alias-device','manufacturer':'Honeywell International','product':'IQ4E Firmware','version':'3.29'}
    report=asyncio.run(run_inventory([item],client))
    assert report['results'][0]['outcome']=='affected_range_match'
    assert report['results'][0]['manufacturer']=='Honeywell International'
    assert report['coverage']['alias_catalog']['sha256']
    assert any(args.get('vendor')=='Honeywell' for name,args in client.calls)
    assert '3.29' not in json.dumps(client.calls)
    assert 'fictional-alias-device' not in json.dumps(client.calls)


def test_omitted_vendor_terms_never_claim_complete_discovery():
    item={'asset_id':'fictional-device','manufacturer':'Schneider Electric','product':'unrecognized','version':'1'}
    report=asyncio.run(run_inventory([item],FakeClient()))
    assert report['coverage']['alias_expansions'][0]['omitted_terms']
    assert report['coverage']['candidate_selection_complete'] is False
    assert report['results'][0]['outcome']=='needs_review'


def test_input_hints_exist_without_advisory_identity_match():
    item={'asset_id':'fictional-device','manufacturer':'Schneider Electric','product':'PME','version':'1'}
    report=asyncio.run(run_inventory([item],FakeClient(),advisory_ids=[ADVISORY_ID]))
    assert report['results'][0]['name_hints']['mappings']
    assert report['results'][0]['findings']==[]


def test_alias_catalog_is_packaged_for_ibm(tmp_path):
    import subprocess,sys
    subprocess.run([sys.executable,str(ROOT/'scripts/package_runtime.py')],check=True,capture_output=True)
    packaged=ROOT/'dist/gsa_jc_inventory_advisory/advisory_matcher/data/aliases.json'
    assert packaged.read_bytes()==(ROOT/'advisory_matcher/data/aliases.json').read_bytes()
    result=subprocess.run([sys.executable,'-c','from advisory_matcher.aliases import metadata; print(metadata()["sha256"])'],cwd=packaged.parents[2],capture_output=True,text=True,check=True)
    assert result.stdout.strip()==hashlib.sha256(packaged.read_bytes()).hexdigest()
