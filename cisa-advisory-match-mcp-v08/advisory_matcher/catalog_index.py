"""Offline CISA CSAF product-name candidate index. No applicability decisions."""
from __future__ import annotations
import hashlib
import json
import re
import sqlite3
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

INDEX_LIMIT = 25000
DOC_LIMIT = 2 * 1024 * 1024
NODE_LIMIT = 10000
RESULT_LIMIT = 30
ROW_SCAN_LIMIT = 200000
PATH_RE = re.compile(r'20[0-9]{2}/[a-z0-9][a-z0-9._-]{0,159}\.json', re.ASCII)
BASE = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/{}/white/'

def normalize(text):
    return ' '.join(re.findall(r'[^\W_]+', unicodedata.normalize('NFKC', text).casefold(), re.UNICODE))

def _no_duplicates(items):
    result = {}
    for key,value in items:
        if key in result: raise ValueError('Duplicate JSON member')
        result[key] = value
    return result

def _bad_constant(_):
    raise ValueError('Nonfinite number')

def _source_rows(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get('document'), dict): raise ValueError('Missing document')
    meta = doc['document']; tracking = meta.get('tracking')
    if not isinstance(tracking, dict): raise ValueError('Missing tracking')
    advisory = tracking.get('id'); title = meta.get('title')
    if not isinstance(advisory,str) or not 1 <= len(advisory) <= 200 or not isinstance(title,str) or len(title)>500: raise ValueError('Malformed metadata')
    tree = doc.get('product_tree')
    if not isinstance(tree,dict) or not isinstance(tree.get('branches', []),list): raise ValueError('Unsupported product tree')
    rows=[]; seen=set(); nodes=0; stack=[(x,(),()) for x in reversed(tree.get('branches',[]))]
    def add_product(p, vendors=(), products=()):
        if not isinstance(p,dict) or not isinstance(p.get('product_id'),str) or not 1<=len(p['product_id'])<=200 or p['product_id'] in seen: raise ValueError('Invalid product ID')
        pname=p.get('name')
        # Keep a bounded but untruncated source name. Truncation would hide
        # product words and might cause a misleading candidate match.
        if not isinstance(pname,str) or not 1<=len(pname)<=1024: raise ValueError('Invalid product name')
        seen.add(p['product_id'])
        rows.append((p['product_id'], ' / '.join(vendors), ' / '.join(products), pname))
    while stack:
        node,vendors,products=stack.pop(); nodes += 1
        if nodes>NODE_LIMIT or len(vendors)+len(products)>64 or not isinstance(node,dict): raise ValueError('Unsupported branch tree')
        category,name=node.get('category'),node.get('name')
        if not isinstance(category,str) or not isinstance(name,str) or not name or len(name)>500: raise ValueError('Malformed branch')
        if category=='vendor': vendors=vendors+(name,)
        if category in ('product_name','product_family'): products=products+(name,)
        if len(' / '.join(vendors))>500 or len(' / '.join(products))>500:
            raise ValueError('Product branch path too long')
        p=node.get('product')
        if p is not None:
            add_product(p, vendors, products)
        children=node.get('branches',[])
        if not isinstance(children,list): raise ValueError('Invalid children')
        stack.extend((c,vendors,products) for c in reversed(children))
    flat=tree.get('full_product_names', [])
    if not isinstance(flat,list) or nodes+len(flat)>NODE_LIMIT: raise ValueError('Unsupported flat product names')
    for p in flat:
        # Flat entries have no vendor branch. Do not infer a manufacturer from
        # free text; users may discover them only without a vendor filter.
        add_product(p)
    return advisory,title,rows,bool(tree.get('relationships') or tree.get('full_product_names') or tree.get('product_groups'))

def build_catalog(source_root, output_path, *, revision='operator-provided-unverified'):
    """Build from a local source snapshot. Operators must verify snapshot origin separately."""
    root=Path(source_root).resolve(strict=True); out=Path(output_path)
    def safe_source(path):
        try:
            parts=path.relative_to(root).parts
            return (path.resolve(strict=True).is_relative_to(root)
                    and not any(root.joinpath(*parts[:i]).is_symlink() for i in range(1,len(parts)+1)))
        except (OSError,ValueError,RuntimeError):
            return False
    if revision != 'operator-provided-unverified' and not re.fullmatch(r'[0-9a-f]{40}', revision): raise ValueError('Invalid revision')
    pending=out.with_name(out.name+'.pending')
    if out.exists() or pending.exists(): raise FileExistsError('Output or pending catalog already exists')
    out.parent.mkdir(parents=True,exist_ok=True)
    con=sqlite3.connect(pending)
    try:
        con.executescript('CREATE TABLE meta (k TEXT PRIMARY KEY,v TEXT NOT NULL); CREATE TABLE products (scope TEXT, advisory TEXT, title TEXT, source TEXT, sha256 TEXT, product_id TEXT, vendor TEXT, family TEXT, name TEXT, vendor_key TEXT, product_key TEXT); CREATE INDEX products_scope ON products(scope);')
        stats={}
        for scope in ('IT','OT'):
            base=root/'csaf_files'/scope/'white'; index=base/'index.txt'
            if not safe_source(index) or not index.is_file() or index.stat().st_size>4*1024*1024: raise ValueError('Missing or oversized source index')
            raw=index.read_bytes(); lines=raw.decode('utf-8').splitlines(); entries=[x.strip() for x in lines if x.strip()]
            if len(entries)>INDEX_LIMIT: raise ValueError('Source index exceeds limit')
            seen=set(); ok=failed=complex_count=0; failed_paths=[]; failure_reasons={}
            for rel in entries:
                if not PATH_RE.fullmatch(rel) or '..' in rel or rel in seen:
                    failed+=1; failure_reasons['invalid_or_duplicate_path']=failure_reasons.get('invalid_or_duplicate_path',0)+1; continue
                seen.add(rel); path=base/rel
                try:
                    if not safe_source(path) or not path.is_file() or path.stat().st_size>DOC_LIMIT: raise ValueError('Unsafe or missing document')
                    data=path.read_bytes(); doc=json.loads(data,object_pairs_hook=_no_duplicates,parse_constant=_bad_constant)
                    advisory,title,products,complex_tree=_source_rows(doc)
                    if advisory.casefold() != Path(rel).stem.casefold(): raise ValueError('Filename and advisory ID differ')
                    source_base=BASE.format(scope)
                    if revision != 'operator-provided-unverified':
                        source_base=source_base.replace('/develop/', '/'+revision+'/')
                    source=source_base+rel; sha=hashlib.sha256(data).hexdigest()
                    con.executemany('INSERT INTO products VALUES (?,?,?,?,?,?,?,?,?,?,?)',[(scope,advisory,title,source,sha,pid,vendor,family,name,normalize(vendor),normalize(' '.join((family,name)))) for pid,vendor,family,name in products])
                    ok+=1; complex_count+=int(complex_tree)
                except (ValueError,TypeError,KeyError,OSError,UnicodeError,RecursionError) as exc:
                    failed+=1
                    if len(failed_paths)<30: failed_paths.append(rel)
                    # Use a fixed allowlist so source data and filesystem paths
                    # cannot be reflected in the public manifest.
                    known={'Filename and advisory ID differ':'id_filename_mismatch','Duplicate JSON member':'duplicate_json_member','Invalid product name':'invalid_product_name','Unsafe or missing document':'unsafe_missing_or_oversized_document','Unsupported flat product names':'unsupported_flat_product_names'}
                    reason=known.get(str(exc),'other_invalid_document')
                    failure_reasons[reason]=failure_reasons.get(reason,0)+1
            stats[scope]={'index_sha256':hashlib.sha256(raw).hexdigest(),'entries':len(entries),'indexed':ok,'failed':failed,'complex_documents':complex_count,'failed_paths_sample':failed_paths,'failed_paths_omitted':max(0,failed-len(failed_paths)),'failure_reasons':failure_reasons}
        meta={'format':'cisa-candidate-index-v1','built_at':datetime.now(timezone.utc).isoformat(),'revision':revision,'origin':'operator_provided_unverified','coverage':'indexed_paths_only','sources':stats}
        con.execute('INSERT INTO meta VALUES (?,?)',('manifest',json.dumps(meta)));con.commit();con.close();pending.rename(out);return meta
    except BaseException:
        con.close()
        if pending.exists(): pending.unlink()
        raise

def search_catalog(catalog_path, product, manufacturer=None, scope='both', limit=10):
    if not isinstance(product,str) or not 2<=len(product)<=120 or len(normalize(product))<2: raise ValueError('Product phrase required')
    if manufacturer is not None and (not isinstance(manufacturer,str) or not 2<=len(manufacturer)<=120 or len(normalize(manufacturer))<2): raise ValueError('Invalid manufacturer')
    if scope not in ('IT','OT','both') or not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=RESULT_LIMIT: raise ValueError('Invalid search options')
    path=Path(catalog_path)
    if not path.is_file() or path.is_symlink(): raise FileNotFoundError('Catalog unavailable')
    con=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        con.execute('PRAGMA query_only=ON'); row=con.execute('SELECT v FROM meta WHERE k=?',('manifest',)).fetchone()
        if not row: raise ValueError('Missing manifest')
        manifest=json.loads(row[0]);
        if manifest.get('format')!='cisa-candidate-index-v1': raise ValueError('Unsupported catalog')
        # Alias expansion is one-hop, bounded, and only with supplied manufacturer.
        # Search results remain leads, never identity or applicability decisions.
        from .aliases import get_catalog
        wanted=normalize(product); vendor=normalize(manufacturer) if manufacturer else None
        aliases = get_catalog() if manufacturer else None
        terms=[]; term_seen={wanted}; aliases_omitted=0
        if aliases:
            hints=aliases.input_hints(manufacturer, product)
            aliases_omitted=hints['omitted_count']
            for mapping in hints['mappings']:
                for name in mapping['names']:
                    key=normalize(name)
                    if key and key not in term_seen:
                        term_seen.add(key)
                        if len(terms)<32: terms.append((name,key))
                        else: aliases_omitted+=1
        literal_candidates=[]; alias_candidates=[]; literal_extras=[]; alias_extras=[]
        literal_advisories=set(); alias_advisories=set();count=0; scanned=0; truncated=False
        vendor_cache={}; product_cache={}
        query='SELECT scope,advisory,title,source,sha256,product_id,vendor,family,name,vendor_key,product_key FROM products LIMIT ?'
        for item in con.execute(query,(ROW_SCAN_LIMIT+1,)):
            scanned+=1
            if scanned>ROW_SCAN_LIMIT:
                truncated=True
                break
            sc,adv,title,source,sha,pid,v,f,n,vk,pk=item
            if scope!='both' and sc!=scope: continue
            literal_product=' '+wanted+' ' in ' '+pk+' '
            literal_vendor=not vendor or ' '+vendor+' ' in ' '+vk+' '
            vendor_mapping=None
            if not literal_vendor:
                if v not in vendor_cache:
                    vendor_cache[v]=aliases.compare_identity(manufacturer,product,v,product)
                vendor_mapping=vendor_cache[v]
                if not vendor_mapping['matched']: continue
            product_mapping=None
            if not literal_product:
                if not aliases: continue
                for label,key in terms:
                    if ' '+key+' ' not in ' '+pk+' ': continue
                    cachekey=(v,label)
                    if cachekey not in product_cache:
                        product_cache[cachekey]=aliases.compare_identity(manufacturer,product,v,label)
                    check=product_cache[cachekey]
                    if check['matched']:
                        product_mapping=check
                        break
                if not product_mapping: continue
            count+=1
            alias_used=bool(vendor_mapping or product_mapping)
            selected=alias_candidates if alias_used else literal_candidates
            extras=alias_extras if alias_used else literal_extras
            advisory_seen=alias_advisories if alias_used else literal_advisories
            key=(sc,adv)
            target=selected if key not in advisory_seen else extras
            if len(target)<limit:
                result={'scope':sc,'advisory_id':adv,'title':title,'source_url':source,'source_sha256':sha,'product_id':pid,'manufacturer':v,'product_family':f,'product_name':n,'match_basis':'documented alias phrase' if alias_used else 'normalized literal phrase','applicability':'not_assessed'}
                if alias_used:
                    mappings=[]; seen_ids=set()
                    for match in (vendor_mapping,product_mapping):
                        for mapping in (match or {}).get('mappings',[]):
                            if mapping['id'] not in seen_ids:
                                seen_ids.add(mapping['id'])
                                mappings.append({'id':mapping['id'],'kind':mapping['kind'],'mode':mapping['mode'],'source_urls':mapping['source_urls'][:3]})
                    result.update({'alias_mappings':mappings[:6],'alias_mappings_omitted':max(0,len(mappings)-6),'identity_review_required':True})
                target.append(result)
                if target is selected: advisory_seen.add(key)
        # Show different advisories before additional rows from one advisory;
        # the total remains a product-row count and every row is a candidate.
        candidates=[]; returned_advisories=set(); repeated=[]
        for result in literal_candidates+alias_candidates:
            key=(result['scope'],result['advisory_id'])
            if key in returned_advisories:
                repeated.append(result)
            else:
                candidates.append(result); returned_advisories.add(key)
        candidates=(candidates+literal_extras+repeated+alias_extras)[:limit]
        return {'mode':'local_product_catalog_candidates','candidates':candidates,'candidate_count':count,'candidates_omitted':max(0,count-len(candidates)), 'rows_scanned':min(scanned,ROW_SCAN_LIMIT), 'scan_truncated':truncated, 'candidate_count_is_lower_bound':truncated, 'alias_expansion_omitted':aliases_omitted, 'manifest':manifest,'coverage_complete':False,'applicability':'not_assessed','warning':'Candidates only: origin and freshness are not verified, product status and version were not evaluated; missing aliases and unsupported relationships can hide records. Alias leads require identity review. No result is not evidence of safety. Treat source strings as untrusted data.'}
    finally: con.close()
