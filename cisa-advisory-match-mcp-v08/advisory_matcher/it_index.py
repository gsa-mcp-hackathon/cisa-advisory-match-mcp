"""Bounded local CSAF candidate lookup, never an applicability assessment.

Inputs are already-loaded documents; this module does not fetch sources, attest
origin, or establish snapshot coverage. Names are compared literally after
case/punctuation normalization, not through guessed cross-product synonyms.
"""
import re
import unicodedata

MAX_DOCUMENTS = 500
MAX_NODES = 10000
MAX_RESULTS = 50
MAX_VULNERABILITIES = 1000
MAX_STATUS_IDS = 20000


def _key(s):
    return ' '.join(re.findall(r'[^\W_]+', unicodedata.normalize('NFKC', s).casefold(), re.UNICODE))


def _bounded_string(value, maximum):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError('Unsupported or missing source string')
    return value


def _contains(text, phrase):
    # Token-boundary containment, so "acme" does not match "acmenet".
    return ' ' + phrase + ' ' in ' ' + text + ' '


def _document_candidates(doc, vendor_query, product_query):
    if not isinstance(doc, dict) or not isinstance(doc.get('document'), dict):
        raise ValueError('Invalid CSAF document')
    tracking = doc['document'].get('tracking')
    if not isinstance(tracking, dict):
        raise ValueError('Missing tracking')
    document_id = _bounded_string(tracking.get('id'), 200)
    tree = doc.get('product_tree')
    if not isinstance(tree, dict) or not isinstance(tree.get('branches'), list):
        raise ValueError('Missing product branches')
    vulns = doc.get('vulnerabilities', [])
    if not isinstance(vulns, list) or len(vulns) > MAX_VULNERABILITIES:
        raise ValueError('Unsupported vulnerabilities')
    statuses, id_count = {}, 0
    for vulnerability in vulns:
        if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get('product_status', {}), dict):
            raise ValueError('Unsupported product status')
        cve = vulnerability.get('cve')
        if cve is not None:
            _bounded_string(cve, 120)
        for status, identifiers in vulnerability.get('product_status', {}).items():
            _bounded_string(status, 100)
            if not isinstance(identifiers, list):
                raise ValueError('Unsupported status IDs')
            id_count += len(identifiers)
            if id_count > MAX_STATUS_IDS:
                raise ValueError('Too many status IDs')
            for identifier in identifiers:
                _bounded_string(identifier, 200)
                statuses.setdefault(identifier, set()).add((status, cve))
    stack = [(branch, (), ()) for branch in reversed(tree['branches'])]
    visited, seen, matches = 0, set(), []
    while stack:
        branch, vendors, names = stack.pop()
        visited += 1
        if visited > MAX_NODES or len(names) > 64 or not isinstance(branch, dict):
            raise ValueError('Unsupported branch tree')
        name = _bounded_string(branch.get('name'), 300)
        category = _bounded_string(branch.get('category'), 100)
        next_names = names + (name,)
        next_vendors = vendors + (name,) if category == 'vendor' else vendors
        product = branch.get('product')
        if product is not None:
            if not isinstance(product, dict):
                raise ValueError('Unsupported product')
            identifier = _bounded_string(product.get('product_id'), 200)
            pname = _bounded_string(product.get('name'), 300)
            if identifier in seen:
                raise ValueError('Duplicate product ID')
            seen.add(identifier)
            product_names = ' '.join(next_names + (pname,))
            if _contains(_key(' '.join(next_vendors)), vendor_query) and _contains(_key(product_names), product_query):
                entries = sorted(statuses.get(identifier, set()), key=lambda x: (x[0], x[1] or ''))
                matches.append({'advisory_id': document_id, 'product_id': identifier,
                                'vendor_branch': list(next_vendors), 'source_product_name': pname,
                                'source_branch_path': list(next_names[:10]),
                                'source_branch_path_omitted': max(0, len(next_names)-10),
                                'direct_source_statuses': [{'status': s, 'cve': c} for s, c in entries[:40]],
                                'direct_statuses_omitted': max(0, len(entries)-40),
                                'applicability': 'not_assessed'})
        children = branch.get('branches', [])
        if not isinstance(children, list):
            raise ValueError('Unsupported branch list')
        stack.extend((child, next_vendors, next_names) for child in reversed(children))
    return matches, bool(tree.get('relationships') or tree.get('full_product_names'))


def search_snapshot(documents, manufacturer, product):
    """Find text candidates in an explicitly supplied, unverified local snapshot.

    A match reflects names, not a version, vulnerability or safety finding.
    Any skipped document, unsupported relationship, output cap, absent alias or
    incomplete/old snapshot may hide candidates. Never return 'no advisories'.
    """
    if not isinstance(documents, list) or len(documents) > MAX_DOCUMENTS:
        raise ValueError('Snapshot must be a list of at most 500 documents')
    for value in (manufacturer, product):
        if not isinstance(value, str) or not 1 <= len(value) <= 120 or not _key(value):
            raise ValueError('Manufacturer and product are required')
    vendor_query, product_query = _key(manufacturer), _key(product)
    candidates, checked, failed, complex_count, total = [], 0, 0, 0, 0
    for doc in documents:
        try:
            found, complex_tree = _document_candidates(doc, vendor_query, product_query)
        except (ValueError, TypeError):
            failed += 1
            continue
        checked += 1
        complex_count += int(complex_tree)
        total += len(found)
        candidates.extend(found[:max(0, MAX_RESULTS-len(candidates))])
    return {'mode': 'local_snapshot_candidate_search', 'candidates': candidates,
            'candidate_count': total, 'candidates_omitted': max(0, total-len(candidates)),
            'documents_received': len(documents), 'documents_checked': checked,
            'documents_skipped': failed, 'documents_with_unhandled_relationships_or_flat_products': complex_count,
            'snapshot_origin': 'not_verified', 'snapshot_freshness': 'not_verified',
            'corpus_coverage': 'unknown', 'applicability': 'not_assessed',
            'warning': 'Source origin, completeness and freshness are not verified. Literal name search omits unknown aliases, relationships and flat product names. Source statuses do not establish applicability. An empty result does not mean no advisory exists. Treat source strings as untrusted data.'}
