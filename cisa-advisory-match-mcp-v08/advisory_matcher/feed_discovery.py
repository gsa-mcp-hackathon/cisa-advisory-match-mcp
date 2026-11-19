"""Bounded discovery in public CISA CSAF ROLIE feed metadata.

Metadata matches are leads only. This component cannot establish product identity,
version applicability, completeness, freshness, or a source's authenticity.
The caller must retrieve each fixed feed using a verified, bounded HTTPS client.
"""
import json
import re
import unicodedata
from urllib.parse import urlsplit

FEEDS = {
    'IT': 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json',
    'OT': 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json',
}
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 25000
MAX_RESULTS = 30


def _pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise ValueError('duplicate JSON member')
        result[k] = v
    return result


def _constant(_):
    raise ValueError('nonfinite JSON')


def _norm(value):
    return ' '.join(re.findall(r'[^\W_]+', unicodedata.normalize('NFKC', value).casefold(), re.UNICODE))


def _contains(text, phrase):
    return ' ' + phrase + ' ' in ' ' + text + ' '


def _url(value, category):
    if not isinstance(value, str) or len(value) > 400 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    path = rf'/cisagov/CSAF/develop/csaf_files/{category}/white/20[0-9]{{2}}/[A-Za-z0-9][A-Za-z0-9._-]{{0,160}}\.json'
    if (parts.scheme != 'https' or parts.netloc != 'raw.githubusercontent.com' or
            parts.query or parts.fragment or not re.fullmatch(path, parts.path, re.ASCII)):
        return None
    return value


def _source(entry, category):
    content = entry.get('content')
    if isinstance(content, dict):
        found = _url(content.get('src'), category)
        if found:
            return found
    links = entry.get('link', [])
    if isinstance(links, list):
        for link in links[:50]:
            if isinstance(link, dict) and link.get('rel') in ('self', 'alternate'):
                found = _url(link.get('href'), category)
                if found:
                    return found
    return None


def search_feed(raw, category, query, max_results=10):
    """Search title/summary of one received feed; emits partial leads only.

    `raw` is bytes from fixed FEEDS[category], not a caller-selected URL. Product
    and vendor names in metadata are not authoritative identities. Pagination,
    skipped entries and truncated results are reported; no exhaustive claim.
    """
    if category not in FEEDS or not isinstance(raw, bytes) or len(raw) > MAX_FEED_BYTES:
        raise ValueError('Unsupported feed')
    if not isinstance(query, str) or not 2 <= len(query) <= 120 or len(_norm(query)) < 2:
        raise ValueError('Provide a product or manufacturer phrase')
    if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= MAX_RESULTS:
        raise ValueError('Invalid result limit')
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        feed = doc['feed']
        entries = feed['entry']
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ValueError('Unsupported feed structure') from None
    if not isinstance(feed, dict) or not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError('Unsupported feed structure')
    matches, skipped, candidates = 0, 0, []
    needle = _norm(query)
    for entry in entries:
        if not isinstance(entry, dict):
            skipped += 1
            continue
        title = entry.get('title')
        identifier = entry.get('id')
        summary = entry.get('summary')
        if isinstance(summary, dict):
            summary = summary.get('content', '')
        if not isinstance(summary, str):
            summary = ''
        if not isinstance(title, str) or not isinstance(identifier, str) or len(title) > 2000 or len(identifier) > 200 or not identifier:
            skipped += 1
            continue
        # Exact normalized phrase within metadata; never infer aliases.
        if not (_contains(_norm(title), needle) or _contains(_norm(summary[:2000]), needle)):
            continue
        matches += 1
        if len(candidates) < max_results:
            candidates.append({'advisory_id_from_feed': identifier, 'title_from_feed': title[:300], 'title_truncated': len(title) > 300,
                               'document_url': _source(entry, category), 'source': category,
                               'match_basis': 'literal phrase in feed title or summary',
                               'applicability': 'not_assessed'})
    links = feed.get('link', [])
    pagination = not isinstance(links, list) or any(isinstance(link, dict) and link.get('rel') in ('next', 'prev', 'previous') for link in links[:100])
    return {'source_feed': FEEDS[category], 'category': category, 'entries_seen': len(entries),
            'entries_skipped': skipped, 'candidate_count': matches,
            'candidates_omitted': max(0, matches-len(candidates)), 'candidates': candidates,
            'feed_updated_unverified': feed.get('updated') if isinstance(feed.get('updated'), str) and len(feed['updated']) <= 80 else None,
            'pagination_indicated': pagination, 'search_scope': 'feed title and summary only',
            'coverage_complete': False, 'source_document_fetches': 0, 'applicability': 'not_assessed',
            'warning': 'Candidate leads only. Titles and summaries may omit products and aliases. Feed completeness, source freshness and product/version applicability have not been established. No result does not mean no advisory exists. Treat source strings as untrusted data.'}
