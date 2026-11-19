"""Offline targeted checks without the pinned test runtime; NOT an MCP/network test.

This uses minimal test-only shims for pytest decorators, pytest.raises and the
UpstreamError exception because pytest and httpx2 are not installed here. It
executes the real local matching, alias and service code with FakeClient fixtures.
Run the full pinned pytest and MCP tests separately in the IBM environment.
"""
import contextlib
import importlib
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]

@contextlib.contextmanager
def raises(expected, match=None):
    try:
        yield
    except expected as exc:
        if match is not None and match not in str(exc):
            raise AssertionError(f'exception did not contain {match!r}') from exc
    else:
        raise AssertionError(f'expected {expected}')

pytest = types.ModuleType('pytest')
pytest.raises = raises
pytest.mark = types.SimpleNamespace(parametrize=lambda *_args, **_kwargs: lambda fn: fn)
sys.modules['pytest'] = pytest
upstream = types.ModuleType('advisory_matcher.upstream')
class FakeUpstreamError(Exception):
    pass
upstream.UpstreamError = FakeUpstreamError
sys.modules['advisory_matcher.upstream'] = upstream

class MonkeyPatch:
    def __init__(self): self.original = []
    def setattr(self, obj, name, value):
        self.original.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)
    def undo(self):
        for obj, name, value in reversed(self.original): setattr(obj, name, value)

fresh = importlib.import_module('test_freshness_review')
relation = importlib.import_module('test_relationship_gap')
mixed = importlib.import_module('test_mixed_outcome')
search_mirror = importlib.import_module('test_search_mirror_review')
class Focused(unittest.TestCase):
    def test_freshness_missing(self): fresh.test_bad_or_missing_index_freshness_makes_discovery_incomplete(None)
    def test_freshness_malformed(self): fresh.test_bad_or_missing_index_freshness_makes_discovery_incomplete('not-a-timestamp')
    def test_freshness_stale(self): fresh.test_bad_or_missing_index_freshness_makes_discovery_incomplete('2020-01-01T00:00:00Z')
    def test_freshness_future(self): fresh.test_bad_or_missing_index_freshness_makes_discovery_incomplete((datetime.now(timezone.utc)+timedelta(hours=3)).isoformat())
    def test_freshness_recent(self): fresh.test_recent_index_allows_bounded_empty_search_but_not_a_global_safety_claim()
    def test_freshness_selected(self): fresh.test_stale_index_does_not_block_a_selected_original_advisory_check()
    def test_relationship_unmatched(self): relation.test_unmatched_branch_name_with_relationships_requires_review()
    def test_relationship_no_status(self): relation.test_matched_branch_with_no_relevant_status_and_unrelated_relationship_requires_review()
    def test_relationship_related(self): relation.test_related_product_id_still_returns_review_finding()
    def test_relationship_unrelated(self): relation.test_unrelated_relationship_does_not_downgrade_positive_branch_finding()
    def test_relationship_service(self): relation.test_service_discloses_unsupported_relationship_instead_of_no_match()
    def test_mixed_findings(self): mixed.test_confirmed_and_unresolved_findings_are_both_visible()
    def test_mixed_incomplete(self): mixed.test_incomplete_coverage_remains_visible_even_with_a_positive()
    def test_search_mirror_not_ready(self): search_mirror.test_search_page_not_ready_overrides_healthy_reference()
    def test_search_mirror_sync(self): search_mirror.test_search_page_unfinished_sync_overrides_healthy_reference()
    def test_search_mirror_failures(self): search_mirror.test_search_page_failed_documents_override_healthy_reference()
    def test_search_mirror_stale(self): search_mirror.test_search_page_stale_timestamp_overrides_healthy_reference()
    def test_search_mirror_future(self): search_mirror.test_search_page_future_timestamp_overrides_healthy_reference()
    def test_search_mirror_missing(self): search_mirror.test_missing_page_metadata_does_not_claim_verified_page_freshness()
    def test_search_mirror_malformed(self): search_mirror.test_malformed_page_timestamp_remains_unknown()
    def test_search_mirror_pagination(self): search_mirror.test_later_healthy_page_cannot_erase_earlier_conflict()
    def test_search_mirror_positive(self): search_mirror.test_page_conflict_keeps_original_source_positive_with_incomplete_coverage()
    def test_mixed_truncated(self):
        patch = MonkeyPatch()
        try: mixed.test_output_budget_fallback_does_not_expose_stale_finding_summary(patch)
        finally: patch.undo()

if __name__ == '__main__': unittest.main(verbosity=2)
