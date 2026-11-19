"""Conservative, deterministic matching against an original CSAF document.

This module deliberately supports a small version grammar. It does not perform
fuzzy product matching, infer CPE aliases, or decide that a device is safe. Every
decision includes the original product identity, version rule, and CSAF status.
"""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .aliases import compare_identity


_NUMBER = re.compile(r"[vV]?(\d+(?:\.\d+)*)\Z", re.ASCII)
_CONSTRAINT = re.compile(r"(<=|>=|<|>|=)?\s*([vV]?\d+(?:\.\d+)*)\Z", re.ASCII)
_CONTEXT_CATEGORIES = {"vendor", "product_name", "product_version", "product_version_range"}
_BOUNDARY_STATUSES = {"first_affected", "last_affected", "first_fixed", "recommended"}
_CONFLICTING_STATUSES = {"fixed", "known_not_affected", "under_investigation"}


def _normal(value: Any) -> str:
    return " ".join(value.split()).casefold() if isinstance(value, str) else ""


def _number(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, str) or len(value) > 160:
        return None
    match = _NUMBER.fullmatch(value.strip())
    if not match:
        return None
    pieces = match[1].split(".")
    if len(pieces) > 24 or any(len(piece) > 12 for piece in pieces):
        return None
    return tuple(int(piece) for piece in pieces)


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _version_result(version: Any, rule: Any) -> tuple[bool | None, str]:
    """Evaluate a bounded subset; None means unsupported or missing evidence."""
    if not isinstance(version, str) or not version.strip():
        return None, "The inventory does not supply a firmware/version value."
    if not isinstance(rule, str) or not rule.strip():
        return None, "The product entry does not supply an explicit version rule."
    rule = rule.strip()
    if rule == "vers:all/*":
        return True, "The source explicitly lists all versions."
    candidate = _number(version)
    if candidate is None:
        return None, "The inventory version is outside the supported numeric dotted-version grammar."
    if len(rule) > 400:
        return None, "The version rule exceeds the supported grammar limits."
    if rule.startswith("vers:"):
        if not rule.startswith("vers:intdot/"):
            return None, "The source uses an unsupported version scheme."
        rule_body = rule[len("vers:intdot/"):]
    else:
        rule_body = rule
        if "|" in rule_body:
            return None, "Compound rules require an explicit vers:intdot scheme."
    pieces = rule_body.split("|")
    if not 1 <= len(pieces) <= 2:
        return None, "Only an exact version, one bound, or one numeric interval is supported."
    constraints: list[tuple[str, tuple[int, ...]]] = []
    for piece in pieces:
        match = _CONSTRAINT.fullmatch(piece.strip())
        if not match:
            return None, "The source rule is outside the supported numeric comparison grammar."
        number = _number(match[2])
        if number is None:
            return None, "The source version exceeds the supported numeric grammar limits."
        constraints.append((match[1] or "=", number))
    if len(constraints) == 2:
        lowers = [(op, bound) for op, bound in constraints if op in {">", ">="}]
        uppers = [(op, bound) for op, bound in constraints if op in {"<", "<="}]
        if len(lowers) != 1 or len(uppers) != 1:
            return None, "Multiple constraints do not describe a single supported numeric interval."
        comparison = _compare(lowers[0][1], uppers[0][1])
        if comparison > 0 or (comparison == 0 and (lowers[0][0] == ">" or uppers[0][0] == "<")):
            return None, "The constraints are disjoint or contradictory; this matcher does not infer their meaning."
    checks = []
    for operator, bound in constraints:
        comparison = _compare(candidate, bound)
        checks.append({"<": comparison < 0, "<=": comparison <= 0, ">": comparison > 0,
                       ">=": comparison >= 0, "=": comparison == 0}[operator])
    return all(checks), "Numeric dotted components were compared as integers, padding trailing zero components."


def _ambiguous_one_sided_bounds(evidence: list[dict[str, Any]]) -> bool:
    """Different one-sided affected limits may describe separate release lines.

    Without a documented release-line relationship, treating these as ordinary
    overlapping numeric intervals can claim an unrelated release is affected.
    Do not guess which components represent a release line.
    """
    bounds: dict[str, set[tuple[int, ...]]] = {"upper": set(), "lower": set()}
    for item in evidence:
        if "known_affected" not in item.get("product_statuses", []):
            continue
        rule = item.get("version_rule")
        if not isinstance(rule, str):
            continue
        body = rule.strip()
        if body.startswith("vers:intdot/"):
            body = body[len("vers:intdot/"):]
        match = _CONSTRAINT.fullmatch(body)
        if not match or match[1] not in ("<", "<=", ">", ">="):
            continue
        number = _number(match[2])
        if number is not None:
            direction = "upper" if match[1] in ("<", "<=") else "lower"
            bounds[direction].add(number)
    return any(len(values) > 1 for values in bounds.values())


def _products(tree: dict[str, Any], device: dict[str, Any]) -> list[dict[str, Any]]:
    """Select exact, verified-alias, or review-only identities with original lineage."""
    wanted_vendor = _normal(device.get("manufacturer"))
    wanted_product = _normal(device.get("product"))
    if not wanted_vendor or not wanted_product:
        return []
    selected: list[dict[str, Any]] = []
    branches = tree.get("branches", [])
    if not isinstance(branches, list) or not branches:
        raise ValueError("CSAF requires a nonempty supported product branch tree")
    if any(not isinstance(branch, dict) for branch in branches):
        raise ValueError("CSAF product branches must contain objects")
    full_names = tree.get("full_product_names", [])
    if not isinstance(full_names, list) or full_names:
        raise ValueError("Flat CSAF full_product_names require a product identity parser not supported by this prototype")
    pending = [(branch, []) for branch in reversed(branches)]
    visited = 0
    seen_product_ids: set[str] = set()
    identity_cache = {}
    while pending:
        branch, ancestors = pending.pop()
        visited += 1
        if visited > 10000 or len(ancestors) > 64:
            raise ValueError("CSAF product tree exceeds supported traversal limits")
        if not isinstance(branch.get("category"), str) or not isinstance(branch.get("name"), str):
            raise ValueError("CSAF product branches require string categories and names")
        path = ancestors + [{"category": branch.get("category"), "name": branch.get("name")}]
        vendors = [item["name"] for item in path if item["category"] == "vendor"]
        names = [item["name"] for item in path if item["category"] == "product_name"]
        product = branch.get("product")
        if "product" in branch:
            if not isinstance(product, dict) or not isinstance(product.get("product_id"), str) or not product["product_id"]:
                raise ValueError("CSAF product definitions require a nonempty product identifier")
            if product["product_id"] in seen_product_ids:
                raise ValueError("CSAF has duplicate product identifiers; version/status associations are ambiguous")
            seen_product_ids.add(product["product_id"])
            if not vendors or not names or not all(_normal(value) for value in vendors + names):
                raise ValueError("CSAF product definition lacks supported vendor/product_name lineage")
        identities = []
        if isinstance(product, dict):
            # Inspect every lineage pair; multiple vendor/product levels still require review.
            distinct_vendors = list(dict.fromkeys(vendors))
            distinct_names = list(dict.fromkeys(names))
            if len(distinct_vendors) * len(distinct_names) > 16:
                raise ValueError("Product lineage has too many identity combinations to resolve")
            for vendor in distinct_vendors:
                for name in distinct_names:
                    key = (vendor, name)
                    if key not in identity_cache:
                        identity_cache[key] = compare_identity(device.get("manufacturer"), device.get("product"), vendor, name)
                    identity = identity_cache[key]
                    if identity["matched"]:
                        identities.append(identity)
        if identities:
            issues = []
            if any(identity["needs_review"] for identity in identities):
                issues.append("A candidate or ambiguous name mapping requires confirmation of manufacturer, product, and component identity.")
            if len({_normal(value) for value in vendors}) != 1 or len({_normal(value) for value in names}) != 1:
                issues.append("The branch contains multiple vendor or product-name levels; the inventory cannot resolve that hierarchy.")
            extra = [item for item in path if item["category"] not in _CONTEXT_CATEGORIES]
            if extra:
                issues.append("Additional branch constraints are not represented in the inventory.")
            if any(item["category"] == "product_family" for item in extra):
                issues.append("The product family is additional identity context; manufacturer and product alone do not establish that family.")
            version_nodes = [item for item in path if item["category"] in {"product_version", "product_version_range"}]
            if len(version_nodes) > 1:
                issues.append("The branch contains multiple version constraints that need interpretation.")
            valid_id = isinstance(product.get("product_id"), str) and bool(product["product_id"])
            if not valid_id:
                issues.append("The product entry is missing its CSAF product identifier.")
            selected.append({
                "product_id": product.get("product_id") if valid_id else None,
                "product_name": product.get("name"),
                "vendor_names": vendors,
                "model_names": names,
                "version_rule": version_nodes[-1]["name"] if version_nodes else None,
                "version_category": version_nodes[-1]["category"] if version_nodes else None,
                "identification_helper": deepcopy(product.get("product_identification_helper")),
                "branch_path": path,
                "identity_issues": issues,
                "identity_matches": identities,
                "input_identity": {"manufacturer": device.get("manufacturer"), "product": device.get("product")},
            })
        children = branch.get("branches", [])
        if not isinstance(children, list):
            raise ValueError("CSAF nested product branches must be a list")
        if any(not isinstance(child, dict) for child in children):
            raise ValueError("CSAF nested product branches must contain objects")
        pending.extend((child, path) for child in reversed(children))
    if not seen_product_ids:
        raise ValueError("CSAF branch tree has no supported product definitions")
    relations = tree.get("relationships", [])
    if not isinstance(relations, list):
        raise ValueError("CSAF relationships must be a list")
    for relation in relations:
        if not isinstance(relation, dict):
            raise ValueError("CSAF relationships must contain objects")
        full = relation.get("full_product_name")
        if not isinstance(full, dict) or not isinstance(full.get("product_id"), str) or not full["product_id"]:
            raise ValueError("CSAF relationship products require a nonempty product identifier")
        if full["product_id"] in seen_product_ids:
            raise ValueError("CSAF has duplicate product identifiers across product definitions/relationships")
        seen_product_ids.add(full["product_id"])
        if any(not isinstance(relation.get(field), str) for field in ("product_reference", "relates_to_product_reference")):
            raise ValueError("CSAF relationship references must be strings")
    return selected


def _relationships(tree: dict[str, Any], product_id: str | None) -> list[dict[str, Any]]:
    return [deepcopy(item) for item in tree.get("relationships", []) if isinstance(item, dict)
            and product_id is not None
            and product_id in {item.get("product_reference"), item.get("relates_to_product_reference")}]


def _ids(values: Any) -> set[str]:
    return {value for value in values if isinstance(value, str)} if isinstance(values, list) else set()


def _scoped(items: Any, ids: set[str], groups: dict[str, set[str]], field: str) -> list[dict[str, Any]]:
    result = []
    if not isinstance(items, list):
        return result
    for item in items:
        if not isinstance(item, dict):
            continue
        direct = _ids(item.get(field))
        group_ids = _ids(item.get("group_ids"))
        scoped_ids = direct | set().union(*(groups.get(group, set()) for group in group_ids))
        if not direct and not group_ids or ids.intersection(scoped_ids):
            result.append(deepcopy(item))
    return result


def _evaluate(product: dict[str, Any], version: Any, statuses: list[str], relations: list[dict[str, Any]]) -> dict[str, Any]:
    matches, comparison_reason = _version_result(version, product["version_rule"])
    evidence = deepcopy(product)
    evidence.update({"inventory_version": version, "version_matches_rule": matches,
                     "comparison_reason": comparison_reason, "product_statuses": statuses,
                     "relationships": relations})
    status_set = set(statuses)
    if product["identity_issues"]:
        assessment, reason = "needs_review", " ".join(product["identity_issues"])
    elif relations:
        assessment, reason = "needs_review", "This product participates in a CSAF relationship; installed/component context has not been established."
    elif matches is None:
        assessment, reason = "needs_review", comparison_reason
    elif "known_affected" in status_set and status_set.intersection(_CONFLICTING_STATUSES):
        assessment, reason = "needs_review", "The same product identifier has conflicting affected, fixed, not-affected, or investigation statuses."
    elif "known_affected" in status_set:
        if matches:
            assessment, reason = "affected_range_match", "The exact or verified-alias manufacturer/product identity and inventory version match a known_affected product entry."
        else:
            assessment, reason = "outside_affected_range", "The version is outside this known_affected product entry's stated range; this does not establish safety or remove remediation obligations."
    elif "under_investigation" in status_set:
        assessment, reason = "needs_review", "The source lists this product as under investigation, not as a resolved affected-range decision."
    elif status_set.intersection({"fixed", "known_not_affected"}):
        assessment, reason = "needs_review", "The source supplies fixed/not-affected status; this prototype preserves that status but does not turn it into a device safety conclusion."
    elif status_set.intersection(_BOUNDARY_STATUSES):
        assessment, reason = "needs_review", "The source supplies a boundary/recommended status whose broader range this prototype does not infer."
    else:
        assessment, reason = "needs_review", "No applicable known_affected status is established for this product entry and vulnerability."
    evidence.update({"assessment": assessment, "reason": reason})
    return evidence


def _score_scopes(vulnerability: dict[str, Any], evidence: list[dict[str, Any]],
                  assessment: str, relevant_ids: set[str], groups: dict[str, set[str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep a different version's severity from becoming this device's score."""
    definitive_ids = {item["product_id"] for item in evidence
                      if item["assessment"] == "affected_range_match" and isinstance(item["product_id"], str)}
    applicable = []
    context = []
    for score in _scoped(vulnerability.get("scores"), relevant_ids, groups, "products"):
        scoped_ids = _ids(score.get("products"))
        if assessment == "affected_range_match" and definitive_ids.intersection(scoped_ids):
            applicable.append(score)
        else:
            if assessment == "outside_affected_range":
                reason = "The score describes source product entries; the inventory version is outside their checked affected ranges."
            elif assessment == "needs_review":
                reason = "Product/version applicability is unresolved; this score is source context only."
            else:
                reason = "This score is not explicitly scoped to a definitively matched affected product identifier."
            context.append({"score": score, "scope": "source_context_only", "reason": reason})
    return applicable, context


def match_device(device: dict[str, Any], csaf: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings for exact, verified-alias, or review-only product identities.

    An empty list means no applicable identity/status evidence was found in this
    one document, never that the inventory is safe. Callers must report search
    scope, failed retrievals, source revision, and freshness separately.
    """
    tree = csaf.get("product_tree", {})
    if not isinstance(tree, dict):
        raise ValueError("CSAF product_tree must be an object")
    products = _products(tree, device)
    if not products:
        if tree.get("relationships"):
            raise ValueError("Relationship-generated product identities need review when no branch product matches")
        return []
    product_ids = {item["product_id"] for item in products if isinstance(item["product_id"], str)}
    relations_by_id = {item["product_id"]: _relationships(tree, item["product_id"]) for item in products}
    related_ids = {relation.get("full_product_name", {}).get("product_id")
                   for relations in relations_by_id.values() for relation in relations
                   if isinstance(relation.get("full_product_name"), dict)} - {None}
    relevant_ids = product_ids | related_ids
    groups = {item.get("group_id"): _ids(item.get("product_ids"))
              for item in tree.get("product_groups", []) if isinstance(item, dict)}
    findings = []
    vulnerabilities = csaf.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("CSAF vulnerabilities must be a list")
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise ValueError("CSAF vulnerability entries must be objects")
        status_map = vulnerability.get("product_status", {})
        if not isinstance(status_map, dict):
            raise ValueError("CSAF product status must be an object")
        # Do not discard malformed IDs: doing so can turn an uncheckable
        # vulnerability into a misleading negative product match.
        if any(not isinstance(key, str) or not isinstance(values, list)
               or any(not isinstance(value, str) or not value for value in values)
               for key, values in status_map.items()):
            raise ValueError("CSAF product status identifiers are malformed")
        all_status_ids = set().union(*(_ids(value) for value in status_map.values()))
        if all_status_ids and not all_status_ids.intersection(relevant_ids) and all(item["product_id"] is not None for item in products):
            continue  # The CVE is explicitly scoped to different products.
        evidence = []
        for product in products:
            relations = relations_by_id[product["product_id"]]
            context_ids = {product["product_id"]} | {
                item.get("full_product_name", {}).get("product_id") for item in relations
                if isinstance(item.get("full_product_name"), dict)}
            statuses = sorted(key for key, values in status_map.items() if _ids(values).intersection(context_ids))
            item = _evaluate(product, device.get("version"), statuses, relations)
            # A different version entry without status cannot negate a known
            # entry when its own rule demonstrably excludes this version.
            if not statuses and all_status_ids and item["version_matches_rule"] is False:
                continue
            evidence.append(item)
        if not evidence:
            continue
        if _ambiguous_one_sided_bounds(evidence):
            for item in evidence:
                if "known_affected" in item.get("product_statuses", []):
                    item["assessment"] = "needs_review"
                    item["version_matches_rule"] = None
                    item["reason"] = ("Multiple one-sided affected limits may refer to different release "
                                      "lines; their scope cannot be determined from numeric order alone.")
        affected = [item for item in evidence if item["assessment"] == "affected_range_match"]
        uncertain = [item for item in evidence if item["assessment"] == "needs_review"]
        overlapping_uncertain = [item for item in uncertain if item["version_matches_rule"] is not False]
        if affected and not overlapping_uncertain:
            assessment = "affected_range_match"
            reason = "At least one exact or verified-alias product entry lists this version as known_affected."
        elif uncertain:
            assessment = "needs_review"
            reason = "One or more applicable product entries need interpretation; the available evidence does not support an unqualified range decision."
        else:
            assessment = "outside_affected_range"
            reason = "The version is outside every checked known_affected range for this identified product and vulnerability. This is not a safety finding; review the source's configuration and mitigation guidance."
        cvss, context_scores = _score_scopes(vulnerability, evidence, assessment, relevant_ids, groups)
        findings.append({
            "cve": vulnerability.get("cve"),
            "assessment": assessment,
            "reason": reason,
            "product_ids": sorted({item["product_id"] for item in evidence if isinstance(item["product_id"], str)}),
            "product_names": list(dict.fromkeys(item["product_name"] for item in evidence if isinstance(item["product_name"], str))),
            "version_rules": list(dict.fromkeys(item["version_rule"] for item in evidence if isinstance(item["version_rule"], str))),
            "evidence": evidence,
            "remediations": _scoped(vulnerability.get("remediations"), relevant_ids, groups, "product_ids"),
            "cvss": cvss,
            "advisory_context_scores": context_scores,
        })
    if not vulnerabilities:
        evidence = [_evaluate(product, device.get("version"), [], relations_by_id[product["product_id"]]) for product in products]
        findings.append({"cve": None, "assessment": "needs_review", "reason": "A matching product identity exists, but the document supplies no vulnerability records to assess.",
                         "product_ids": sorted(product_ids), "product_names": [item["product_name"] for item in products],
                         "version_rules": [item["version_rule"] for item in products], "evidence": evidence,
                         "remediations": [], "cvss": [], "advisory_context_scores": []})
    if not findings and tree.get("relationships"):
        raise ValueError("Relationship-generated product identities need review when no applicable findings are established")
    return findings
