"""High-level vulnerability intelligence search service."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from vulnagent.intel.cveorg import CveOrgCrawlerClient
from vulnagent.intel.github import GitHubIntelClient
from vulnagent.intel.matcher import IntelMatcher
from vulnagent.intel.nvd import NvdClient
from vulnagent.intel.schema import IntelMatch, IntelQuery, IntelReference, IntelSearchResult


class VulnerabilityIntelService:
    """Search public intelligence and correlate it with a finding."""

    def __init__(
        self,
        *,
        cveorg_client: CveOrgCrawlerClient | None = None,
        nvd_client: NvdClient | None = None,
        github_client: GitHubIntelClient | None = None,
        matcher: IntelMatcher | None = None,
    ) -> None:
        self.cveorg_client = cveorg_client or CveOrgCrawlerClient()
        self.nvd_client = nvd_client or NvdClient()
        self.github_client = github_client or GitHubIntelClient()
        self.matcher = matcher or IntelMatcher()

    def search(
        self,
        query: IntelQuery,
        *,
        sources: Iterable[str] = ("cveorg", "nvd", "github"),
    ) -> IntelSearchResult:
        searched_sources: list[str] = []
        errors: list[str] = []
        references: list[IntelReference] = []
        source_set = {source.strip().lower() for source in sources if source.strip()}

        if "cveorg" in source_set:
            searched_sources.append("cveorg")
            references.extend(
                self._search_many(
                    "cveorg",
                    self.cveorg_client.search,
                    self._build_official_keywords(query),
                    query.max_results,
                    errors,
                )
            )

        if "nvd" in source_set:
            searched_sources.append("nvd")
            references.extend(
                self._search_many(
                    "nvd",
                    self.nvd_client.search,
                    self._build_official_keywords(query),
                    query.max_results,
                    errors,
                )
            )

        if "github" in source_set:
            searched_sources.append("github")
            references.extend(
                self._search_many(
                    "github",
                    self.github_client.search,
                    self._build_github_keywords(query),
                    query.max_results,
                    errors,
                )
            )

        matches = self._dedupe_and_score(query, references)
        return IntelSearchResult(
            query=query,
            matches=matches[: query.max_results],
            searched_sources=searched_sources,
            errors=errors,
            assessment=self._assess(matches, errors),
        )

    @staticmethod
    def _search_many(
        source: str,
        search_fn: Any,
        keywords: list[str],
        limit: int,
        errors: list[str],
    ) -> list[IntelReference]:
        references: list[IntelReference] = []
        for keyword in keywords:
            try:
                found = search_fn(keyword, limit=limit)
            except Exception as exc:  # noqa: BLE001 - return partial intel when one query fails
                errors.append(f"{source} [{keyword}]: {type(exc).__name__}: {exc}")
                continue
            for reference in found:
                reference.raw.setdefault("search_queries", [])
                if isinstance(reference.raw["search_queries"], list):
                    reference.raw["search_queries"].append(keyword)
                references.append(reference)
        return references

    @staticmethod
    def _build_official_keywords(query: IntelQuery) -> list[str]:
        """Use broad public-record queries; keep binary-only evidence for local scoring."""
        vendor = _canonical_vendor(query.vendor)
        product_variants = _product_variants(query.product)
        vulnerability_type = query.vulnerability_type.strip()
        firmware_version = query.firmware_version.strip()
        keywords: list[str] = []

        for product in product_variants[:2]:
            keywords.append(_join_terms(vendor, product))
        for product in product_variants[:1]:
            keywords.append(_join_terms(vendor, product, firmware_version))
            keywords.append(_join_terms(vendor, product, vulnerability_type))
            keywords.append(_join_terms(product, vulnerability_type))
        for extra in query.keywords[:2]:
            if len(extra.strip()) >= 4:
                keywords.append(_join_terms(vendor, product_variants[0] if product_variants else "", extra))

        if not keywords:
            return [VulnerabilityIntelService._build_keyword(query)]
        return _dedupe_keywords(keywords)[:6]

    @staticmethod
    def _build_github_keywords(query: IntelQuery) -> list[str]:
        official = VulnerabilityIntelService._build_official_keywords(query)
        product = _product_variants(query.product)
        model = product[0] if product else query.product.strip()
        exploit_terms = [
            _join_terms(_canonical_vendor(query.vendor), model, "CVE"),
            _join_terms(_canonical_vendor(query.vendor), model, "exploit"),
            _join_terms(_canonical_vendor(query.vendor), model, query.vulnerability_type, "PoC"),
        ]
        return _dedupe_keywords([*official[:3], *exploit_terms])[:6]

    @staticmethod
    def _build_keyword(query: IntelQuery) -> str:
        terms = query.search_terms()
        if not terms:
            return "firmware vulnerability"
        prioritized = [
            query.vendor,
            query.product,
            query.firmware_version,
            query.vulnerability_type,
            query.route,
            query.sink,
        ]
        selected = [term.strip() for term in prioritized if term.strip()]
        if len(selected) < 2:
            selected = terms[:6]
        return " ".join(selected[:8])

    def _dedupe_and_score(
        self,
        query: IntelQuery,
        references: list[IntelReference],
    ) -> list[IntelMatch]:
        by_key: dict[tuple[str, str], IntelReference] = {}
        for reference in references:
            key = (reference.source, reference.identifier or reference.url)
            if key[1]:
                by_key[key] = reference
        matches = [self.matcher.score(query, reference) for reference in by_key.values()]
        matches.sort(key=lambda item: item.score, reverse=True)
        return matches

    @staticmethod
    def _assess(matches: list[IntelMatch], errors: list[str]) -> str:
        if matches and matches[0].score >= 70:
            return "likely_known_vulnerability"
        if matches and matches[0].score >= 40:
            return "possible_known_vulnerability"
        if not matches and errors:
            return "lookup_failed"
        return "no_strong_match"


def _canonical_vendor(value: str) -> str:
    vendor = value.strip()
    normalized = vendor.lower().replace("-", "").replace(" ", "")
    if normalized in {"dlink", "d-link"}:
        return "D-Link"
    return vendor


def _product_variants(value: str) -> list[str]:
    product = value.strip()
    if not product:
        return []
    variants = [product]
    if " " in product:
        variants.append(product.replace(" ", "-"))
    if "-" in product:
        variants.append(product.replace("-", " "))
    return _dedupe_keywords(variants)


def _join_terms(*values: str) -> str:
    return " ".join(value.strip() for value in values if value and value.strip())


def _dedupe_keywords(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = " ".join(value.split())
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        deduped.append(normalized)
        seen.add(key)
    return deduped
