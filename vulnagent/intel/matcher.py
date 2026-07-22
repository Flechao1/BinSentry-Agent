"""Deterministic scoring for known-vulnerability intelligence matches."""

from __future__ import annotations

from vulnagent.intel.schema import IntelMatch, IntelQuery, IntelReference


class IntelMatcher:
    """Score references against firmware/finding evidence without relying on LLM memory."""

    def score(self, query: IntelQuery, reference: IntelReference) -> IntelMatch:
        haystack = " ".join(
            [
                reference.identifier,
                reference.title,
                reference.description,
                reference.url,
                " ".join(str(value) for value in reference.raw.values()),
            ]
        ).lower()
        reasons: list[str] = []
        matched_terms: list[str] = []
        score = 0

        score += self._score_term(query.vendor, haystack, 18, "vendor matched", reasons, matched_terms)
        score += self._score_term(query.product, haystack, 24, "product/model matched", reasons, matched_terms)
        score += self._score_term(
            query.firmware_version,
            haystack,
            18,
            "firmware version matched",
            reasons,
            matched_terms,
        )
        score += self._score_term(query.component, haystack, 12, "component matched", reasons, matched_terms)
        score += self._score_term(
            query.vulnerability_type,
            haystack,
            18,
            "vulnerability type matched",
            reasons,
            matched_terms,
        )
        score += self._score_term(query.route, haystack, 18, "route matched", reasons, matched_terms)
        score += self._score_term(query.sink, haystack, 8, "sink matched", reasons, matched_terms)

        for symbol in query.symbols[:8]:
            score += self._score_term(symbol, haystack, 6, "symbol/function matched", reasons, matched_terms)
        for keyword in query.keywords[:8]:
            score += self._score_term(keyword, haystack, 4, "keyword matched", reasons, matched_terms)

        if reference.source in {"cveorg", "nvd"} and reference.identifier.startswith("CVE-"):
            score += 5
            reasons.append("official CVE record")
        if reference.source == "github" and any(term in haystack for term in ("poc", "exploit", "cve")):
            score += 8
            reasons.append("public exploit or PoC signal")

        score = min(score, 100)
        confidence = "high" if score >= 70 else "medium" if score >= 40 else "low"
        return IntelMatch(
            reference=reference,
            score=score,
            confidence=confidence,
            reasons=reasons or ["weak textual similarity"],
            matched_terms=matched_terms,
        )

    @staticmethod
    def _score_term(
        term: str,
        haystack: str,
        points: int,
        reason: str,
        reasons: list[str],
        matched_terms: list[str],
    ) -> int:
        normalized = term.strip().lower()
        if not normalized or len(normalized) < 2:
            return 0
        if normalized in haystack:
            reasons.append(reason)
            matched_terms.append(term.strip())
            return points
        compact = normalized.replace("-", "").replace("_", "").replace("/", "").replace(" ", "")
        compact_haystack = haystack.replace("-", "").replace("_", "").replace("/", "").replace(" ", "")
        if len(compact) >= 4 and compact in compact_haystack:
            reasons.append(f"{reason} after normalization")
            matched_terms.append(term.strip())
            return max(points - 4, 1)
        return 0
