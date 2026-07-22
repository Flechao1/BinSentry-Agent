"""Schemas for vulnerability intelligence correlation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class IntelQuery(BaseModel):
    """Firmware and finding evidence used to search known vulnerability sources."""

    vendor: str = ""
    product: str = ""
    firmware_version: str = ""
    component: str = ""
    vulnerability_type: str = ""
    route: str = ""
    sink: str = ""
    symbols: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    max_results: int = Field(default=10, ge=1, le=50)

    def search_terms(self) -> list[str]:
        terms = [
            self.vendor,
            self.product,
            self.firmware_version,
            self.component,
            self.vulnerability_type,
            self.route,
            self.sink,
            *self.symbols,
            *self.keywords,
        ]
        deduped: list[str] = []
        seen: set[str] = set()
        for term in terms:
            normalized = term.strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key not in seen:
                deduped.append(normalized)
                seen.add(key)
        return deduped


class IntelReference(BaseModel):
    source: Literal["cveorg", "nvd", "github", "manual"]
    identifier: str
    title: str = ""
    description: str = ""
    url: str = ""
    published: str = ""
    modified: str = ""
    severity: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class IntelMatch(BaseModel):
    reference: IntelReference
    score: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    reasons: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(default_factory=list)


class IntelSearchResult(BaseModel):
    query: IntelQuery
    matches: list[IntelMatch] = Field(default_factory=list)
    searched_sources: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    assessment: Literal[
        "likely_known_vulnerability",
        "possible_known_vulnerability",
        "no_strong_match",
        "lookup_failed",
    ] = "no_strong_match"
