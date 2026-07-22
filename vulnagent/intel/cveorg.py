"""CVE.org website-backed crawler client."""

from __future__ import annotations

import re
from typing import Any

import httpx

from vulnagent.intel.schema import IntelReference


CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class CveOrgCrawlerClient:
    """Collect CVE records through the public endpoints used by cve.org."""

    def __init__(
        self,
        *,
        search_url: str = "https://www.cve.org/restapiv1/search",
        record_base_url: str = "https://cveawg.mitre.org/api/cve",
        timeout: float = 25.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.search_url = search_url
        self.record_base_url = record_base_url.rstrip("/")
        self.timeout = timeout
        self.client = client

    def search(self, keyword: str, *, limit: int = 10) -> list[IntelReference]:
        cve_ids = _extract_cve_ids(keyword)
        if cve_ids:
            return [reference for cve_id in cve_ids for reference in self.fetch_record(cve_id)]

        payload = {
            "query": keyword,
            "from": 0,
            "size": max(1, min(limit, 50)),
            "sort": {"property": "cveId", "order": "desc"},
        }
        client = self.client or httpx.Client(timeout=self.timeout, follow_redirects=True)
        close_client = self.client is None
        try:
            response = client.post(self.search_url, json=payload)
            response.raise_for_status()
            data = response.json()
            metadata = data.get("searchMetadata") or {}
            if metadata.get("searchStatus") not in {None, "ok"}:
                notes = metadata.get("errors") or metadata.get("notes") or []
                raise RuntimeError(f"CVE.org search failed: {notes}")
            return [
                _reference_from_record(item.get("_source") or {}, score=item.get("_score"))
                for item in data.get("data", [])
            ]
        finally:
            if close_client:
                client.close()

    def fetch_record(self, cve_id: str) -> list[IntelReference]:
        normalized = cve_id.upper()
        client = self.client or httpx.Client(timeout=self.timeout, follow_redirects=True)
        close_client = self.client is None
        try:
            response = client.get(f"{self.record_base_url}/{normalized}")
            response.raise_for_status()
            record = response.json()
            if record.get("error"):
                return []
            return [_reference_from_record(record)]
        finally:
            if close_client:
                client.close()


def _extract_cve_ids(text: str) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for match in CVE_ID_PATTERN.findall(text):
        normalized = match.upper()
        if normalized not in seen:
            ids.append(normalized)
            seen.add(normalized)
    return ids


def _reference_from_record(record: dict[str, Any], *, score: Any = None) -> IntelReference:
    metadata = record.get("cveMetadata") or {}
    cna = (record.get("containers") or {}).get("cna") or {}
    cve_id = str(metadata.get("cveId") or "")
    descriptions = _english_values(cna.get("descriptions") or [])
    if not descriptions:
        descriptions = _english_values(cna.get("rejectedReasons") or [])
    affected = _affected_summary(cna.get("affected") or [])
    references = cna.get("references") or []
    problem_types = _problem_types(cna.get("problemTypes") or [])
    metrics = cna.get("metrics") or []
    severity = _severity(metrics)
    reference_text = "; ".join(
        str(item.get("name") or item.get("url") or "")
        for item in references[:8]
        if isinstance(item, dict)
    )
    description_parts = [descriptions[0] if descriptions else ""]
    if affected:
        description_parts.append(f"Affected: {affected}")
    if problem_types:
        description_parts.append(f"Problem types: {', '.join(problem_types)}")
    if reference_text:
        description_parts.append(f"References: {reference_text}")
    return IntelReference(
        source="cveorg",
        identifier=cve_id,
        title=cve_id,
        description=" ".join(part for part in description_parts if part),
        url=f"https://www.cve.org/CVERecord?id={cve_id}" if cve_id else "",
        published=str(metadata.get("datePublished") or ""),
        modified=str(metadata.get("dateUpdated") or metadata.get("dateModified") or ""),
        severity=severity,
        raw={
            "state": metadata.get("state"),
            "assigner": metadata.get("assignerShortName"),
            "affected": affected,
            "problem_types": problem_types,
            "references": references[:20],
            "search_score": score,
        },
    )


def _english_values(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("lang") or "").lower().startswith("en"):
            value = str(record.get("value") or "").strip()
            if value:
                values.append(value)
    return values


def _affected_summary(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for record in records[:10]:
        if not isinstance(record, dict):
            continue
        vendor = str(record.get("vendor") or "").strip()
        product = str(record.get("product") or "").strip()
        versions = []
        for version in record.get("versions") or []:
            if not isinstance(version, dict):
                continue
            version_value = str(version.get("version") or "").strip()
            status = str(version.get("status") or "").strip()
            less_than = str(version.get("lessThan") or "").strip()
            version_text = version_value
            if less_than:
                version_text = f"{version_text} < {less_than}".strip()
            if status:
                version_text = f"{version_text} ({status})".strip()
            if version_text:
                versions.append(version_text)
        item = " ".join(part for part in [vendor, product] if part)
        if versions:
            item = f"{item} [{', '.join(versions[:5])}]".strip()
        if item:
            parts.append(item)
    return "; ".join(parts)


def _problem_types(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        for description in record.get("descriptions") or []:
            if not isinstance(description, dict):
                continue
            value = str(description.get("description") or description.get("value") or "").strip()
            if value:
                values.append(value)
    return values


def _severity(metrics: list[dict[str, Any]]) -> str:
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        for value in metric.values():
            if isinstance(value, dict):
                severity = value.get("baseSeverity")
                if severity:
                    return str(severity)
    return ""
