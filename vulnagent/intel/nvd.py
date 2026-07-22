"""NVD CVE API client."""

from __future__ import annotations

import os
from typing import Any

import httpx

from vulnagent.intel.schema import IntelReference


class NvdClient:
    """Small wrapper around the NVD CVE 2.0 API."""

    def __init__(
        self,
        *,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key: str | None = None,
        timeout: float = 20.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY", "")
        self.timeout = timeout
        self.client = client

    def search(self, keyword: str, *, limit: int = 10) -> list[IntelReference]:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(max(1, min(limit, 50))),
        }
        headers = {"apiKey": self.api_key} if self.api_key else {}
        client = self.client or httpx.Client(timeout=self.timeout)
        close_client = self.client is None
        try:
            response = client.get(self.base_url, params=params, headers=headers)
            response.raise_for_status()
            return [_reference_from_cve(item) for item in response.json().get("vulnerabilities", [])]
        finally:
            if close_client:
                client.close()


def _reference_from_cve(item: dict[str, Any]) -> IntelReference:
    cve = item.get("cve", {})
    cve_id = str(cve.get("id") or "")
    descriptions = cve.get("descriptions") or []
    description = ""
    for record in descriptions:
        if record.get("lang") == "en":
            description = str(record.get("value") or "")
            break
    metrics = cve.get("metrics") or {}
    severity = _extract_severity(metrics)
    return IntelReference(
        source="nvd",
        identifier=cve_id,
        title=cve_id,
        description=description,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        published=str(cve.get("published") or ""),
        modified=str(cve.get("lastModified") or ""),
        severity=severity,
        raw={"cve": cve},
    )


def _extract_severity(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            metric_data = values[0].get("cvssData") or {}
            severity = values[0].get("baseSeverity") or metric_data.get("baseSeverity")
            if severity:
                return str(severity)
    return ""
