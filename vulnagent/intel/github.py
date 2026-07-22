"""GitHub advisory and code-search intelligence client."""

from __future__ import annotations

import os
from typing import Any

import httpx

from vulnagent.intel.schema import IntelReference


class GitHubIntelClient:
    """Query GitHub search endpoints for public vulnerability references."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.github.com/search",
        token: str | None = None,
        timeout: float = 20.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token if token is not None else (
            os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT") or ""
        )
        self.timeout = timeout
        self.client = client

    def search(self, keyword: str, *, limit: int = 10) -> list[IntelReference]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        params = {"q": keyword, "per_page": str(max(1, min(limit, 50)))}
        client = self.client or httpx.Client(timeout=self.timeout)
        close_client = self.client is None
        try:
            response = client.get(f"{self.base_url}/repositories", params=params, headers=headers)
            response.raise_for_status()
            return [_reference_from_repo(item, keyword) for item in response.json().get("items", [])]
        finally:
            if close_client:
                client.close()


def _reference_from_repo(item: dict[str, Any], keyword: str) -> IntelReference:
    full_name = str(item.get("full_name") or item.get("name") or "")
    description = str(item.get("description") or "")
    html_url = str(item.get("html_url") or "")
    topics = item.get("topics") or []
    return IntelReference(
        source="github",
        identifier=full_name,
        title=full_name,
        description=description,
        url=html_url,
        modified=str(item.get("updated_at") or ""),
        raw={
            "query": keyword,
            "stars": item.get("stargazers_count"),
            "topics": topics,
            "language": item.get("language"),
        },
    )
