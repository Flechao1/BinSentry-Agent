"""LangChain tools for known-vulnerability intelligence lookup."""

from __future__ import annotations

import json

from vulnagent.intel import IntelQuery, VulnerabilityIntelService
from vulnagent.tools.recon_tools import _json_result


class VulnerabilityIntelTools:
    """Agent-facing wrappers for CVE and public reference correlation."""

    def __init__(self, service: VulnerabilityIntelService | None = None) -> None:
        self.service = service or VulnerabilityIntelService()

    def search_vulnerability_intel(
        self,
        vendor: str = "",
        product: str = "",
        firmware_version: str = "",
        component: str = "",
        vulnerability_type: str = "",
        route: str = "",
        sink: str = "",
        symbols: str = "",
        keywords: str = "",
        max_results: str = "10",
        sources: str = "cveorg,nvd,github",
    ) -> str:
        """Search CVE.org, NVD, and GitHub intelligence for a firmware finding.

        symbols and keywords are comma-separated lists. Use only observed evidence
        from firmware triage, IDA tools, or validated findings.
        """
        query = IntelQuery(
            vendor=vendor,
            product=product,
            firmware_version=firmware_version,
            component=component,
            vulnerability_type=vulnerability_type,
            route=route,
            sink=sink,
            symbols=_split_csv(symbols),
            keywords=_split_csv(keywords),
            max_results=int(max_results),
        )
        result = self.service.search(
            query,
            sources=_split_csv(sources) or ["cveorg", "nvd", "github"],
        )
        lines = [
            f"Known vulnerability intelligence: {result.assessment}",
            f"Searched sources: {', '.join(result.searched_sources) or '(none)'}",
        ]
        if result.errors:
            lines.append(f"Lookup errors: {'; '.join(result.errors)}")
        if result.matches:
            lines.append("Matches:")
            for match in result.matches:
                ref = match.reference
                lines.append(
                    f"- [{match.score}/100 {match.confidence}] {ref.identifier} "
                    f"({ref.source}) {ref.url}"
                )
                lines.append(f"  Reasons: {'; '.join(match.reasons)}")
                if ref.description:
                    lines.append(f"  Summary: {ref.description[:260]}")
        else:
            lines.append("No strong public intelligence match found.")

        return _json_result(
            "\n".join(lines),
            vulnerability_intel=result.model_dump(mode="json"),
            known_vulnerability_matches=[
                match.model_dump(mode="json") for match in result.matches
            ],
        )


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
