"""Known-vulnerability intelligence lookup for VulnAgent findings."""

from vulnagent.intel.schema import (
    IntelMatch,
    IntelQuery,
    IntelReference,
    IntelSearchResult,
)
from vulnagent.intel.service import VulnerabilityIntelService
from vulnagent.intel.cveorg import CveOrgCrawlerClient

__all__ = [
    "CveOrgCrawlerClient",
    "IntelMatch",
    "IntelQuery",
    "IntelReference",
    "IntelSearchResult",
    "VulnerabilityIntelService",
]
