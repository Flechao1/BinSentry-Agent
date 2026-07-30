"""VulnAgent V2 package."""

__version__ = "0.4.0"

from vulnagent.harness import (
    BinaryVulnAgentHarness,
    HarnessBaselineScanRequest,
    HarnessRunResult,
    HarnessTraceEvent,
    HarnessTurnRequest,
)

__all__ = [
    "__version__",
    "BinaryVulnAgentHarness",
    "HarnessBaselineScanRequest",
    "HarnessRunResult",
    "HarnessTraceEvent",
    "HarnessTurnRequest",
]
