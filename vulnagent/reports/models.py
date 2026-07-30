"""Pydantic models for binary vulnerability analysis reports."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from vulnagent.ida.schemas import (
    CallChainResult,
    RouteRegistration,
    SinkCallResult,
    SourceCandidate,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SampleInfo(BaseModel):
    """Metadata describing the analyzed binary / IDA database."""

    database: str = ""
    architecture: str = ""
    bits: int = 0
    endian: str = ""


class ArgumentRecord(BaseModel):
    """One validated sink-argument recorded in a report candidate."""

    index: int
    expression: str = ""
    arg_type: str = "unknown"
    taint_status: str = "unknown"
    source_func: str = ""
    source_expr: str = ""
    reason: str = ""


class CandidateFindingRecord(BaseModel):
    """A persisted, independently verifiable source-to-sink candidate.

    Mirrors :class:`vulnagent.agent.validation_planner.CandidateFinding` so reports can
    be reconstructed from ``CandidateFinding.model_dump(mode="json")`` without importing
    the agent layer (which would create a circular import).
    """

    candidate_id: str
    status: Literal["pending", "verified", "unverified", "rejected"] = "pending"
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sink_name: str
    sink_ea: str
    caller_name: str
    caller_ea: str
    callee_ea: str = ""
    arguments: list[ArgumentRecord] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    conclusion: str = "Awaiting argument-origin validation."


class VulnerabilityFinding(BaseModel):
    """One confirmed or candidate vulnerability finding in a report."""

    finding_id: str = Field(default_factory=lambda: uuid4().hex)
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sink: SinkCallResult
    source: str = ""
    call_chains: list[CallChainResult] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    llm_review: str = ""
    remediation: str = ""
    verification_status: Literal["verified", "unverified", "rejected", "pending"] = "unverified"


class BinaryVulnerabilityReport(BaseModel):
    """The complete, serializable result of one vulnerability analysis run."""

    report_id: str = Field(default_factory=lambda: uuid4().hex)
    report_version: str = "1.0"
    created_at: datetime = Field(default_factory=_utc_now)
    thread_id: str = ""
    sample: SampleInfo
    scope: str = "global-fallback"
    routes: list[RouteRegistration] = Field(default_factory=list)
    source_candidates: list[SourceCandidate] = Field(default_factory=list)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    candidate_findings: list[CandidateFindingRecord] = Field(default_factory=list)
    summary: str = ""
