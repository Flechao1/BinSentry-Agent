"""Structured request and result models for VulnAgent harness runs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from langchain_core.messages import BaseMessage
from pydantic import BaseModel, ConfigDict, Field

from vulnagent.agent.baseline_scan import BaselineScanConfig
from vulnagent.reports import BinaryVulnerabilityReport


HarnessMode = Literal["agent_chat", "baseline_scan"]
HarnessStatus = Literal["completed", "failed", "canceled"]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HarnessTraceEvent(BaseModel):
    """One observable event in a harness-managed run."""

    event_id: str = Field(default_factory=lambda: uuid4().hex)
    run_id: str
    event_type: str
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utc_now)


class HarnessTurnRequest(BaseModel):
    """Input for one conversational Agent turn."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    prompt: str
    thread_id: str = ""
    messages: list[BaseMessage] = Field(default_factory=list)
    ida_backend_url: str = "http://127.0.0.1:8765"
    report_dir: str = "./reports"


class HarnessBaselineScanRequest(BaseModel):
    """Input for one deterministic baseline scan run."""

    thread_id: str = ""
    ida_backend_url: str = "http://127.0.0.1:8765"
    report_dir: str = "./reports"
    config: BaselineScanConfig = Field(default_factory=BaselineScanConfig)


class HarnessRunResult(BaseModel):
    """Structured output produced by the harness after a run finishes."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    run_id: str = Field(default_factory=lambda: uuid4().hex)
    mode: HarnessMode
    status: HarnessStatus
    thread_id: str = ""
    answer: str = ""
    messages: list[BaseMessage] = Field(default_factory=list)
    report_id: str = ""
    report: BinaryVulnerabilityReport | None = None
    tool_events: list[dict[str, Any]] = Field(default_factory=list)
    trace_events: list[HarnessTraceEvent] = Field(default_factory=list)
    error: str = ""
    started_at: datetime = Field(default_factory=_utc_now)
    finished_at: datetime = Field(default_factory=_utc_now)
