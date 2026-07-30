"""Runtime harness that standardizes VulnAgent task execution."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage

from vulnagent.agent.baseline_scan import BaselineScanner, ScanProgress
from vulnagent.agent.standalone import StandaloneBinaryVulnerabilityAgent
from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.harness.schemas import (
    HarnessBaselineScanRequest,
    HarnessRunResult,
    HarnessTraceEvent,
    HarnessTurnRequest,
)
from vulnagent.reports import FileReportStore
from vulnagent.storage import SqliteVulnRepository


ProgressCallback = Callable[[ScanProgress], Any]


class BinaryVulnAgentHarness:
    """Unified runtime boundary for chat turns, scans, state, and traces."""

    def __init__(
        self,
        *,
        repository: SqliteVulnRepository | None = None,
        timeout: float = 120.0,
        agent_runtime: Any | None = None,
    ) -> None:
        self.repository = repository or SqliteVulnRepository.from_env()
        self.timeout = timeout
        self.agent_runtime = agent_runtime

    async def run_agent_chat(
        self,
        request: HarnessTurnRequest,
    ) -> HarnessRunResult:
        """Run one user prompt through the conversational Agent and persist history."""
        run_id = uuid4().hex
        trace = [
            self._event(
                run_id,
                "run_started",
                "Agent chat run started",
                {"thread_id": request.thread_id},
            )
        ]
        try:
            runtime = self.agent_runtime or StandaloneBinaryVulnerabilityAgent(
                ida_backend_url=request.ida_backend_url,
                report_dir=request.report_dir,
                repository=self.repository,
            )
            messages = await runtime.ask(
                request.prompt,
                request.messages,
                thread_id=request.thread_id,
            )
            if request.thread_id:
                self.repository.save_chat_messages(request.thread_id, messages)
            answer = self._last_ai_text(messages)
            tool_events = (
                self.repository.list_tool_events(request.thread_id)
                if request.thread_id
                else []
            )
            trace.append(
                self._event(
                    run_id,
                    "run_completed",
                    "Agent chat run completed",
                    {
                        "message_count": len(messages),
                        "tool_event_count": len(tool_events),
                    },
                )
            )
            result = HarnessRunResult(
                run_id=run_id,
                mode="agent_chat",
                status="completed",
                thread_id=request.thread_id,
                answer=answer,
                messages=messages,
                tool_events=tool_events,
                trace_events=trace,
                started_at=trace[0].created_at,
                finished_at=trace[-1].created_at,
            )
            self._persist_result(result)
            return result
        except asyncio.CancelledError:
            trace.append(
                self._event(
                    run_id,
                    "run_canceled",
                    "Agent chat run canceled",
                    {"thread_id": request.thread_id},
                )
            )
            messages = [
                *request.messages,
                HumanMessage(content=request.prompt),
                AIMessage(content="Request canceled by user before completion."),
            ]
            if request.thread_id:
                self.repository.save_chat_messages(request.thread_id, messages)
            result = HarnessRunResult(
                run_id=run_id,
                mode="agent_chat",
                status="canceled",
                thread_id=request.thread_id,
                answer="Request canceled by user before completion.",
                messages=messages,
                trace_events=trace,
                started_at=trace[0].created_at,
                finished_at=trace[-1].created_at,
            )
            self._persist_result(result)
            return result
        except Exception as exc:  # noqa: BLE001 - return structured harness failures
            trace.append(
                self._event(
                    run_id,
                    "run_failed",
                    "Agent chat run failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            )
            result = HarnessRunResult(
                run_id=run_id,
                mode="agent_chat",
                status="failed",
                thread_id=request.thread_id,
                error=f"{type(exc).__name__}: {exc}",
                trace_events=trace,
                started_at=trace[0].created_at,
                finished_at=trace[-1].created_at,
            )
            self._persist_result(result)
            return result

    async def run_baseline_scan(
        self,
        request: HarnessBaselineScanRequest,
        progress_callback: ProgressCallback | None = None,
    ) -> HarnessRunResult:
        """Run deterministic baseline scan through the same harness boundary."""
        run_id = uuid4().hex
        trace = [
            self._event(
                run_id,
                "run_started",
                "Baseline scan run started",
                {"thread_id": request.thread_id},
            )
        ]

        def progress(progress: ScanProgress) -> None:
            trace.append(
                self._event(
                    run_id,
                    "progress",
                    progress.message,
                    {"stage": progress.stage, **progress.data},
                )
            )
            if progress_callback:
                progress_callback(progress)

        try:
            async with AsyncIdaClient(
                request.ida_backend_url,
                timeout=self.timeout,
            ) as client:
                report = await BaselineScanner(
                    client,
                    FileReportStore(Path(request.report_dir)),
                    progress_callback=progress,
                    persistence=self.repository,
                ).run(
                    thread_id=request.thread_id,
                    config=request.config,
                )
            trace.append(
                self._event(
                    run_id,
                    "run_completed",
                    "Baseline scan run completed",
                    {
                        "report_id": report.report_id,
                        "finding_count": len(report.findings),
                    },
                )
            )
            result = HarnessRunResult(
                run_id=run_id,
                mode="baseline_scan",
                status="completed",
                thread_id=request.thread_id,
                answer=report.summary,
                report_id=report.report_id,
                report=report,
                tool_events=(
                    self.repository.list_tool_events(request.thread_id)
                    if request.thread_id
                    else []
                ),
                trace_events=trace,
                started_at=trace[0].created_at,
                finished_at=trace[-1].created_at,
            )
            self._persist_result(result)
            return result
        except Exception as exc:  # noqa: BLE001 - surface structured failure
            trace.append(
                self._event(
                    run_id,
                    "run_failed",
                    "Baseline scan run failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            )
            result = HarnessRunResult(
                run_id=run_id,
                mode="baseline_scan",
                status="failed",
                thread_id=request.thread_id,
                error=f"{type(exc).__name__}: {exc}",
                trace_events=trace,
                started_at=trace[0].created_at,
                finished_at=trace[-1].created_at,
            )
            self._persist_result(result)
            return result

    @staticmethod
    def _event(
        run_id: str,
        event_type: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> HarnessTraceEvent:
        return HarnessTraceEvent(
            run_id=run_id,
            event_type=event_type,
            message=message,
            data=data or {},
        )

    @staticmethod
    def _last_ai_text(messages: list[BaseMessage]) -> str:
        for message in reversed(messages):
            if isinstance(message, AIMessage) and message.content:
                return str(message.content)
        return ""

    def _persist_result(self, result: HarnessRunResult) -> None:
        persist = getattr(self.repository, "persist_harness_run", None)
        if not callable(persist):
            return
        persist(
            run_id=result.run_id,
            mode=result.mode,
            status=result.status,
            thread_id=result.thread_id,
            report_id=result.report_id,
            answer=result.answer,
            error=result.error,
            started_at=result.started_at.isoformat(),
            finished_at=result.finished_at.isoformat(),
            trace_events=result.trace_events,
            metadata={
                "tool_event_count": len(result.tool_events),
                "trace_event_count": len(result.trace_events),
            },
        )
