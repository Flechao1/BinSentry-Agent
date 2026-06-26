"""Deterministic baseline scan used by higher-level Agent orchestration."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from inspect import isawaitable
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from vulnagent.agent.investigation_state import (
    InvestigationState,
    merge_report_into_investigation_state,
)
from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.ida.schemas import SinkCallResult, SourcePropagateResult
from vulnagent.reports import (
    BinaryVulnerabilityReport,
    FileReportStore,
    SampleInfo,
    VulnerabilityFinding,
)
from vulnagent.rules import get_default_sink_specs


class BaselineScanConfig(BaseModel):
    source_limit: int = Field(default=100, ge=1, le=10000)
    source_min_score: float = Field(default=25.0, ge=0.0, le=100.0)
    source_max_rounds: int = Field(default=5, ge=0, le=20)
    sink_max_depth: int = Field(default=8, ge=0, le=64)
    sink_max_functions: int = Field(default=500, ge=1, le=10000)
    taint_max_depth: int = Field(default=20, ge=1, le=100)
    taint_max_chains: int = Field(default=5, ge=1, le=50)
    max_findings: int = Field(default=100, ge=1, le=1000)


class ScanProgress(BaseModel):
    stage: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


ProgressCallback = Callable[[ScanProgress], Awaitable[None] | None]


class ReportPersistence(Protocol):
    def persist_report(
        self,
        report: BinaryVulnerabilityReport,
        *,
        report_path: str = "",
        config: Any = None,
    ) -> str: ...


class BaselineScanner:
    """Run the bounded, deterministic part of a Web/CGI firmware audit."""

    def __init__(
        self,
        client: AsyncIdaClient,
        report_store: FileReportStore | str | Path,
        progress_callback: ProgressCallback | None = None,
        persistence: ReportPersistence | None = None,
    ) -> None:
        self.client = client
        self.report_store = (
            report_store
            if isinstance(report_store, FileReportStore)
            else FileReportStore(report_store)
        )
        self.progress_callback = progress_callback
        self.persistence = persistence

    async def _emit(self, stage: str, message: str, **data: Any) -> None:
        if self.progress_callback is None:
            return
        result = self.progress_callback(ScanProgress(stage=stage, message=message, data=data))
        if isawaitable(result):
            await result

    async def run(
        self,
        thread_id: str = "",
        config: BaselineScanConfig | None = None,
    ) -> BinaryVulnerabilityReport:
        config = config or BaselineScanConfig()

        await self._emit("check_backend", "Checking IDA backend")
        health = await self.client.validate_protocol()

        await self._emit("collect_metadata", "Collecting architecture and imports")
        arch = await self.client.detect_arch()
        imports = await self.client.get_imports()

        await self._emit("discover_entrypoints", "Discovering Web/CGI routes and sources")
        routes = await self.client.find_route_handlers()
        source_scan = await self.client.scan_source_candidates(
            limit=config.source_limit,
            min_score=config.source_min_score,
        )
        sources = _deduplicate(
            [candidate.name for candidate in source_scan.results]
            + [callee.name for callee in routes.cross_handler_callees]
        )

        await self._emit(
            "propagate_sources",
            "Propagating taint sources through wrappers",
            source_count=len(sources),
        )
        if sources:
            propagated = await self.client.propagate_sources(
                sources,
                max_rounds=config.source_max_rounds,
            )
        else:
            propagated = SourcePropagateResult()
        all_sources = _deduplicate(sources + propagated.new_sources)

        await self._emit(
            "scan_sinks",
            "Scanning dangerous sinks",
            route_count=len(routes.handlers),
            source_count=len(all_sources),
        )
        sink_scan = await self.client.scan_sink_calls(
            get_default_sink_specs(),
            roots=routes.handlers,
            max_depth=config.sink_max_depth,
            max_functions=config.sink_max_functions,
        )

        findings: list[VulnerabilityFinding] = []
        for sink in sink_scan.results[: config.max_findings]:
            await self._emit(
                "trace_taint",
                f"Tracing arguments for {sink.sink_name} at {sink.loc}",
                caller=sink.caller_addr,
            )
            findings.append(await self._build_finding(sink, all_sources, config))

        verified_count = sum(
            finding.verification_status == "verified" for finding in findings
        )
        summary = (
            f"Scanned {sink_scan.scanned_functions} function(s), identified "
            f"{len(sink_scan.results)} sink call(s), and produced {len(findings)} finding(s). "
            f"{verified_count} finding(s) have deterministic taint evidence. "
            f"Imports observed: {len(imports)}."
        )
        report = BinaryVulnerabilityReport(
            thread_id=thread_id,
            sample=SampleInfo(
                database=health.database,
                architecture=arch.arch,
                bits=arch.bits,
                endian=arch.endian,
            ),
            scope=sink_scan.scope,
            routes=routes.registrations,
            source_candidates=source_scan.results,
            findings=findings,
            summary=summary,
        )
        path = self.report_store.save(report)
        if self.persistence:
            self.persistence.persist_report(report, report_path=str(path), config=config)
            self._persist_investigation_state(thread_id, report)
        await self._emit(
            "persist_report",
            "Saved JSON and SQLite vulnerability report",
            report_id=report.report_id,
            path=str(path),
        )
        return report

    def _persist_investigation_state(
        self,
        thread_id: str,
        report: BinaryVulnerabilityReport,
    ) -> None:
        if not thread_id or self.persistence is None:
            return
        get_state = getattr(self.persistence, "get_investigation_state", None)
        save_state = getattr(self.persistence, "save_investigation_state", None)
        get_thread = getattr(self.persistence, "get_chat_thread", None)
        if not callable(get_state) or not callable(save_state):
            return
        if callable(get_thread) and get_thread(thread_id) is None:
            return
        state = InvestigationState.model_validate(get_state(thread_id) or {})
        merge_report_into_investigation_state(state, report)
        save_state(thread_id, state.model_dump(mode="json"))

    async def _build_finding(
        self,
        sink: SinkCallResult,
        sources: list[str],
        config: BaselineScanConfig,
    ) -> VulnerabilityFinding:
        chains = []
        for argument in sink.args:
            if argument.get("arg_type") == "constant":
                continue
            arg_index = int(argument.get("index", 1))
            chains.extend(
                await self.client.trace_call_chain(
                    sink.caller_addr,
                    arg_index=arg_index,
                    sources=sources,
                    max_depth=config.taint_max_depth,
                    max_chains=config.taint_max_chains,
                )
            )

        verified = any(chain.taint_verified for chain in chains)
        source_names = _deduplicate(
            [
                node.source_func
                for chain in chains
                for node in chain.chain
                if node.source_func
            ]
        )
        evidence = [
            f"{sink.caller_name} calls {sink.sink_name} at {sink.loc}",
            *[f"Taint chain: {chain.chain_str}" for chain in chains],
        ]
        return VulnerabilityFinding(
            category=_sink_category(sink.sink_name),
            severity=_sink_severity(sink.sink_name, verified),
            confidence=0.9 if verified else min(max(sink.confidence, 0.1), 0.7),
            sink=sink,
            source=", ".join(source_names),
            call_chains=chains,
            evidence=evidence,
            remediation=_sink_remediation(sink.sink_name),
            verification_status="verified" if verified else "unverified",
        )


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _sink_category(sink_name: str) -> str:
    command_sinks = {
        "system",
        "popen",
        "exec",
        "execl",
        "execlp",
        "execle",
        "execv",
        "execvp",
        "execve",
        "doSystem",
    }
    if sink_name in command_sinks:
        return "command-injection"
    return "memory-safety"


def _sink_severity(sink_name: str, verified: bool) -> str:
    if not verified:
        return "medium"
    return "critical" if _sink_category(sink_name) == "command-injection" else "high"


def _sink_remediation(sink_name: str) -> str:
    if _sink_category(sink_name) == "command-injection":
        return (
            "Avoid shell execution for user-controlled data; use fixed argument vectors "
            "and strict allowlists."
        )
    return (
        "Use bounded operations, validate lengths, and ensure destination buffers are "
        "sized correctly."
    )
