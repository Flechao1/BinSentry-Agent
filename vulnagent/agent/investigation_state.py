from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

MAX_ROUTES = 50
MAX_SOURCES = 30
MAX_SINKS = 30
MAX_FINDINGS = 30
MAX_RULED_OUT = 30
MAX_CANDIDATES = 50
MAX_QUESTIONS = 30
MAX_FUNCTIONS = 80
MAX_FUNCTION_NOTES = 80
MAX_INDIRECT_CALLS = 40
MAX_PROCESSED_TOOL_RESULTS = 200
MAX_TEXT_LENGTH = 160


class ConfirmedRoute(BaseModel):
    route: str
    handler_name: str = ""
    handler_ea: str = ""
    registration_name: str = ""
    registration_ea: str = ""


class PendingSink(BaseModel):
    sink_name: str
    sink_ea: str = ""
    caller_name: str = ""
    caller_ea: str = ""
    category: str = ""
    reason: str = ""


class CandidateFindingState(BaseModel):
    candidate_id: str
    status: str = "pending"
    category: str = "unknown"
    sink_name: str = ""
    sink_ea: str = ""
    caller_name: str = ""
    caller_ea: str = ""
    confidence: float = 0.0
    conclusion: str = ""
    missing_evidence: list[str] = Field(default_factory=list)


class InvestigationState(BaseModel):
    """Structured short-term state injected into each Agent model call."""

    objective: str = "Audit the active Web/CGI firmware binary for evidence-backed vulnerabilities."
    phase: str = "initial_recon"
    confirmed_routes: list[ConfirmedRoute] = Field(default_factory=list)
    source_candidates: list[str] = Field(default_factory=list)
    confirmed_sources: list[str] = Field(default_factory=list)
    pending_sinks: list[PendingSink] = Field(default_factory=list)
    candidate_findings: list[CandidateFindingState] = Field(default_factory=list)
    indirect_call_sites: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    verified_findings: list[str] = Field(default_factory=list)
    ruled_out_paths: list[str] = Field(default_factory=list)
    active_function: str = ""
    active_sink: dict[str, Any] = Field(default_factory=dict)
    investigated_functions: list[str] = Field(default_factory=list)
    function_notes: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    processed_tool_result_ids: list[str] = Field(default_factory=list)

    def add_route(self, route: ConfirmedRoute) -> None:
        route = _compact_route(route)
        key = (route.route, route.handler_ea or route.handler_name)
        if key not in {
            (existing.route, existing.handler_ea or existing.handler_name)
            for existing in self.confirmed_routes
        }:
            self.confirmed_routes.append(route)
        self.confirmed_routes = self.confirmed_routes[-MAX_ROUTES:]

    def add_source_candidate(self, source: str) -> None:
        _append_unique(self.source_candidates, source, MAX_SOURCES)

    def add_confirmed_source(self, source: str) -> None:
        source = _clip(source)
        if not source:
            return
        _append_unique(self.confirmed_sources, source, MAX_SOURCES)
        self.source_candidates = [
            candidate for candidate in self.source_candidates if candidate != source
        ]

    def add_pending_sink(self, sink: PendingSink) -> None:
        sink = _compact_sink(sink)
        key = (sink.sink_name, sink.sink_ea, sink.caller_ea)
        if key not in {
            (existing.sink_name, existing.sink_ea, existing.caller_ea)
            for existing in self.pending_sinks
        }:
            self.pending_sinks.append(sink)
        self.pending_sinks = self.pending_sinks[-MAX_SINKS:]

    def add_candidate_finding(self, candidate: CandidateFindingState) -> None:
        candidate = _compact_candidate(candidate)
        for index, existing in enumerate(self.candidate_findings):
            if existing.candidate_id == candidate.candidate_id:
                self.candidate_findings[index] = candidate
                break
        else:
            self.candidate_findings.append(candidate)
        self.candidate_findings = self.candidate_findings[-MAX_CANDIDATES:]

    def add_missing_evidence(self, question: str) -> None:
        _append_unique(self.missing_evidence, question, MAX_QUESTIONS)

    def add_indirect_call_site(self, site: str) -> None:
        _append_unique(self.indirect_call_sites, site, MAX_INDIRECT_CALLS)

    def add_verified_finding(self, finding: str) -> None:
        _append_unique(self.verified_findings, finding, MAX_FINDINGS)

    def add_ruled_out_path(self, path: str) -> None:
        _append_unique(self.ruled_out_paths, path, MAX_RULED_OUT)

    def add_function_note(self, note: str) -> None:
        _append_unique(self.function_notes, note, MAX_FUNCTION_NOTES)

    def resolve_sink(self, *addresses: str) -> None:
        resolved = {str(address).strip() for address in addresses if str(address).strip()}
        if not resolved:
            return
        self.pending_sinks = [
            sink
            for sink in self.pending_sinks
            if sink.sink_ea not in resolved and sink.caller_ea not in resolved
        ]
        self.missing_evidence = [
            question
            for question in self.missing_evidence
            if not any(address in question for address in resolved)
        ]

    def mark_tool_result_processed(self, tool_call_id: str) -> None:
        _append_unique(
            self.processed_tool_result_ids,
            tool_call_id,
            MAX_PROCESSED_TOOL_RESULTS,
        )

    def compact(self) -> None:
        self.objective = _clip(self.objective)
        self.phase = _clip(self.phase)
        self.confirmed_routes = [
            _compact_route(route) for route in self.confirmed_routes[-MAX_ROUTES:]
        ]
        self.source_candidates = _bounded_unique(self.source_candidates, MAX_SOURCES)
        self.confirmed_sources = _bounded_unique(self.confirmed_sources, MAX_SOURCES)
        self.pending_sinks = [
            _compact_sink(sink) for sink in self.pending_sinks[-MAX_SINKS:]
        ]
        self.candidate_findings = [
            _compact_candidate(candidate)
            for candidate in self.candidate_findings[-MAX_CANDIDATES:]
        ]
        self.indirect_call_sites = _bounded_unique(
            self.indirect_call_sites,
            MAX_INDIRECT_CALLS,
        )
        self.missing_evidence = _bounded_unique(self.missing_evidence, MAX_QUESTIONS)
        self.verified_findings = _bounded_unique(self.verified_findings, MAX_FINDINGS)
        self.ruled_out_paths = _bounded_unique(self.ruled_out_paths, MAX_RULED_OUT)
        self.active_function = _clip(self.active_function)
        self.active_sink = {
            _clip(str(key)): _clip_value(value)
            for key, value in list(self.active_sink.items())[:12]
        }
        self.investigated_functions = _bounded_unique(
            self.investigated_functions,
            MAX_FUNCTIONS,
        )
        self.function_notes = _bounded_unique(self.function_notes, MAX_FUNCTION_NOTES)
        self.open_questions = _bounded_unique(self.open_questions, MAX_QUESTIONS)
        self.processed_tool_result_ids = _bounded_unique(
            self.processed_tool_result_ids,
            MAX_PROCESSED_TOOL_RESULTS,
        )

    def prompt_dump(self) -> dict[str, Any]:
        """Return compact state fields suitable for the LLM system prompt."""
        return self.model_dump(mode="json", exclude={"processed_tool_result_ids"})


def merge_report_into_investigation_state(state: InvestigationState, report: Any) -> None:
    """Merge deterministic Baseline Scan evidence into conversational state."""
    for route in report.routes:
        state.add_route(
            ConfirmedRoute(
                route=route.route_name,
                handler_name=route.handler_name,
                handler_ea=route.handler_ea,
                registration_name=route.registration_name,
                registration_ea=route.registration_ea,
            )
        )
    for candidate in report.source_candidates:
        state.add_source_candidate(candidate.name)
    report_candidates = {
        candidate.candidate_id: candidate
        for candidate in getattr(report, "candidate_findings", [])
    }
    for candidate in report_candidates.values():
        state.add_candidate_finding(
            CandidateFindingState(
                candidate_id=candidate.candidate_id,
                status=candidate.status,
                category=candidate.category,
                sink_name=candidate.sink_name,
                sink_ea=candidate.sink_ea,
                caller_name=candidate.caller_name,
                caller_ea=candidate.caller_ea,
                confidence=candidate.confidence,
                conclusion=candidate.conclusion,
                missing_evidence=candidate.missing_evidence,
            )
        )
        for question in candidate.missing_evidence:
            state.add_missing_evidence(question)
    for finding in report.findings:
        sink = finding.sink
        candidate_id = f"{sink.sink_name}:{sink.caller_addr}:{sink.loc}".lower()
        if candidate_id not in report_candidates:
            # Reports created before Candidate Finding support retain the prior state shape.
            state.add_candidate_finding(
                CandidateFindingState(
                    candidate_id=candidate_id,
                    status=finding.verification_status,
                    category=finding.category,
                    sink_name=sink.sink_name,
                    sink_ea=sink.loc,
                    caller_name=sink.caller_name,
                    caller_ea=sink.caller_addr,
                    confidence=finding.confidence,
                    conclusion=(
                        finding.evidence[0]
                        if finding.evidence
                        else finding.verification_status
                    ),
                )
            )
        state.add_pending_sink(
            PendingSink(
                sink_name=sink.sink_name,
                sink_ea=sink.loc,
                caller_name=sink.caller_name,
                caller_ea=sink.caller_addr,
                category=sink.category,
                reason=finding.verification_status,
            )
        )
        if finding.verification_status == "verified":
            for source in finding.source.split(","):
                state.add_confirmed_source(source.strip())
            state.resolve_sink(sink.loc, sink.caller_addr)
            state.add_verified_finding(
                f"{sink.sink_name} @ {sink.loc}: {finding.source or 'source-to-sink chain verified'}"
            )
        else:
            state.add_missing_evidence(
                f"Validate whether user-controlled input reaches {sink.sink_name} @ {sink.loc}."
            )
    state.compact()


def _append_unique(values: list[str], value: str, limit: int) -> None:
    value = _clip(value)
    if value and value not in values:
        values.append(value)
    del values[:-limit]


def _bounded_unique(values: list[str], limit: int) -> list[str]:
    bounded: list[str] = []
    for value in values:
        _append_unique(bounded, value, limit)
    return bounded


def _clip(value: str) -> str:
    return str(value).strip()[:MAX_TEXT_LENGTH]


def _compact_route(route: ConfirmedRoute) -> ConfirmedRoute:
    return ConfirmedRoute(
        route=_clip(route.route),
        handler_name=_clip(route.handler_name),
        handler_ea=_clip(route.handler_ea),
        registration_name=_clip(route.registration_name),
        registration_ea=_clip(route.registration_ea),
    )


def _compact_sink(sink: PendingSink) -> PendingSink:
    return PendingSink(
        sink_name=_clip(sink.sink_name),
        sink_ea=_clip(sink.sink_ea),
        caller_name=_clip(sink.caller_name),
        caller_ea=_clip(sink.caller_ea),
        category=_clip(sink.category),
        reason=_clip(sink.reason),
    )


def _compact_candidate(candidate: CandidateFindingState) -> CandidateFindingState:
    return CandidateFindingState(
        candidate_id=_clip(candidate.candidate_id),
        status=_clip(candidate.status),
        category=_clip(candidate.category),
        sink_name=_clip(candidate.sink_name),
        sink_ea=_clip(candidate.sink_ea),
        caller_name=_clip(candidate.caller_name),
        caller_ea=_clip(candidate.caller_ea),
        confidence=max(0.0, min(float(candidate.confidence), 1.0)),
        conclusion=_clip(candidate.conclusion),
        missing_evidence=_bounded_unique(candidate.missing_evidence, MAX_QUESTIONS),
    )


def _clip_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_clip(str(item)) for item in value[:12]]
    if isinstance(value, dict):
        return {
            _clip(str(key)): _clip_value(item)
            for key, item in list(value.items())[:12]
        }
    return _clip(str(value))
