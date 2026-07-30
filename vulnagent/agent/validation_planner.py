"""Deterministic sink-validation planning for binary vulnerability investigations."""

from __future__ import annotations

import re
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from vulnagent.ida.schemas import ArgumentOriginResult, SinkCallResult


CandidateStatus = Literal["pending", "verified", "unverified", "rejected"]

COMMAND_SINKS = {
    "system",
    "popen",
    "exec",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "execve",
    "dosystem",
    "do_system",
    "eval",
    "fork_exec",
    "twsystem",
    "cstesystem",
}
MEMORY_SINKS = {
    "strcpy",
    "strcat",
    "strncat",
    "sprintf",
    "vsprintf",
    "sscanf",
    "memcpy",
    "memmove",
    "gets",
}
REMOTE_SOURCE_HINTS = (
    "webs",
    "cgi",
    "http",
    "https",
    "request",
    "req",
    "query",
    "form",
    "post",
    "get",
    "cookie",
    "header",
    "param",
    "parameter",
    "upload",
    "uri",
    "url",
    "soap",
    "xml",
    "json",
    "ubus",
    "nvram",
    "config",
    "recv",
    "recvfrom",
    "read",
    "socket",
)


class ArgumentValidation(BaseModel):
    index: int
    expression: str = ""
    arg_type: str = "unknown"
    taint_status: str = "unknown"
    source_func: str = ""
    source_expr: str = ""
    reason: str = ""


class CandidateFinding(BaseModel):
    """One independently verifiable source-to-sink investigation task."""

    candidate_id: str
    status: CandidateStatus = "pending"
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    sink_name: str
    sink_ea: str
    caller_name: str
    caller_ea: str
    callee_ea: str = ""
    arguments: list[ArgumentValidation] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    conclusion: str = "Awaiting argument-origin validation."


class ArgumentOriginClient(Protocol):
    def trace_argument_origin(
        self,
        caller_ea: int | str,
        call_site: int | str,
        callee_ea: int | str,
        target_arg_idx: int = 1,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult: ...


class ValidationPlanner:
    """Create and validate evidence-backed candidates without LLM guesswork."""

    def plan(self, sink: SinkCallResult) -> CandidateFinding:
        arguments = [
            ArgumentValidation(
                index=int(argument.get("index", 0) or 0),
                expression=str(argument.get("expr", "")),
                arg_type=str(argument.get("arg_type", "unknown")),
            )
            for argument in sink.args
            if int(argument.get("index", 0) or 0) > 0
        ]
        category = _category(sink.sink_name)
        return CandidateFinding(
            candidate_id=_candidate_id(sink),
            category=category,
            severity="high" if category == "command-injection" else "medium",
            confidence=min(max(float(sink.confidence), 0.1), 0.7),
            sink_name=sink.sink_name,
            sink_ea=sink.loc,
            caller_name=sink.caller_name,
            caller_ea=sink.caller_addr,
            callee_ea=sink.callee_ea,
            arguments=arguments,
            evidence=[f"{sink.caller_name} calls {sink.sink_name} at {sink.loc}."],
            missing_evidence=[
                "Trace each non-constant dangerous argument to a trusted input source.",
                _boundary_requirement(category),
            ],
        )

    def validate(
        self,
        sink: SinkCallResult,
        client: ArgumentOriginClient,
        *,
        known_sources: list[str] | None = None,
    ) -> CandidateFinding:
        candidate = self.plan(sink)
        if not sink.callee_ea or not candidate.arguments:
            return self.evaluate(candidate)

        origins: dict[int, ArgumentOriginResult] = {}
        for argument in candidate.arguments:
            origins[argument.index] = client.trace_argument_origin(
                caller_ea=sink.caller_addr,
                call_site=sink.loc,
                callee_ea=sink.callee_ea,
                target_arg_idx=argument.index,
                sources=known_sources or None,
            )
        return self.apply_origins(candidate, origins)

    def apply_origins(
        self,
        candidate: CandidateFinding,
        origins: dict[int, ArgumentOriginResult],
    ) -> CandidateFinding:
        for argument in candidate.arguments:
            origin = origins.get(argument.index)
            if origin is not None:
                _apply_origin(argument, origin)
        return self.evaluate(candidate)

    def evaluate(self, candidate: CandidateFinding) -> CandidateFinding:
        if not candidate.arguments:
            candidate.status = "rejected"
            candidate.confidence = 0.1
            candidate.conclusion = "No non-constant dangerous sink arguments were observed."
            return candidate

        remote_inputs = [
            argument
            for argument in candidate.arguments
            if is_trusted_remote_source(argument.source_func) and argument.taint_status.lower() in {"tainted", "verified"}
        ]
        all_clean = candidate.arguments and all(
            argument.taint_status.lower() == "clean" for argument in candidate.arguments
        )
        candidate.evidence.extend(_argument_evidence(candidate.arguments))

        if all_clean:
            candidate.status = "rejected"
            candidate.confidence = 0.85
            candidate.conclusion = "All dangerous arguments were statically classified as clean."
            candidate.missing_evidence = []
            return candidate

        if remote_inputs and candidate.category == "command-injection":
            candidate.status = "verified"
            candidate.severity = "critical"
            candidate.confidence = 0.9
            candidate.conclusion = "A trusted remote-input source reaches a command-execution argument."
            candidate.missing_evidence = [
                "Confirm runtime reachability and any command-specific allowlist before exploitation testing."
            ]
            return candidate

        if not candidate.callee_ea:
            candidate.status = "unverified"
            candidate.conclusion = (
                "The sink target address is unavailable; argument origin could not be "
                "proven by the available fallback evidence."
            )
            candidate.missing_evidence.append("Resolve the sink callee address in IDA.")
            return candidate

        candidate.status = "unverified"
        candidate.confidence = 0.65 if remote_inputs else 0.35
        if remote_inputs:
            candidate.confidence = max(candidate.confidence, 0.75)
            candidate.severity = "high"
            candidate.conclusion = (
                "A remote-input source reaches a memory-operation argument, but destination size "
                "and effective bounds checks are not yet proven."
            )
        else:
            candidate.conclusion = "No trusted remote-input source was proven for the dangerous argument."
        return candidate


def _apply_origin(argument: ArgumentValidation, origin: ArgumentOriginResult) -> None:
    argument.taint_status = origin.taint_status
    argument.source_func = origin.source_func
    argument.source_expr = origin.source_expr
    argument.reason = origin.reason


def _category(sink_name: str) -> str:
    name = sink_name.lower()
    if name in COMMAND_SINKS:
        return "command-injection"
    if name in MEMORY_SINKS:
        return "memory-safety"
    return "unknown"


def _candidate_id(sink: SinkCallResult) -> str:
    return f"{sink.sink_name}:{sink.caller_addr}:{sink.loc}".lower()


def is_trusted_remote_source(source_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", source_name.lower())
    return bool(normalized) and any(hint in normalized for hint in REMOTE_SOURCE_HINTS)


def _boundary_requirement(category: str) -> str:
    if category == "memory-safety":
        return "Prove destination buffer size and whether an effective bounds check exists."
    if category == "command-injection":
        return "Prove the command argument is reachable from a remote request and not safely allowlisted."
    return "Classify the sink semantics and validate whether input is user-controlled."


def _argument_evidence(arguments: list[ArgumentValidation]) -> list[str]:
    evidence: list[str] = []
    for argument in arguments:
        source = argument.source_func or "unresolved"
        evidence.append(
            f"Argument {argument.index} ({argument.expression or '?'}) is "
            f"{argument.taint_status}; source={source}."
        )
    return evidence
