"""Tool-call scheduling policy for one conversational Agent turn."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

DECOMPILE_TOOLS = {"decompile_function", "get_function_context"}
LIGHT_TOOLS = {
    "check_ida_backend",
    "detect_binary_architecture",
    "list_binary_imports",
    "list_binary_functions",
    "get_function_signals",
    "get_function_xrefs",
}
DISCOVERY_SCAN_TOOLS = {
    "find_web_route_handlers",
    "scan_indirect_calls",
    "scan_taint_source_candidates",
    "propagate_taint_sources",
    "scan_dangerous_sink_calls",
    "investigate_vulnerability_candidates",
}
FOCUSED_ANALYSIS_TOOLS = {
    "analyze_function_as_source",
    "find_function_sink_calls",
}
TAINT_TRACE_TOOLS = {
    "trace_taint_call_chain",
    "trace_argument_origin",
    "validate_sink_candidate",
}


@dataclass(frozen=True)
class SkippedToolCall:
    tool_call: dict[str, Any]
    reason: str


@dataclass(frozen=True)
class ToolSchedulingDecision:
    allowed_calls: list[dict[str, Any]]
    skipped_calls: list[SkippedToolCall]
    updates: dict[str, Any]
    request_final_answer: bool = False

    @property
    def has_skipped_calls(self) -> bool:
        return bool(self.skipped_calls)


@dataclass(frozen=True)
class AgentExecutionLimits:
    """Configurable dynamic scheduler limits applied independently to each user turn."""

    max_tool_calls: int = 48
    max_tool_loops: int = 24
    max_tool_calls_per_batch: int = 8
    max_decompile_calls: int = 20
    max_decompile_calls_per_batch: int = 4
    max_scan_calls: int = 24
    max_scan_calls_per_batch: int = 6
    max_taint_trace_calls: int = 24
    max_taint_trace_calls_per_batch: int = 6
    max_turn_seconds: float = 900.0
    tool_timeout_seconds: float = 90.0
    model_timeout_seconds: float = 180.0

    @classmethod
    def from_env(cls) -> AgentExecutionLimits:
        return cls(
            max_tool_calls=int(os.getenv("VULN_AGENT_MAX_TOOL_CALLS", "48")),
            max_tool_loops=int(os.getenv("VULN_AGENT_MAX_TOOL_LOOPS", "24")),
            max_tool_calls_per_batch=int(os.getenv("VULN_AGENT_MAX_TOOL_CALLS_PER_BATCH", "8")),
            max_decompile_calls=int(os.getenv("VULN_AGENT_MAX_DECOMPILE_CALLS", "20")),
            max_decompile_calls_per_batch=int(
                os.getenv("VULN_AGENT_MAX_DECOMPILE_CALLS_PER_BATCH", "4")
            ),
            max_scan_calls=int(os.getenv("VULN_AGENT_MAX_SCAN_CALLS", "24")),
            max_scan_calls_per_batch=int(os.getenv("VULN_AGENT_MAX_SCAN_CALLS_PER_BATCH", "6")),
            max_taint_trace_calls=int(os.getenv("VULN_AGENT_MAX_TAINT_TRACE_CALLS", "24")),
            max_taint_trace_calls_per_batch=int(
                os.getenv("VULN_AGENT_MAX_TAINT_TRACE_CALLS_PER_BATCH", "6")
            ),
            max_turn_seconds=float(os.getenv("VULN_AGENT_MAX_TURN_SECONDS", "900")),
            tool_timeout_seconds=float(os.getenv("VULN_AGENT_TOOL_TIMEOUT_SECONDS", "90")),
            model_timeout_seconds=float(os.getenv("VULN_AGENT_MODEL_TIMEOUT_SECONDS", "180")),
        )

    def remaining_seconds(self, started_at: float) -> float:
        return max(0.0, self.max_turn_seconds - (time.monotonic() - started_at))

    def schedule(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        started_at: float,
        tool_call_count: int,
        tool_loop_count: int,
        decompile_count: int,
        scan_count: int,
        tool_signatures: list[str],
        taint_trace_count: int = 0,
        tool_failure_counts: dict[str, int] | None = None,
    ) -> ToolSchedulingDecision:
        """Split tool calls into allowed and skipped calls without guessing user intent."""
        if self.remaining_seconds(started_at) <= 0:
            return _skip_all(
                tool_calls,
                "The per-turn execution time limit was reached.",
            )

        if tool_loop_count >= self.max_tool_loops:
            return _skip_all(tool_calls, f"Tool loop limit reached ({self.max_tool_loops}).")

        allowed: list[dict[str, Any]] = []
        skipped: list[SkippedToolCall] = []
        seen_batch_signatures: set[str] = set()
        next_tool_calls = tool_call_count
        next_decompile = decompile_count
        next_scans = scan_count
        next_taint_traces = taint_trace_count
        batch_decompile = 0
        batch_scans = 0
        batch_taint_traces = 0
        failures = tool_failure_counts or {}

        for tool_call in tool_calls:
            name = str(tool_call.get("name", "unknown"))
            signature = _tool_signature(tool_call)
            reason = ""
            if signature in tool_signatures or signature in seen_batch_signatures:
                reason = f"Duplicate tool call skipped: {signature}"
            elif failures.get(signature, 0) >= 2:
                reason = f"Tool retry limit reached after repeated failures: {signature}"
            elif next_tool_calls >= self.max_tool_calls:
                reason = f"Tool call limit reached ({self.max_tool_calls})."
            elif len(allowed) >= self.max_tool_calls_per_batch:
                reason = f"Per-batch tool call limit reached ({self.max_tool_calls_per_batch})."
            elif name in DECOMPILE_TOOLS and next_decompile >= self.max_decompile_calls:
                reason = f"Decompile limit reached ({self.max_decompile_calls})."
            elif name in DECOMPILE_TOOLS and batch_decompile >= self.max_decompile_calls_per_batch:
                reason = (
                    "Per-batch decompile limit reached "
                    f"({self.max_decompile_calls_per_batch})."
                )
            elif name in DISCOVERY_SCAN_TOOLS and next_scans >= self.max_scan_calls:
                reason = f"Discovery scan limit reached ({self.max_scan_calls})."
            elif name in DISCOVERY_SCAN_TOOLS and batch_scans >= self.max_scan_calls_per_batch:
                reason = f"Per-batch discovery scan limit reached ({self.max_scan_calls_per_batch})."
            elif name in TAINT_TRACE_TOOLS and next_taint_traces >= self.max_taint_trace_calls:
                reason = f"Taint trace limit reached ({self.max_taint_trace_calls})."
            elif (
                name in TAINT_TRACE_TOOLS
                and batch_taint_traces >= self.max_taint_trace_calls_per_batch
            ):
                reason = (
                    "Per-batch taint trace limit reached "
                    f"({self.max_taint_trace_calls_per_batch})."
                )

            if reason:
                skipped.append(SkippedToolCall(tool_call=tool_call, reason=reason))
                continue

            allowed.append(tool_call)
            seen_batch_signatures.add(signature)
            next_tool_calls += 1
            if name in DECOMPILE_TOOLS:
                next_decompile += 1
                batch_decompile += 1
            elif name in DISCOVERY_SCAN_TOOLS:
                next_scans += 1
                batch_scans += 1
            elif name in TAINT_TRACE_TOOLS:
                next_taint_traces += 1
                batch_taint_traces += 1

        return ToolSchedulingDecision(
            allowed_calls=allowed,
            skipped_calls=skipped,
            # A partially admitted batch must be allowed to continue. The model
            # should only be forced to answer when no requested tool can run.
            request_final_answer=bool(skipped) and not allowed,
            updates={
            "tool_call_count": next_tool_calls,
            "tool_loop_count": tool_loop_count + 1,
            "decompile_count": next_decompile,
            "scan_count": next_scans,
            "taint_trace_count": next_taint_traces,
            "tool_signatures": [
                *tool_signatures,
                *[_tool_signature(tool_call) for tool_call in allowed],
            ],
            },
        )



def budget_stop_message(reason: str, continuation: str = "") -> str:
    base = (
        "This investigation turn stopped because its execution budget was reached. "
        f"{reason}"
    )
    if continuation:
        return (
            f"{base}\n\n{continuation}\n\n"
            "Send a focused follow-up instruction such as \"continue validating the "
            "pending candidates\" to resume from this state."
        )
    return (
        base
        + " Review the completed tool results, then request a focused follow-up "
        "turn if more analysis is needed."
    )


def model_timeout_message(continuation: str = "") -> str:
    """Distinguish a transient model stall from a genuine budget condition."""
    base = (
        "The model call timed out before responding. This is a transient model stall, "
        "not a budget limit: retry the same instruction to continue the investigation "
        "with the budget left in this turn."
    )
    if continuation:
        return f"{base}\n\n{continuation}"
    return base


def _tool_signature(tool_call: dict[str, Any]) -> str:
    args = json.dumps(
        tool_call.get("args", {}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"{tool_call.get('name', 'unknown')}({args})"


def _skip_all(tool_calls: list[dict[str, Any]], reason: str) -> ToolSchedulingDecision:
    return ToolSchedulingDecision(
        allowed_calls=[],
        skipped_calls=[
            SkippedToolCall(tool_call=tool_call, reason=reason) for tool_call in tool_calls
        ],
        updates={},
        request_final_answer=True,
    )
