"""LangGraph builder for the binary vulnerability analysis Agent."""

from __future__ import annotations

import asyncio
import html
import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import StreamWriter

from vulnagent.agent.baseline_scan import BaselineScanner
from vulnagent.agent.context_builder import ContextBudget, trim_messages_for_model
from vulnagent.agent.execution_limits import (
    AgentExecutionLimits,
    SkippedToolCall,
    _tool_signature,
    budget_stop_message,
    model_timeout_message,
)
from vulnagent.agent.progress import ToolkitTaskProgressWriter
from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.clients.ida_client import IdaClient
from vulnagent.reports import FileReportStore
from vulnagent.storage import SqliteVulnRepository
from vulnagent.tools.langchain_tools import build_readonly_ida_tools
from vulnagent.tools.langgraph_write_tools import build_confirmed_write_tools, build_direct_write_tools


ModelFactory = Callable[[RunnableConfig], BaseChatModel]


_DSML_TOOL_BLOCK_RE = re.compile(
    r"<[^>]*DSML[^>]*tool_calls[^>]*>(?P<body>.*?)</[^>]*DSML[^>]*tool_calls[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_DSML_INVOKE_RE = re.compile(
    r"<[^>]*DSML[^>]*invoke\s+name=[\"'](?P<name>[^\"']+)[\"'][^>]*>"
    r"(?P<body>.*?)</[^>]*DSML[^>]*invoke[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_DSML_PARAMETER_RE = re.compile(
    r"<[^>]*DSML[^>]*parameter\s+name=[\"'](?P<name>[^\"']+)[\"'][^>]*>"
    r"(?P<value>.*?)</[^>]*DSML[^>]*parameter[^>]*>",
    re.IGNORECASE | re.DOTALL,
)


def _normalize_model_tool_calls(response: AIMessage) -> AIMessage:
    """Convert DeepSeek's raw DSML tool syntax to LangChain tool calls.

    Some OpenAI-compatible DeepSeek deployments return tool calls in the
    response content instead of populating ``AIMessage.tool_calls``. LangGraph
    only routes messages with the latter, so normalize this provider-specific
    representation at the model boundary.
    """
    if response.tool_calls or not isinstance(response.content, str):
        return response

    match = _DSML_TOOL_BLOCK_RE.search(response.content)
    if match is None:
        return response

    calls: list[dict[str, Any]] = []
    for index, invoke in enumerate(_DSML_INVOKE_RE.finditer(match.group("body"))):
        arguments: dict[str, Any] = {}
        for parameter in _DSML_PARAMETER_RE.finditer(invoke.group("body")):
            arguments[parameter.group("name")] = _coerce_dsml_value(parameter.group("value"))
        name = invoke.group("name").strip()
        if not name:
            continue
        calls.append(
            {
                "name": name,
                "args": arguments,
                "id": f"dsml_{index}_{name}",
                "type": "tool_call",
            }
        )

    if not calls:
        return response

    clean_content = _DSML_TOOL_BLOCK_RE.sub("", response.content).strip()
    return response.model_copy(update={"content": clean_content, "tool_calls": calls})


def _coerce_dsml_value(value: str) -> Any:
    value = html.unescape(value).strip()
    if not value:
        return ""
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


class BinaryVulnerabilityAgentState(MessagesState, total=False):
    report_id: str
    context_note: str
    execution_started_at: float
    tool_call_count: int
    tool_loop_count: int
    decompile_count: int
    scan_count: int
    taint_trace_count: int
    tool_signatures: list[str]
    tool_failure_counts: dict[str, int]
    budget_stop_reason: str
    final_response_requested: bool
    scheduled_tool_calls: list[dict[str, Any]]
    skipped_tool_calls: list[dict[str, Any]]


def _forced_final_response(
    state: BinaryVulnerabilityAgentState,
    reason: str,
) -> str:
    """Produce a useful deterministic closeout when the model keeps requesting tools."""
    summaries: list[str] = []
    for message in reversed(state.get("messages", [])):
        if not isinstance(message, ToolMessage):
            continue
        name = message.name or "tool"
        status = getattr(message, "status", "success") or "success"
        summaries.append(f"- {name} [{status}]: {_compact_tool_text(message.content)}")
        if len(summaries) >= 5:
            break

    lines = [
        "Investigation paused before another tool call.",
        f"Stop reason: {reason}",
    ]
    if summaries:
        lines.extend(["Completed evidence:", *reversed(summaries)])
    lines.extend(
        [
            "Next step:",
            "Start a focused follow-up from the latest successful result; do not repeat failed or duplicate calls.",
        ]
    )
    return "\n".join(lines)


def _compact_tool_text(content: Any, limit: int = 260) -> str:
    text = str(content or "").strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            text = str(payload.get("text") or payload.get("error") or text)
    except json.JSONDecodeError:
        pass
    text = " ".join(text.split())
    return text if len(text) <= limit else f"{text[:limit - 3]}..."


_TOOL_DEGRADE_HINTS = {
    "scan_dangerous_sink_calls": (
        "Retry with a smaller scope: pass roots=<known handler addresses> and reduce "
        "max_functions, or call investigate_vulnerability_candidates with a small "
        "max_candidates to validate only the top sinks."
    ),
    "investigate_vulnerability_candidates": (
        "Retry with roots=<known handlers> or a smaller max_candidates/max_functions."
    ),
    "find_web_route_handlers": (
        "Fall back to list_binary_functions and get_function_signals on known "
        "registration functions, or scan_indirect_calls on the dispatcher."
    ),
    "scan_indirect_calls": (
        "Reduce max_results/max_functions, or check get_function_xrefs on the "
        "specific dispatcher first."
    ),
    "scan_taint_source_candidates": (
        "Retry with a lower limit/min_score, or analyze_function_as_source on a "
        "known input getter."
    ),
    "propagate_taint_sources": (
        "Retry with a smaller source list or max_rounds=2."
    ),
    "trace_taint_call_chain": (
        "Use trace_argument_origin on the specific call site instead of a broad chain."
    ),
    "trace_argument_origin": (
        "Retry with the exact caller_ea/call_site/callee_ea triple."
    ),
    "validate_sink_candidate": (
        "Retry with a single caller_ea/sink_ea pair."
    ),
    "decompile_function": (
        "Use get_function_signals or get_function_xrefs instead of full decompilation."
    ),
    "get_function_context": (
        "Use get_function_signals first, or batch_decompile a smaller address list."
    ),
}


def _parse_tool_payload(content: Any) -> dict[str, Any] | None:
    text = str(content or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _format_sink_entry(sink: Any) -> str:
    if isinstance(sink, dict):
        name = str(sink.get("sink_name") or "")
        loc = str(sink.get("sink_ea") or sink.get("loc") or "")
        caller = str(sink.get("caller_name") or "")
        line = " @ ".join(part for part in (name, loc) if part)
        if caller:
            line += f" ({caller})"
        return line
    return str(sink).strip()


def _finding_summary(finding: Any) -> str:
    if isinstance(finding, dict):
        text = str(finding.get("summary") or finding.get("text") or "")
    else:
        text = str(finding)
    return " ".join(text.split())[:160]


def _evidence_summary(item: Any) -> str:
    if isinstance(item, dict):
        text = str(item.get("reason") or item.get("evidence") or "")
    else:
        text = str(item)
    return " ".join(text.split())[:160]


def _source_summary(source: Any) -> str:
    if isinstance(source, dict):
        return str(source.get("name") or source.get("source") or "")
    return str(source)


def _build_continuation_plan(state: BinaryVulnerabilityAgentState) -> str:
    """Extract a compact continuation plan from completed tool results.

    Lets the user resume a budget-stopped turn from the evidence already found
    instead of restarting the investigation from scratch.
    """
    pending: list[str] = []
    verified: list[str] = []
    missing: list[str] = []
    sources: list[str] = []
    for message in reversed(state.get("messages", [])):
        if not isinstance(message, ToolMessage):
            continue
        payload = _parse_tool_payload(message.content)
        if payload is None:
            continue
        for sink in _as_list(payload.get("pending_sinks")):
            line = _format_sink_entry(sink)
            if line and line not in pending:
                pending.append(line)
        for finding in _as_list(payload.get("verified_findings")):
            text = _finding_summary(finding)
            if text and text not in verified:
                verified.append(text)
        for item in _as_list(payload.get("missing_evidence")):
            text = _evidence_summary(item)
            if text and text not in missing:
                missing.append(text)
        for source in _as_list(payload.get("confirmed_sources")):
            text = _source_summary(source)
            if text and text not in sources:
                sources.append(text)

    lines: list[str] = []
    if verified:
        lines.append(f"- Verified findings ({len(verified)}): {', '.join(verified[:8])}")
    if sources:
        lines.append(f"- Confirmed sources ({len(sources)}): {', '.join(sources[:10])}")
    if pending:
        lines.append(f"- Pending sink candidates ({len(pending)}): {', '.join(pending[:15])}")
    if missing:
        lines.append(f"- Missing evidence ({len(missing)}): {', '.join(missing[:6])}")
    if not lines:
        return ""
    return (
        "Continuation plan: completed evidence and the next validation targets.\n"
        + "\n".join(lines)
        + "\n- Next: continue from the pending candidates; do not re-run completed scans."
    )


def _verified_evidence_list(state: BinaryVulnerabilityAgentState) -> str:
    """Collate the verified findings tools actually recorded in this thread."""
    verified: list[str] = []
    for message in state.get("messages", []):
        if not isinstance(message, ToolMessage):
            continue
        payload = _parse_tool_payload(message.content)
        if payload is None:
            continue
        for finding in _as_list(payload.get("verified_findings")):
            text = _finding_summary(finding)
            if text and text not in verified:
                verified.append(text)
    return "\n".join(f"- {line}" for line in verified)


def _verified_evidence_anchor(state: BinaryVulnerabilityAgentState) -> str:
    """Whitelist of tool-verified findings shown in final-response mode.

    Anchors the model to evidence actually recorded by tools, so it cannot label
    an invented chain as "verified" when answering under budget pressure.
    """
    verified_lines = _verified_evidence_list(state)
    if verified_lines:
        return (
            "\n\nVerified evidence recorded by tools in this thread (ONLY these may "
            "be labeled 'verified'; do not add to this list):\n"
            + verified_lines
        )
    return (
        "\n\nNo verified vulnerability evidence was recorded by any tool in this thread. "
        "Do not label any claim 'verified' or 'confirmed'. Report hypotheses as "
        "unverified candidates and list their exact missing evidence."
    )


def _ruled_out_evidence_anchor(state: BinaryVulnerabilityAgentState) -> str:
    """Confirmed false positives the model must never re-report in a final answer."""
    ruled_out: list[str] = []
    for message in state.get("messages", []):
        if not isinstance(message, ToolMessage):
            continue
        payload = _parse_tool_payload(message.content)
        if payload is None:
            continue
        for item in _as_list(payload.get("ruled_out", payload.get("ruled_out_paths"))):
            text = _evidence_summary(item)
            if text and text not in ruled_out:
                ruled_out.append(text)
    if not ruled_out:
        return ""
    return (
        "\n\nRuled-out false positives recorded by tools in this thread (do not "
        "re-report these as vulnerabilities or candidates):\n"
        + "\n".join(f"- {line}" for line in ruled_out)
    )


def _budget_warning(state: BinaryVulnerabilityAgentState, limits: AgentExecutionLimits) -> str:
    """Proactive prompt attached when the tool budget is nearly exhausted.

    Prevents the model from starting a broad new scan just as the budget runs out,
    which previously wasted the last few calls on an aborted scan and forced the
    turn to stop with nothing to report.
    """
    used = int(state.get("tool_call_count", 0))
    loops = int(state.get("tool_loop_count", 0))
    if used >= limits.max_tool_calls or loops >= limits.max_tool_loops:
        return (
            "\n\nBudget warning: the tool budget is exhausted "
            f"({used}/{limits.max_tool_calls} calls, {loops}/{limits.max_tool_loops} loops). "
            "Do not request any more tools. Answer now from the completed evidence, "
            "separating confirmed findings from candidates and missing proof."
        )
    if used >= limits.max_tool_calls * 0.8 or loops >= limits.max_tool_loops * 0.8:
        return (
            "\n\nBudget warning: most of the tool budget is spent "
            f"({used}/{limits.max_tool_calls} calls, {loops}/{limits.max_tool_loops} loops). "
            "Prefer one narrow, targeted tool call over a broad scan, and be ready to "
            "answer from completed evidence."
        )
    return ""


def _estimate_tokens_chars(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _last_user_instruction(messages: list[BaseMessage], max_chars: int = 600) -> str:
    """Return the most recent user message, to re-anchor the model on the task."""
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            return _message_content_text(message.content)[:max_chars]
    return ""


def _message_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _message_budget_for_model(
    context_note: str,
    instructions: str,
    budget: ContextBudget,
) -> int:
    """Tokens left for conversation history after fixed prompt overhead.

    Enforces ``max_input_tokens`` as a real ceiling for every model call, including
    mid-tool-loop calls where the raw message list otherwise grows unbounded and
    floods the context window.
    """
    fixed = _estimate_tokens_chars(instructions) + _estimate_tokens_chars(context_note)
    return max(1024, budget.max_input_tokens - fixed - budget.response_reserve_tokens)


def build_binary_vulnerability_agent(
    model_factory: ModelFactory,
    ida_backend_url: str | None = None,
    report_dir: str | Path | None = None,
    include_write_tools: bool = False,
    confirm_write_tools: bool = True,
):
    """Build a graph suitable for registration in agent-service-toolkit."""
    base_url = ida_backend_url or os.getenv("IDA_BACKEND_URL", "http://127.0.0.1:8765")
    report_path = report_dir or os.getenv("VULN_REPORT_DIR", "./reports")
    timeout = float(os.getenv("IDA_BACKEND_TIMEOUT", "120"))
    limits = AgentExecutionLimits.from_env()
    tool_timeout = min(timeout, limits.tool_timeout_seconds)
    readonly_tools = build_readonly_ida_tools(IdaClient(base_url, timeout=tool_timeout))
    tools = list(readonly_tools)
    tools_by_name = {tool.name: tool for tool in tools}
    if include_write_tools:
        write_tool_builder = build_confirmed_write_tools if confirm_write_tools else build_direct_write_tools
        write_tools = write_tool_builder(
            lambda: AsyncIdaClient(base_url, timeout=tool_timeout),
        )
        tools.extend(write_tools)
        tools_by_name.update({tool.name: tool for tool in write_tools})
    write_policy = (
        "\nWrite tools are available. Only use them when the user explicitly asks to modify, "
        "patch, rename, comment, or save the IDA database. Before patching bytes or jumps, "
        "collect enough evidence to name the target address, original bytes when available, "
        "patched bytes or mode, and the reason. After a write tool returns, report the exact "
        "result and whether a database save is still needed.\n"
        if include_write_tools
        else "\nWrite tools are not available in this run. Do not claim you can patch or modify the binary.\n"
    )

    instructions = f"""
You are a binary vulnerability analysis Agent for Web/CGI firmware.

Follow the user's latest instruction exactly. It defines this turn's task and
scope; every tool call must serve it. Re-read the instruction before each tool
call and skip any call that does not serve it. If the user asks a scoped question
(for example, which webGetVar-to-command-injection chains exist), enumerate
exactly that scope and stop when it is answered. Do not expand into unrelated
attack surfaces (other sinks, memory corruption, side channels, or keys) unless
they are part of the same chain the user asked about.
Reply in the same language the user writes in. If they write Chinese, respond in
Chinese; do not switch to English.
Be concise. Do not narrate your reasoning with filler such as "let me now...",
"interesting", or "key insight". Report evidence directly and answer the exact
question asked, then stop.

Use IDA tools as the source of truth. Evidence integrity is the highest priority:
- "Verified" means exploitable: user-controlled input reaches the sink in its dangerous
  form and no validation or guard function blocks the payload. A tool result labeled
  "VERIFIED" only proves taint reached the sink in static analysis; it does NOT prove
  exploitability. Every verified claim must cite the tool result that proves it.
- Whenever a chain passes through a validation or guard function (IP/mask check, length
  check, whitelist, sanitizer), you MUST decompile that guard and read its actual
  parsing logic to determine whether the payload survives. Only after examining the
  guard's own code may you label the chain verified or rule it out. If the guard is a
  genuinely external or opaque function you cannot decompile, the chain is a candidate
  with missing evidence "resolve the guard's behavior", never a verified finding. Never
  assume a guard is bypassable.
- When you deterministically prove a candidate is a false positive (for example, a
  strict IPv4-format guard that rejects shell metacharacters), or when the user reports
  one, call record_investigation_exclusion to persist it and stop reporting it. A chain
  in ruled_out_paths or a candidate marked "rejected" is a confirmed false positive:
  do not re-report it, do not re-validate it, and do not re-add its missing evidence.
- Without citable tool evidence the claim is a candidate or hypothesis, never a verified
  finding. Never upgrade confidence to satisfy the user or because the budget is low.
  A plausible-looking chain (exact addresses and API names) that no tool result supports
  is still fabrication and is strictly forbidden.
- Prefer answering "no verified vulnerability found yet" with the exact missing evidence
  over inventing plausible chains.
- When you provide a PoC, separate confirmed steps from assumed steps. If a step depends
  on an unverified assumption (for example, a guard parsing input loosely), mark the PoC
  as conditional and unverified, not as confirmed.
Use bounded investigation and avoid repeatedly
decompiling the same function. Follow the playbook tool-selection rules strictly:
prefer specialized and lightweight tools before pseudocode retrieval. Treat heuristic
tool output as investigation seeds, not exhaustive proof.
If a decompile tool returns a budget-skipped error, stop requesting more pseudocode in
that turn and summarize the completed evidence instead.
Many tools return vulnagent.tool_result.v1 JSON. Read the JSON `text` field for the
human-readable details, and use structured fields such as confirmed_routes,
confirmed_sources, pending_sinks, missing_evidence, verified_findings, and
function_notes to maintain investigation status.
When the user asks to find new vulnerabilities, do not stop at a summary. Run a
fresh evidence workflow unless the needed results are already present in this
thread: (1) discover routes and source candidates, (2) scan dangerous sinks from
route handlers or global fallback, (3) validate candidate sink arguments with
argument-origin or call-chain tracing. Report unverified high-risk candidates
with exact missing evidence instead of discarding them. These workflow steps are
a default; the user's latest instruction overrides them.
If the previous turn stopped on a budget or timeout and the user replies with a
short resume instruction ("继续", "continue", "接着挖"), do not restart discovery.
Resume from the continuation plan and the structured state's pending candidates and
missing evidence, and only run tools that validate or extend those candidates.
When the user explicitly redirects the investigation direction (e.g., asks to check
a different attack surface like configuration handlers instead of upload routes),
follow the user's direction immediately. Treat user redirection as the highest
priority — override the playbook's default investigation order. Do not repeat or
defend previous conclusions when the user signals they want a different angle.
{write_policy}

Skill loading:
- The full vulnerability-discovery playbook is not loaded by default.
- If the context note contains an explicitly loaded skill, follow that skill for
  the current turn.
- Users can request a skill with commands such as `/skill vuln_discovery` or
  `/skill firmware_web_audit`.
"""

    async def call_model(
        state: BinaryVulnerabilityAgentState,
        config: RunnableConfig,
    ) -> BinaryVulnerabilityAgentState:
        remaining = limits.remaining_seconds(state["execution_started_at"])
        if remaining <= 0:
            reason = "The per-turn execution time limit was reached before another model call."
            return {
                "budget_stop_reason": reason,
                "messages": [AIMessage(content=budget_stop_message(reason, _build_continuation_plan(state)))],
            }
        final_response_requested = bool(state.get("final_response_requested", False))
        model = model_factory(config)
        if not final_response_requested:
            model = model.bind_tools(tools)
        budget_warning = _budget_warning(state, limits)
        context_budget = ContextBudget.from_env()
        messages_for_model = trim_messages_for_model(
            state["messages"],
            max_tokens=_message_budget_for_model(
                state.get("context_note", ""),
                instructions,
                context_budget,
            ),
            max_message_tokens=context_budget.max_message_tokens,
        )
        verified_anchor = _verified_evidence_anchor(state) if final_response_requested else ""
        ruled_out_anchor = _ruled_out_evidence_anchor(state) if final_response_requested else ""
        final_instruction = (
            "\n\nFinal-response mode:\n"
            "- Tool execution has reached a policy or budget boundary.\n"
            "- Do not request any more tools in this turn.\n"
            "- Answer the user from the completed tool results and structured state.\n"
            "- Only label a claim 'verified' if it appears in the Verified evidence list "
            "above. Label everything else as an unverified candidate and state its missing "
            "evidence. Never invent chains to satisfy the user.\n"
            "- Do not re-report any chain in the Ruled-out false positives list above; "
            "it is a confirmed false positive.\n"
            "- Before labeling a chain 'verified', confirm no validation/guard function "
            "between source and sink blocks the payload; if a guard's behavior is "
            "unresolved, mark the chain as a candidate with that missing evidence.\n"
        )
        user_instruction = _last_user_instruction(state["messages"])
        instruction_anchor = (
            f"\n\nCurrent user instruction:\n{user_instruction}" if user_instruction else ""
        )
        runnable = RunnableLambda(
            lambda current_state: [
                SystemMessage(
                    content=(
                        instructions
                        + current_state.get("context_note", "")
                        + budget_warning
                        + verified_anchor
                        + ruled_out_anchor
                        + (final_instruction if final_response_requested else "")
                        + instruction_anchor
                    )
                )
            ]
            + messages_for_model,
            name="BinaryVulnerabilityStateModifier",
        ) | model

        response: Any = None
        for attempt in range(2):
            remaining = limits.remaining_seconds(state["execution_started_at"])
            if remaining <= 0:
                reason = "The per-turn execution time limit was reached before another model call."
                return {
                    "budget_stop_reason": reason,
                    "messages": [AIMessage(content=budget_stop_message(reason, _build_continuation_plan(state)))],
                }
            try:
                response = await asyncio.wait_for(
                    runnable.ainvoke(state, config),
                    timeout=min(limits.model_timeout_seconds, remaining),
                )
                break
            except (TimeoutError, asyncio.TimeoutError):
                if attempt == 0:
                    continue  # a single transient model stall must not kill the turn
                reason = "The model response timeout was reached."
                return {
                    "budget_stop_reason": reason,
                    "messages": [AIMessage(content=model_timeout_message(_build_continuation_plan(state)))],
                }
        if isinstance(response, AIMessage):
            response = _normalize_model_tool_calls(response)
        if final_response_requested and isinstance(response, AIMessage) and response.tool_calls:
            reason = state.get("budget_stop_reason") or "Tool execution is closed for this turn."
            content = response.content or _forced_final_response(state, reason)
            response = AIMessage(content=content)
        return {"messages": [response]}

    def initialize_execution(
        state: BinaryVulnerabilityAgentState,
    ) -> BinaryVulnerabilityAgentState:
        return {
            "execution_started_at": time.monotonic(),
            "tool_call_count": 0,
            "tool_loop_count": 0,
            "decompile_count": 0,
            "scan_count": 0,
            "taint_trace_count": 0,
            "tool_signatures": [],
            "tool_failure_counts": {},
            "budget_stop_reason": "",
            "final_response_requested": False,
            "scheduled_tool_calls": [],
            "skipped_tool_calls": [],
        }

    def schedule_tools(
        state: BinaryVulnerabilityAgentState,
    ) -> BinaryVulnerabilityAgentState:
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage):
            raise TypeError(f"Expected AIMessage, got {type(last_message)}")
        decision = limits.schedule(
            last_message.tool_calls,
            started_at=state["execution_started_at"],
            tool_call_count=state["tool_call_count"],
            tool_loop_count=state["tool_loop_count"],
            decompile_count=state["decompile_count"],
            scan_count=state["scan_count"],
            taint_trace_count=state.get("taint_trace_count", 0),
            tool_signatures=state["tool_signatures"],
            tool_failure_counts=state.get("tool_failure_counts", {}),
        )
        skipped_messages = _skipped_tool_messages(decision.skipped_calls)
        return {
            **decision.updates,
            "budget_stop_reason": decision.skipped_calls[0].reason
            if decision.skipped_calls
            else "",
            "final_response_requested": decision.request_final_answer,
            "scheduled_tool_calls": decision.allowed_calls,
            "skipped_tool_calls": [
                {"tool_call": skipped.tool_call, "reason": skipped.reason}
                for skipped in decision.skipped_calls
            ],
            "messages": skipped_messages if not decision.allowed_calls else [],
        }

    async def execute_tools(
        state: BinaryVulnerabilityAgentState,
        config: RunnableConfig,
    ) -> BinaryVulnerabilityAgentState:
        last_message = next(
            (
                message
                for message in reversed(state["messages"])
                if isinstance(message, AIMessage) and message.tool_calls
            ),
            None,
        )
        if not isinstance(last_message, AIMessage):
            raise TypeError(f"Expected AIMessage, got {type(last_message)}")

        results: list[ToolMessage] = []
        failed_signatures: list[str] = []
        scheduled_by_id = {
            tool_call["id"]: tool_call for tool_call in state.get("scheduled_tool_calls", [])
        }
        skipped_by_id = {
            skipped["tool_call"]["id"]: skipped["reason"]
            for skipped in state.get("skipped_tool_calls", [])
        }
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]
            if tool_call["id"] in skipped_by_id:
                results.append(
                    ToolMessage(
                        content=(
                            "Tool request skipped by execution policy: "
                            f"{skipped_by_id[tool_call['id']]} Use completed tool results "
                            "to answer the user now."
                        ),
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                        status="error",
                    )
                )
                continue
            if tool_call["id"] not in scheduled_by_id:
                continue
            tool = tools_by_name.get(tool_name)
            if tool is None:
                failed_signatures.append(_tool_signature(tool_call))
                results.append(
                    ToolMessage(
                        content=f"Unknown tool: {tool_name}",
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                        status="error",
                    )
                )
                continue

            remaining = limits.remaining_seconds(state["execution_started_at"])
            if remaining <= 0:
                failed_signatures.append(_tool_signature(tool_call))
                results.append(
                    ToolMessage(
                        content="Tool execution skipped: per-turn execution time limit reached.",
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                        status="error",
                    )
                )
                continue
            try:
                result = await asyncio.wait_for(
                    tool.ainvoke(tool_call, config=config),
                    timeout=min(limits.tool_timeout_seconds, remaining),
                )
                tool_message = (
                    result
                    if isinstance(result, ToolMessage)
                    else ToolMessage(
                        content=_serialize_tool_result(result),
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                    )
                )
                if tool_message.status == "error":
                    failed_signatures.append(_tool_signature(tool_call))
                results.append(tool_message)
            except (TimeoutError, asyncio.TimeoutError):
                failed_signatures.append(_tool_signature(tool_call))
                hint = _TOOL_DEGRADE_HINTS.get(tool_name)
                results.append(
                    ToolMessage(
                        content=(
                            "Tool execution timed out after "
                            f"{min(limits.tool_timeout_seconds, remaining):.1f} seconds."
                            + (f" {hint}" if hint else "")
                        ),
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                        status="error",
                    )
                )
            except Exception as exc:  # noqa: BLE001 - return tool failures to the model
                failed_signatures.append(_tool_signature(tool_call))
                results.append(
                    ToolMessage(
                        content=f"{type(exc).__name__}: {exc}",
                        name=tool_name,
                        tool_call_id=tool_call["id"],
                        status="error",
                    )
                )
        if not failed_signatures:
            return {"messages": results}
        failures = dict(state.get("tool_failure_counts", {}))
        for signature in failed_signatures:
            failures[signature] = failures.get(signature, 0) + 1
        return {
            "messages": results,
            "tool_signatures": [
                signature
                for signature in state.get("tool_signatures", [])
                if signature not in failed_signatures
            ],
            "tool_failure_counts": failures,
        }

    async def baseline_scan(
        state: BinaryVulnerabilityAgentState,
        config: RunnableConfig,
        writer: StreamWriter,
    ) -> BinaryVulnerabilityAgentState:
        thread_id = str(config.get("configurable", {}).get("thread_id", ""))
        progress = ToolkitTaskProgressWriter(writer)
        try:
            async with AsyncIdaClient(base_url, timeout=timeout) as client:
                report = await BaselineScanner(
                    client,
                    FileReportStore(report_path),
                    progress_callback=progress,
                    persistence=SqliteVulnRepository.from_env(),
                ).run(thread_id=thread_id)
            progress.finish()
        except Exception as exc:
            progress.fail(f"{type(exc).__name__}: {exc}")
            raise
        return {
            "report_id": report.report_id,
            "messages": [
                AIMessage(
                    content=(
                        f"{report.summary}\n\n"
                        f"Report ID: `{report.report_id}`\n"
                        f"JSON report: `{Path(report_path) / f'{report.report_id}.json'}`"
                    )
                )
            ],
        }

    def select_entry(
        state: BinaryVulnerabilityAgentState,
        config: RunnableConfig,
    ) -> Literal["baseline_scan", "initialize_execution"]:
        workflow = config.get("configurable", {}).get("workflow")
        return "baseline_scan" if workflow == "baseline_scan" else "initialize_execution"

    def pending_tool_calls(
        state: BinaryVulnerabilityAgentState,
    ) -> Literal["schedule_tools", "done"]:
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage):
            raise TypeError(f"Expected AIMessage, got {type(last_message)}")
        return "schedule_tools" if last_message.tool_calls else "done"

    def scheduled_tools(
        state: BinaryVulnerabilityAgentState,
    ) -> Literal["tools", "model"]:
        return "tools" if state.get("scheduled_tool_calls") else "model"

    def after_tools(
        state: BinaryVulnerabilityAgentState,
    ) -> Literal["model"]:
        return "model"

    graph = StateGraph(BinaryVulnerabilityAgentState)
    graph.add_node("baseline_scan", baseline_scan)
    graph.add_node("initialize_execution", initialize_execution)
    graph.add_node("model", call_model)
    graph.add_node("schedule_tools", schedule_tools)
    graph.add_node("tools", execute_tools)
    graph.add_conditional_edges(
        START,
        select_entry,
        {"baseline_scan": "baseline_scan", "initialize_execution": "initialize_execution"},
    )
    graph.add_edge("baseline_scan", END)
    graph.add_edge("initialize_execution", "model")
    graph.add_conditional_edges(
        "model",
        pending_tool_calls,
        {"schedule_tools": "schedule_tools", "done": END},
    )
    graph.add_conditional_edges("schedule_tools", scheduled_tools, {"tools": "tools", "model": "model"})
    graph.add_conditional_edges("tools", after_tools, {"model": "model"})
    return graph.compile()


def _serialize_tool_result(result: Any) -> str:
    if isinstance(result, str):
        return result
    return json.dumps(result, ensure_ascii=False, default=str)


def _skipped_tool_messages(skipped_calls: list[SkippedToolCall]) -> list[ToolMessage]:
    """Return provider-required ToolMessages for scheduled-out tool calls."""
    return [
        ToolMessage(
            content=(
                "Tool request skipped by execution policy: "
                f"{skipped.reason} Use completed tool results to answer the user now."
            ),
            name=skipped.tool_call.get("name", "unknown"),
            tool_call_id=skipped.tool_call["id"],
            status="error",
        )
        for skipped in skipped_calls
    ]
