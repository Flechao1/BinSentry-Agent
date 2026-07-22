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
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig, RunnableLambda
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import StreamWriter

from vulnagent.agent.baseline_scan import BaselineScanner
from vulnagent.agent.execution_limits import (
    AgentExecutionLimits,
    SkippedToolCall,
    _tool_signature,
    budget_stop_message,
)
from vulnagent.agent.progress import ToolkitTaskProgressWriter
from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.clients.ida_client import IdaClient
from vulnagent.reports import FileReportStore
from vulnagent.skills import load_skill
from vulnagent.storage import SqliteVulnRepository
from vulnagent.tools.langchain_tools import build_readonly_ida_tools
from vulnagent.tools.langgraph_write_tools import build_confirmed_write_tools


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


def build_binary_vulnerability_agent(
    model_factory: ModelFactory,
    ida_backend_url: str | None = None,
    report_dir: str | Path | None = None,
    include_write_tools: bool = False,
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
        write_tools = build_confirmed_write_tools(
            lambda: AsyncIdaClient(base_url, timeout=tool_timeout),
        )
        tools.extend(write_tools)
        tools_by_name.update({tool.name: tool for tool in write_tools})

    instructions = f"""
You are a binary vulnerability analysis Agent for Web/CGI firmware.
Use IDA tools as the source of truth. Do not claim a verified vulnerability without
deterministic source-to-sink evidence. Use bounded investigation and avoid repeatedly
decompiling the same function. Follow the playbook tool-selection rules strictly:
prefer specialized and lightweight tools before pseudocode retrieval. Treat heuristic
tool output as investigation seeds, not exhaustive proof.
If a decompile tool returns a budget-skipped error, stop requesting more pseudocode in
that turn and summarize the completed evidence instead.
Many tools return vulnagent.tool_result.v1 JSON. Read the JSON `text` field for the
human-readable details, and use structured fields such as confirmed_routes,
confirmed_sources, pending_sinks, missing_evidence, verified_findings, and
function_notes to maintain investigation status.

Follow this playbook:
{load_skill("firmware_web_audit")}
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
                "messages": [AIMessage(content=budget_stop_message(reason))],
            }
        final_response_requested = bool(state.get("final_response_requested", False))
        model = model_factory(config)
        if not final_response_requested:
            model = model.bind_tools(tools)
        final_instruction = (
            "\n\nFinal-response mode:\n"
            "- Tool execution has reached a policy or budget boundary.\n"
            "- Do not request any more tools in this turn.\n"
            "- Answer the user from the completed tool results and structured state.\n"
            "- Clearly separate confirmed evidence, candidates, and missing evidence.\n"
        )
        runnable = RunnableLambda(
            lambda current_state: [
                SystemMessage(
                    content=(
                        instructions
                        + current_state.get("context_note", "")
                        + (final_instruction if final_response_requested else "")
                    )
                )
            ]
            + current_state["messages"],
            name="BinaryVulnerabilityStateModifier",
        ) | model

        try:
            response = await asyncio.wait_for(
                runnable.ainvoke(state, config),
                timeout=min(limits.model_timeout_seconds, remaining),
            )
        except (TimeoutError, asyncio.TimeoutError):
            reason = "The model response timeout was reached."
            return {
                "budget_stop_reason": reason,
                "messages": [AIMessage(content=budget_stop_message(reason))],
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
                results.append(
                    ToolMessage(
                        content=(
                            "Tool execution timed out after "
                            f"{min(limits.tool_timeout_seconds, remaining):.1f} seconds."
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
