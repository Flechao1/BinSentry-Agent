"""Bounded short-term memory construction for the conversational Agent."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from vulnagent.agent.investigation_state import ConfirmedRoute, InvestigationState, PendingSink
from vulnagent.storage import SqliteVulnRepository

CHARS_PER_TOKEN = 4
ROUTE_PATTERN = re.compile(
    r'^\s*(?P<registration_name>\S+) @ (?P<registration_ea>0x[0-9a-fA-F]+): '
    r'"(?P<route>[^"]+)" -> (?P<handler_name>\S+) @ (?P<handler_ea>0x[0-9a-fA-F]+)$',
    re.MULTILINE,
)
SOURCE_CANDIDATE_PATTERN = re.compile(
    r"^\s*\[[\d.]+\]\s+(?P<name>\S+)\s+@\s+0x[0-9a-fA-F]+",
    re.MULTILINE,
)
PROPAGATED_SOURCE_PATTERN = re.compile(r"^\s*-\s+(?P<name>\S+)\s*$", re.MULTILINE)
FOCUSED_SINK_PATTERN = re.compile(
    r"^\s*\[(?P<category>[^\]]+)\]\s+(?P<sink_name>\S+)\s+@\s+"
    r"(?P<sink_ea>0x[0-9a-fA-F]+)",
    re.MULTILINE,
)
SCANNED_SINK_PATTERN = re.compile(
    r"^\s*\[(?P<category>[^\]]+)\]\s+(?P<caller_name>\S+)\s+@\s+"
    r"(?P<caller_ea>0x[0-9a-fA-F]+):\s+(?P<sink_name>\S+)\s+@\s+"
    r"(?P<sink_ea>0x[0-9a-fA-F]+)",
    re.MULTILINE,
)
INDIRECT_CALL_PATTERN = re.compile(
    r"^\s*\[(?P<kind>[^\]]+)\]\s+(?P<caller_name>\S+)\s+@\s+"
    r"(?P<caller_ea>0x[0-9a-fA-F]+):\s+(?P<call_ea>0x[0-9a-fA-F]+|\([^)]+\))"
    r"\s+->\s+(?P<target>.+?)\s+\(confidence=(?P<confidence>[\d.]+)\)",
    re.MULTILINE,
)
SOURCE_FUNCTION_PATTERN = re.compile(r"^Source function:\s*(?P<name>\S+)", re.MULTILINE)
TAINT_STATUS_PATTERN = re.compile(r"^Taint status:\s*(?P<status>\S+)", re.MULTILINE)
TAINT_REASON_PATTERN = re.compile(r"^Reason:\s*(?P<reason>.+)$", re.MULTILINE)
VERIFIED_CHAIN_PATTERN = re.compile(
    r"--- Chain \d+ \[VERIFIED\] ---\s+Path:\s*(?P<path>[^\n]+)",
    re.MULTILINE,
)
UNVERIFIED_CHAIN_PATTERN = re.compile(
    r"--- Chain \d+ \[UNVERIFIED\] ---\s+Path:\s*(?P<path>[^\n]+)",
    re.MULTILINE,
)
SEMANTIC_SUMMARY_SYSTEM_PROMPT = """You summarize binary vulnerability Agent investigations.

Produce a compact short-term memory summary for the next model call.
Keep only durable information that helps continue the investigation.

Rules:
- Do not invent facts.
- Distinguish confirmed evidence from hypotheses.
- Preserve addresses, route strings, function names, sources, sinks, and missing evidence.
- Prefer concise bullets.
- If a detail is only a candidate, mark it as candidate.
- If an analysis path was ruled out, keep that exclusion.

Output exactly these sections:
Confirmed facts:
Open hypotheses:
Missing evidence:
Ruled-out paths:
Current objective:
"""


@dataclass(frozen=True)
class ContextBudget:
    max_input_tokens: int = 12000
    summary_tokens: int = 1200
    state_tokens: int = 1200
    recent_message_tokens: int = 7200
    response_reserve_tokens: int = 2400
    max_message_tokens: int = 1800

    @property
    def bounded_recent_message_tokens(self) -> int:
        available = self.max_input_tokens - self.summary_tokens - self.state_tokens
        return max(256, min(self.recent_message_tokens, available))

    @classmethod
    def from_env(cls) -> ContextBudget:
        return cls(
            max_input_tokens=int(os.getenv("VULN_CONTEXT_MAX_INPUT_TOKENS", "12000")),
            summary_tokens=int(os.getenv("VULN_CONTEXT_SUMMARY_TOKENS", "1200")),
            state_tokens=int(os.getenv("VULN_CONTEXT_STATE_TOKENS", "1200")),
            recent_message_tokens=int(os.getenv("VULN_CONTEXT_RECENT_TOKENS", "7200")),
            response_reserve_tokens=int(os.getenv("VULN_CONTEXT_RESPONSE_RESERVE_TOKENS", "2400")),
            max_message_tokens=int(os.getenv("VULN_CONTEXT_MAX_MESSAGE_TOKENS", "1800")),
        )


@dataclass(frozen=True)
class PreparedContext:
    messages: list[BaseMessage]
    context_note: str
    estimated_input_tokens: int
    summarized_until_sequence: int


class ContextBuilder:
    """Build a bounded LLM context while preserving full messages in SQLite."""

    def __init__(
        self,
        repository: SqliteVulnRepository,
        *,
        recent_turns: int | None = None,
        budget: ContextBudget | None = None,
        summary_llm_factory: Callable[[], Any] | None = None,
        semantic_summary_enabled: bool | None = None,
    ) -> None:
        self.repository = repository
        self.recent_turns = recent_turns or int(os.getenv("VULN_CONTEXT_RECENT_TURNS", "8"))
        self.budget = budget or ContextBudget.from_env()
        self.summary_llm_factory = summary_llm_factory
        self.semantic_summary_enabled = (
            semantic_summary_enabled
            if semantic_summary_enabled is not None
            else os.getenv("VULN_CONTEXT_SEMANTIC_SUMMARY", "true").lower()
            not in {"0", "false", "no", "off"}
        )

    def prepare(self, thread_id: str, messages: list[BaseMessage]) -> PreparedContext:
        messages = sanitize_provider_message_order(messages)
        state = self._update_investigation_state(thread_id, messages)
        recent_start = _recent_turn_start(messages, self.recent_turns)
        summary = self._update_summary(thread_id, messages, recent_start)
        context_note = self._context_note(summary, state)
        recent_messages = _fit_recent_messages(
            messages[recent_start:],
            max_chars=self.budget.bounded_recent_message_tokens * CHARS_PER_TOKEN,
            max_message_chars=self.budget.max_message_tokens * CHARS_PER_TOKEN,
        )
        estimated_tokens = _estimate_tokens(context_note) + sum(
            _estimate_tokens(_message_text(message)) for message in recent_messages
        )
        return PreparedContext(
            messages=recent_messages,
            context_note=context_note,
            estimated_input_tokens=estimated_tokens,
            summarized_until_sequence=recent_start - 1,
        )

    def record(self, thread_id: str, messages: list[BaseMessage]) -> None:
        """Persist derived state after a completed tool loop."""
        self._update_investigation_state(thread_id, sanitize_provider_message_order(messages))

    def _update_summary(
        self,
        thread_id: str,
        messages: list[BaseMessage],
        recent_start: int,
    ) -> str:
        existing = self.repository.get_chat_summary(thread_id)
        summary = existing["summary"] if existing else ""
        summarized_until = existing["summarized_until_sequence"] if existing else -1
        new_summarized_until = recent_start - 1
        if new_summarized_until <= summarized_until:
            return summary

        additions = messages[summarized_until + 1 : recent_start]
        addition_text = "\n".join(_summarize_message(message) for message in additions)
        merged = self._merge_summary(summary, addition_text)
        summary = _keep_recent_text(
            merged,
            self.budget.summary_tokens * CHARS_PER_TOKEN,
            marker="[Earlier investigation summary truncated]\n",
        )
        self.repository.save_chat_summary(
            thread_id,
            summary,
            summarized_until_sequence=new_summarized_until,
        )
        return summary

    def _merge_summary(self, existing_summary: str, addition_text: str) -> str:
        if (
            self.semantic_summary_enabled
            and self.summary_llm_factory is not None
            and addition_text.strip()
        ):
            try:
                return self._semantic_summary(existing_summary, addition_text)
            except Exception:  # noqa: BLE001 - keep memory construction non-fatal
                pass
        return "\n".join(part for part in [existing_summary, addition_text] if part)

    def _semantic_summary(self, existing_summary: str, addition_text: str) -> str:
        model = self.summary_llm_factory()
        response = model.invoke(
            [
                SystemMessage(content=SEMANTIC_SUMMARY_SYSTEM_PROMPT),
                HumanMessage(
                    content=(
                        "Existing investigation summary:\n"
                        f"{existing_summary or '(none)'}\n\n"
                        "New conversation/tool evidence to merge:\n"
                        f"{addition_text}\n\n"
                        "Rewrite the complete short-term memory summary."
                    )
                ),
            ]
        )
        return _clip_text(
            _response_text(response).strip(),
            self.budget.summary_tokens * CHARS_PER_TOKEN,
        )

    def _update_investigation_state(
        self,
        thread_id: str,
        messages: list[BaseMessage],
    ) -> InvestigationState:
        stored = self.repository.get_investigation_state(thread_id)
        state = InvestigationState.model_validate(stored or {})
        pending_tool_calls: dict[str, tuple[str, dict[str, Any]]] = {}
        for message in messages:
            if isinstance(message, AIMessage):
                for tool_call in message.tool_calls:
                    name = tool_call["name"]
                    args = tool_call.get("args", {})
                    pending_tool_calls[tool_call["id"]] = (name, args)
                    _apply_tool_call(state, name, args)
                continue
            if isinstance(message, ToolMessage):
                call_id = message.tool_call_id
                if call_id in state.processed_tool_result_ids:
                    continue
                name, args = pending_tool_calls.get(
                    call_id,
                    (message.name or "unknown", {}),
                )
                _apply_tool_result(state, name, args, _message_text(message))
                if call_id:
                    state.mark_tool_result_processed(call_id)
        state.compact()
        self.repository.save_investigation_state(thread_id, state.model_dump(mode="json"))
        return state

    def _context_note(self, summary: str, state: InvestigationState) -> str:
        summary_text = summary or "(No older conversation has been summarized yet.)"
        state_text = json.dumps(state.prompt_dump(), ensure_ascii=False, indent=2)
        return (
            "\n\nShort-term memory policy:\n"
            "- Treat the structured investigation state as the current task status.\n"
            "- Use the older-conversation summary as background only.\n"
            "- Recent messages remain the most precise source for conversational details.\n"
            "- IDA tool output remains the source of truth for vulnerability evidence.\n\n"
            "Structured investigation state:\n"
            f"{_clip_text(state_text, self.budget.state_tokens * CHARS_PER_TOKEN)}\n\n"
            "Older conversation summary:\n"
            f"{_clip_text(summary_text, self.budget.summary_tokens * CHARS_PER_TOKEN)}"
        )


def _recent_turn_start(messages: list[BaseMessage], recent_turns: int) -> int:
    human_indexes = [
        index for index, message in enumerate(messages) if isinstance(message, HumanMessage)
    ]
    if len(human_indexes) <= recent_turns:
        return 0
    return human_indexes[-recent_turns]


def sanitize_provider_message_order(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Drop incomplete tool-call fragments before sending history to chat providers."""
    sanitized: list[BaseMessage] = []
    index = 0
    while index < len(messages):
        message = messages[index]
        if isinstance(message, AIMessage) and message.tool_calls:
            required_ids = {tool_call["id"] for tool_call in message.tool_calls}
            tool_messages: list[ToolMessage] = []
            next_index = index + 1
            while next_index < len(messages) and isinstance(messages[next_index], ToolMessage):
                tool_messages.append(messages[next_index])
                next_index += 1
            returned_ids = {tool_message.tool_call_id for tool_message in tool_messages}
            if required_ids.issubset(returned_ids):
                sanitized.append(message)
                sanitized.extend(
                    tool_message
                    for tool_message in tool_messages
                    if tool_message.tool_call_id in required_ids
                )
            index = next_index
            continue
        if isinstance(message, ToolMessage):
            index += 1
            continue
        sanitized.append(message)
        index += 1
    return sanitized


def _split_turns(messages: list[BaseMessage]) -> list[list[BaseMessage]]:
    turns: list[list[BaseMessage]] = []
    for message in messages:
        if isinstance(message, HumanMessage) or not turns:
            turns.append([])
        turns[-1].append(message)
    return turns


def _fit_recent_messages(
    messages: list[BaseMessage],
    *,
    max_chars: int,
    max_message_chars: int,
) -> list[BaseMessage]:
    selected_turns: list[list[BaseMessage]] = []
    used_chars = 0
    for turn in reversed(_split_turns(messages)):
        clipped_turn = [_clip_message(message, max_message_chars) for message in turn]
        turn_chars = sum(len(_message_text(message)) for message in clipped_turn)
        if selected_turns and used_chars + turn_chars > max_chars:
            break
        selected_turns.append(clipped_turn)
        used_chars += turn_chars
    return [message for turn in reversed(selected_turns) for message in turn]


def _clip_message(message: BaseMessage, max_chars: int) -> BaseMessage:
    content = _message_text(message)
    clipped_content = _clip_text(content, max_chars)
    if clipped_content == content:
        return message
    return message.model_copy(update={"content": clipped_content})


def _summarize_message(message: BaseMessage) -> str:
    content = _clip_text(_message_text(message).replace("\n", " "), 480)
    if isinstance(message, HumanMessage):
        return f"User: {content}"
    if isinstance(message, ToolMessage):
        return f"Tool result ({message.name or 'unknown'}): {content}"
    if isinstance(message, AIMessage):
        calls = ", ".join(tool_call["name"] for tool_call in message.tool_calls)
        if calls and content:
            return f"Agent: {content} | Requested tools: {calls}"
        if calls:
            return f"Agent requested tools: {calls}"
        return f"Agent: {content}"
    return f"{message.type}: {content}"


def _apply_tool_call(state: InvestigationState, name: str, args: dict[str, Any]) -> None:
    phase_by_tool = {
        "check_ida_backend": "check_backend",
        "detect_binary_architecture": "collect_metadata",
        "list_binary_imports": "collect_metadata",
        "find_web_route_handlers": "discover_entrypoints",
        "scan_indirect_calls": "discover_indirect_calls",
        "scan_taint_source_candidates": "discover_sources",
        "analyze_function_as_source": "discover_sources",
        "propagate_taint_sources": "propagate_sources",
        "find_function_sink_calls": "scan_sinks",
        "scan_dangerous_sink_calls": "scan_sinks",
        "trace_taint_call_chain": "trace_taint",
        "trace_argument_origin": "trace_taint",
        "get_function_context": "inspect_function",
        "get_function_signals": "inspect_function",
        "decompile_function": "inspect_function",
        "get_function_xrefs": "inspect_function",
    }
    if name in phase_by_tool:
        state.phase = phase_by_tool[name]

    function_address = _first_arg(args, "ea", "address", "function_address", "caller_ea")
    if function_address:
        state.active_function = str(function_address)
        if str(function_address) not in state.investigated_functions:
            state.investigated_functions.append(str(function_address))

    if name == "scan_dangerous_sink_calls":
        state.active_sink = {"scan_requested": True}
    elif name in {"trace_taint_call_chain", "trace_argument_origin"}:
        state.active_sink = {
            key: value
            for key, value in args.items()
            if key
            in {
                "ea",
                "caller_ea",
                "call_site",
                "callee_ea",
                "arg_index",
                "target_arg_idx",
                "sources",
            }
        }


def _apply_tool_result(
    state: InvestigationState,
    name: str,
    args: dict[str, Any],
    result: str,
) -> None:
    if _apply_structured_tool_result(state, name, args, result):
        return

    if name == "find_web_route_handlers":
        for match in ROUTE_PATTERN.finditer(result):
            state.add_route(ConfirmedRoute(**match.groupdict()))
        return

    if name == "scan_indirect_calls":
        for match in INDIRECT_CALL_PATTERN.finditer(result):
            site = (
                f"{match.group('caller_name')} @ {match.group('caller_ea')} "
                f"calls {match.group('target')} indirectly at {match.group('call_ea')}"
            )
            state.add_indirect_call_site(site)
            state.add_missing_evidence(
                f"Resolve possible targets for indirect call {match.group('call_ea')} "
                f"in {match.group('caller_name')}."
            )
        return

    if name in {"scan_taint_source_candidates", "analyze_function_as_source"}:
        for match in SOURCE_CANDIDATE_PATTERN.finditer(result):
            state.add_source_candidate(match.group("name"))
        if name == "analyze_function_as_source":
            match = re.search(r"^Source analysis:\s*(?P<name>\S+)", result, re.MULTILINE)
            if match:
                state.add_source_candidate(match.group("name"))
        return

    if name == "propagate_taint_sources":
        for match in PROPAGATED_SOURCE_PATTERN.finditer(result):
            state.add_confirmed_source(match.group("name"))
        return

    if name == "find_function_sink_calls":
        for match in FOCUSED_SINK_PATTERN.finditer(result):
            state.add_pending_sink(
                PendingSink(
                    **match.groupdict(),
                    caller_ea=str(args.get("ea", "")),
                    reason="Focused sink call requires source-to-sink validation.",
                )
            )
            state.add_missing_evidence(
                f"Validate whether user-controlled input reaches "
                f"{match.group('sink_name')} @ {match.group('sink_ea')}."
            )
        return

    if name == "scan_dangerous_sink_calls":
        for match in SCANNED_SINK_PATTERN.finditer(result):
            state.add_pending_sink(
                PendingSink(
                    **match.groupdict(),
                    reason="Sink scan result requires source-to-sink validation.",
                )
            )
            state.add_missing_evidence(
                f"Validate whether user-controlled input reaches "
                f"{match.group('sink_name')} @ {match.group('sink_ea')}."
            )
        return

    if name == "trace_argument_origin":
        source = SOURCE_FUNCTION_PATTERN.search(result)
        if source:
            state.add_confirmed_source(source.group("name"))
        status = TAINT_STATUS_PATTERN.search(result)
        reason = TAINT_REASON_PATTERN.search(result)
        if status and status.group("status").lower() in {"tainted", "verified"}:
            state.resolve_sink(
                str(args.get("call_site", "")),
                str(args.get("caller_ea", "")),
            )
            state.add_verified_finding(_trace_summary(args, source.group("name") if source else ""))
        else:
            state.add_missing_evidence(
                reason.group("reason")
                if reason
                else f"Argument origin remains unresolved for {args.get('caller_ea', 'unknown caller')}."
            )
        return

    if name == "trace_taint_call_chain":
        verified = list(VERIFIED_CHAIN_PATTERN.finditer(result))
        for match in verified:
            state.add_verified_finding(match.group("path"))
        if verified:
            state.resolve_sink(str(args.get("ea", "")))
        if not verified:
            unresolved = UNVERIFIED_CHAIN_PATTERN.search(result)
            state.add_missing_evidence(
                f"Complete source-to-sink evidence for {unresolved.group('path')}."
                if unresolved
                else f"Complete source-to-sink evidence for {args.get('ea', 'the active sink')}."
            )


def _apply_structured_tool_result(
    state: InvestigationState,
    name: str,
    args: dict[str, Any],
    result: str,
) -> bool:
    payload = _parse_tool_json(result)
    if not payload:
        return False

    for route in _as_list(payload.get("confirmed_routes")):
        if isinstance(route, dict):
            state.add_route(
                ConfirmedRoute(
                    route=str(route.get("route") or route.get("route_name") or ""),
                    handler_name=str(route.get("handler_name") or ""),
                    handler_ea=str(route.get("handler_ea") or ""),
                    registration_name=str(route.get("registration_name") or ""),
                    registration_ea=str(route.get("registration_ea") or ""),
                )
            )

    for source in _as_list(payload.get("source_candidates")):
        state.add_source_candidate(_source_name(source))

    for source in _as_list(payload.get("confirmed_sources")):
        state.add_confirmed_source(_source_name(source))

    for sink in _as_list(payload.get("pending_sinks")):
        if isinstance(sink, dict):
            state.add_pending_sink(
                PendingSink(
                    sink_name=str(sink.get("sink_name") or sink.get("name") or ""),
                    sink_ea=str(sink.get("sink_ea") or sink.get("loc") or ""),
                    caller_name=str(sink.get("caller_name") or ""),
                    caller_ea=str(sink.get("caller_ea") or sink.get("caller_addr") or args.get("ea", "")),
                    category=str(sink.get("category") or ""),
                    reason=str(sink.get("reason") or ""),
                )
            )

    for finding in _as_list(payload.get("verified_findings")):
        state.add_verified_finding(_finding_text(finding))

    for note in _as_list(payload.get("function_notes")):
        state.add_function_note(_function_note_text(note))

    for site in _as_list(payload.get("indirect_call_sites")):
        state.add_indirect_call_site(_function_note_text(site))

    for evidence in _as_list(payload.get("missing_evidence")):
        state.add_missing_evidence(_function_note_text(evidence))

    if payload.get("taint_status"):
        status = str(payload.get("taint_status")).lower()
        if status in {"tainted", "verified"}:
            state.resolve_sink(
                str(args.get("call_site", "")),
                str(args.get("caller_ea", "")),
                str(args.get("ea", "")),
            )

    return True


def _parse_tool_json(result: str) -> dict[str, Any] | None:
    text = str(result).strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if not any(
        key in payload
        for key in {
            "confirmed_routes",
            "source_candidates",
            "confirmed_sources",
            "pending_sinks",
            "missing_evidence",
            "function_notes",
            "verified_findings",
            "indirect_call_sites",
        }
    ):
        return None
    return payload


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _source_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("source") or value.get("ea") or "")
    return str(value)


def _finding_text(value: Any) -> str:
    if isinstance(value, dict):
        sink = value.get("sink_name") or value.get("sink") or "sink"
        source = value.get("source") or value.get("source_name") or "source"
        ea = value.get("sink_ea") or value.get("loc") or ""
        return f"{source} -> {sink} {ea}".strip()
    return str(value)


def _function_note_text(value: Any) -> str:
    if isinstance(value, dict):
        ea = value.get("ea") or value.get("function_ea") or value.get("caller_ea") or ""
        name = value.get("name") or value.get("function_name") or value.get("caller_name") or ""
        note = value.get("note") or value.get("reason") or value.get("summary") or value
        prefix = " ".join(str(item) for item in [name, ea] if item)
        return f"{prefix}: {note}" if prefix else str(note)
    return str(value)


def _trace_summary(args: dict[str, Any], source: str) -> str:
    sink = args.get("call_site") or args.get("caller_ea") or "unknown sink"
    return f"{source or 'source'} -> argument at {sink}"


def _first_arg(args: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = args.get(name)
        if value not in (None, ""):
            return value
    return None


def _message_text(message: BaseMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return json.dumps(message.content, ensure_ascii=False, default=str)


def _response_text(response: Any) -> str:
    if isinstance(response, BaseMessage):
        return _message_text(response)
    content = getattr(response, "content", None)
    if isinstance(content, str):
        return content
    if content is not None:
        return json.dumps(content, ensure_ascii=False, default=str)
    return str(response)


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def _clip_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    marker = "\n[Content truncated for LLM context]"
    return text[: max(0, max_chars - len(marker))] + marker


def _keep_recent_text(text: str, max_chars: int, *, marker: str) -> str:
    if len(text) <= max_chars:
        return text
    return marker + text[-max(0, max_chars - len(marker)) :]
