"""Low-level LangGraph runtime adapter used by the VulnAgent harness."""

from __future__ import annotations

import json
import os
import re
from collections.abc import AsyncIterator
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage

from vulnagent.agent.context_builder import ContextBuilder, sanitize_provider_message_order
from vulnagent.agent.execution_limits import AgentExecutionLimits
from vulnagent.agent.langgraph_agent import build_binary_vulnerability_agent
from vulnagent.agent.llm import LlmSettings, build_chat_model, get_active_llm_settings
from vulnagent.skills import load_skill, resolve_skill_name
from vulnagent.storage import SqliteVulnRepository


_SKILL_COMMAND_RE = re.compile(r"^\s*/skill\s+(?P<name>[\w.-]+)(?P<prompt>[\s\S]*)$", re.IGNORECASE)


@dataclass(frozen=True)
class SkillDirective:
    name: str = ""
    prompt: str = ""
    context_note: str = ""


class StandaloneBinaryVulnerabilityAgent:
    """Run one conversational LangGraph IDA investigation loop.

    UI, CLI, and service code should prefer BinaryVulnAgentHarness as the public
    runtime boundary. This adapter stays focused on prompt/context preparation and
    graph invocation.
    """

    def __init__(
        self,
        ida_backend_url: str | None = None,
        report_dir: str | Path | None = None,
        llm_settings: LlmSettings | None = None,
        graph: Any | None = None,
        repository: SqliteVulnRepository | None = None,
        context_builder: ContextBuilder | None = None,
    ) -> None:
        self.llm_settings = llm_settings or get_active_llm_settings()
        self.ida_backend_url = ida_backend_url or os.getenv(
            "IDA_BACKEND_URL",
            "http://127.0.0.1:8765",
        )
        self.report_dir = report_dir or os.getenv("VULN_REPORT_DIR", "./reports")
        self.repository = repository
        self.context_builder = context_builder or (
            ContextBuilder(
                repository,
                summary_llm_factory=lambda: build_chat_model(self.llm_settings),
            )
            if repository is not None
            else None
        )
        self.graph = graph or build_binary_vulnerability_agent(
            lambda config: build_chat_model(self.llm_settings),
            ida_backend_url=self.ida_backend_url,
            report_dir=self.report_dir,
            include_write_tools=_env_bool("VULN_ENABLE_IDB_WRITES"),
            confirm_write_tools=not _env_bool("VULN_AGENT_DIRECT_IDB_WRITES"),
        )
        # Lazily built when ask_stream() is first called — same config but streaming=True
        self._stream_graph: Any | None = None

    async def ask(
        self,
        prompt: str,
        messages: list[BaseMessage] | None = None,
        *,
        thread_id: str = "",
    ) -> list[BaseMessage]:
        """Append a user prompt, execute the tool loop, and return the updated history."""
        skill = _extract_skill_directive(prompt)
        user_prompt = skill.prompt or prompt
        history = [*sanitize_provider_message_order(messages or []), HumanMessage(content=user_prompt)]
        context_messages = history
        context_note = skill.context_note
        if thread_id and self.context_builder:
            prepared = self.context_builder.prepare(thread_id, history)
            context_messages = prepared.messages
            context_note = prepared.context_note + context_note
        result = await self.graph.ainvoke(
            {"messages": context_messages, "context_note": context_note},
            config={
                "configurable": {"thread_id": thread_id},
                "recursion_limit": _recursion_limit(),
            },
        )
        if not thread_id or not self.context_builder:
            return list(result["messages"])

        generated_messages = list(result["messages"])[len(context_messages) :]
        complete_history = sanitize_provider_message_order([*history, *generated_messages])
        self.context_builder.record(thread_id, complete_history)
        return complete_history

    async def ask_stream(
        self,
        prompt: str,
        messages: list[BaseMessage] | None = None,
        *,
        thread_id: str = "",
    ) -> AsyncIterator[str]:
        """Stream SSE-formatted events as the agent works: tool progress + text tokens.

        Yields newline-terminated SSE lines. Each event has a ``data:`` field
        with a JSON object containing ``type`` and optional ``content``/``name``.

        Event types:
          - ``tool_start``  — agent is about to call a tool (``name``, ``input``)
          - ``tool_end``    — tool returned (``name``, ``summary``)
          - ``text_token``  — a fragment of the final AI text (``content``)
          - ``done``        — stream finished; ``content`` is the full final answer
          - ``error``       — unrecoverable error (``content`` is the message)
        """
        skill = _extract_skill_directive(prompt)
        user_prompt = skill.prompt or prompt
        history = [*sanitize_provider_message_order(messages or []), HumanMessage(content=user_prompt)]
        context_messages = history
        context_note = skill.context_note
        if thread_id and self.context_builder:
            prepared = self.context_builder.prepare(thread_id, history)
            context_messages = prepared.messages
            context_note = prepared.context_note + context_note

        result_messages: list[BaseMessage] | None = None

        # Use a streaming-enabled graph so on_chat_model_stream events fire per-token
        if self._stream_graph is None:
            self._stream_graph = build_binary_vulnerability_agent(
                lambda config: build_chat_model(self.llm_settings, streaming=True),
                ida_backend_url=self.ida_backend_url,
                report_dir=self.report_dir,
                include_write_tools=_env_bool("VULN_ENABLE_IDB_WRITES"),
                confirm_write_tools=not _env_bool("VULN_AGENT_DIRECT_IDB_WRITES"),
            )

        from vulnagent.agent.langgraph_agent import _DSML_TOOL_BLOCK_RE

        try:
            async for event in self._stream_graph.astream_events(
                {"messages": context_messages, "context_note": context_note},
                config={
                    "configurable": {"thread_id": thread_id},
                    "recursion_limit": _recursion_limit(),
                },
                version="v2",
            ):
                kind = event.get("event", "")
                name = event.get("name", "")
                data = event.get("data", {})

                if kind == "on_tool_start":
                    tool_input = data.get("input") or {}
                    yield _sse({"type": "tool_start", "name": name, "input": _short_tool_input(tool_input)})

                elif kind == "on_tool_end":
                    output = data.get("output") or ""
                    yield _sse({"type": "tool_end", "name": name, "summary": _short_tool_output(output)})

                elif kind == "on_chain_end" and name == "LangGraph":
                    output = data.get("output") or {}
                    msgs = output.get("messages") or []
                    if msgs:
                        result_messages = list(msgs)

        except Exception as exc:  # noqa: BLE001
            yield _sse({"type": "error", "content": f"{type(exc).__name__}: {exc}"})
            return

        # Persist history after the stream completes
        if result_messages is not None and thread_id:
            from langchain_core.messages import AIMessage as _AI
            generated = result_messages[len(context_messages):]
            complete_history = sanitize_provider_message_order([*history, *generated])
            if self.context_builder:
                self.context_builder.record(thread_id, complete_history)
            # save_chat_messages is the authoritative write path for chat history
            if self.repository is not None:
                self.repository.save_chat_messages(thread_id, complete_history)

        # Extract the final answer from the completed graph output.
        # The graph's _normalize_model_tool_calls already stripped DSML tool-call
        # markup from the last AIMessage, so this text is always clean.
        final_answer = ""
        if result_messages:
            from langchain_core.messages import AIMessage as _AI
            for msg in reversed(result_messages):
                if isinstance(msg, _AI) and msg.content:
                    content = msg.content
                    text = content if isinstance(content, str) else str(content)
                    # Belt-and-suspenders: strip any residual DSML blocks
                    text = _DSML_TOOL_BLOCK_RE.sub("", text).strip()
                    if text:
                        final_answer = text
                        break
        yield _sse({"type": "done", "content": final_answer})


def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _recursion_limit() -> int:
    limits = AgentExecutionLimits.from_env()
    # Each agent loop iteration uses ~3 graph steps (schedule → model → tools).
    # Add 10 as a safety buffer so LangGraph never fires before our own budget logic.
    return limits.max_tool_loops * 3 + 10


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _short_tool_input(tool_input: Any, limit: int = 120) -> str:
    if isinstance(tool_input, dict):
        parts = [f"{k}={str(v)[:40]}" for k, v in list(tool_input.items())[:3]]
        return ", ".join(parts)
    return str(tool_input)[:limit]


def _short_tool_output(output: Any, limit: int = 180) -> str:
    if isinstance(output, str):
        try:
            parsed = json.loads(output)
            if isinstance(parsed, dict):
                for key in ("summary", "text", "error"):
                    if isinstance(parsed.get(key), str):
                        return parsed[key][:limit]
        except (json.JSONDecodeError, TypeError):
            pass
        return output[:limit]
    return str(output)[:limit]


def _extract_skill_directive(prompt: str) -> SkillDirective:
    match = _SKILL_COMMAND_RE.match(prompt)
    if match is None:
        return SkillDirective(prompt=prompt)

    raw_name = match.group("name").strip().lower()
    skill_name = resolve_skill_name(raw_name)
    remaining_prompt = match.group("prompt").strip()
    if not remaining_prompt:
        remaining_prompt = (
            f"Use the `{skill_name}` skill for this turn. Summarize the next inputs "
            "or analysis target needed before continuing."
        )

    skill_text = load_skill(skill_name)
    return SkillDirective(
        name=skill_name,
        prompt=remaining_prompt,
        context_note=(
            "\n\nExplicitly loaded skill for this turn. Follow it when it applies:\n"
            f"Skill name: {skill_name}\n"
            f"{skill_text}\n"
        ),
    )
