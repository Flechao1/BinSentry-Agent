"""Low-level LangGraph runtime adapter used by the VulnAgent harness."""

from __future__ import annotations

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage

from vulnagent.agent.context_builder import ContextBuilder, sanitize_provider_message_order
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
            config={"configurable": {"thread_id": thread_id}},
        )
        if not thread_id or not self.context_builder:
            return list(result["messages"])

        generated_messages = list(result["messages"])[len(context_messages) :]
        complete_history = sanitize_provider_message_order([*history, *generated_messages])
        self.context_builder.record(thread_id, complete_history)
        return complete_history


def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


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
