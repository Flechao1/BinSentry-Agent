from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from vulnagent.agent.context_builder import ContextBuilder
from vulnagent.agent.investigation_state import InvestigationState
from vulnagent.agent.langgraph_agent import (
    _ruled_out_evidence_anchor,
    _verified_evidence_anchor,
    _verified_evidence_list,
    build_binary_vulnerability_agent,
)
from vulnagent.storage import SqliteVulnRepository
from vulnagent.tools.langchain_tools import build_readonly_ida_tools


def _tool_result(**fields) -> ToolMessage:
    payload = {"format": "vulnagent.tool_result.v1", "text": "tool text", **fields}
    return ToolMessage(
        content=json.dumps(payload),
        name="validate_sink_candidate",
        tool_call_id="t1",
    )


class VerifiedEvidenceListTests(unittest.TestCase):
    def test_collates_verified_findings_from_tool_results(self) -> None:
        state = {
            "messages": [
                _tool_result(
                    verified_findings=[
                        {"summary": "websGetVar -> system @ 0x469034"},
                        "plain finding",
                    ]
                ),
                _tool_result(verified_findings=[{"summary": "websGetVar -> system @ 0x469034"}]),
            ]
        }

        text = _verified_evidence_list(state)

        self.assertEqual(text.count("websGetVar -> system @ 0x469034"), 1)  # dedup
        self.assertIn("plain finding", text)

    def test_empty_when_no_verified_findings(self) -> None:
        state = {"messages": [_tool_result(pending_sinks=[{"sink_name": "system"}])]}
        self.assertEqual(_verified_evidence_list(state), "")

    def test_ignores_non_tool_and_unparseable_messages(self) -> None:
        state = {
            "messages": [
                AIMessage(content="no"),
                ToolMessage(content="plain", name="decompile_function", tool_call_id="t"),
            ]
        }
        self.assertEqual(_verified_evidence_list(state), "")


class VerifiedEvidenceAnchorTests(unittest.TestCase):
    def test_lists_verified_whitelist(self) -> None:
        state = {"messages": [_tool_result(verified_findings=[{"summary": "cmd @ 0x401000"}])]}

        anchor = _verified_evidence_anchor(state)

        self.assertIn("cmd @ 0x401000", anchor)
        self.assertIn("ONLY these may be labeled 'verified'", anchor)

    def test_states_explicitly_when_nothing_verified(self) -> None:
        state = {"messages": [_tool_result(pending_sinks=[{"sink_name": "system"}])]}

        anchor = _verified_evidence_anchor(state)

        self.assertIn("No verified vulnerability evidence was recorded", anchor)
        self.assertIn("unverified candidates", anchor)


class GraphFinalModeEvidenceAnchorTests(unittest.IsolatedAsyncioTestCase):
    def _capture_model(self, captured: dict[str, str]):
        from langchain_core.runnables import Runnable

        class FinalModeModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next((m for m in input if isinstance(m, SystemMessage)), None)
                captured["system"] = system.content if system else ""
                captured["count"] = captured.get("count", 0) + 1
                if captured["count"] < 3:
                    return AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": f"final-c{captured['count']}",
                                "name": "list_binary_functions",
                                "args": {},
                                "type": "tool_call",
                            }
                        ],
                    )
                return AIMessage(content="final summary")

        return FinalModeModel()

    async def _run(self, seed_messages: list) -> str:
        captured: dict[str, str] = {}
        with patch.dict("os.environ", {"VULN_AGENT_MAX_TOOL_CALLS": "1"}), patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: self._capture_model(captured))
            await graph.ainvoke({"messages": seed_messages})
        return captured.get("system", "")

    async def test_final_mode_states_when_no_tool_verified_anything(self) -> None:
        system = await self._run([HumanMessage(content="find vulnerabilities")])

        self.assertIn("Final-response mode", system)
        self.assertIn("No verified vulnerability evidence was recorded", system)

    async def test_final_mode_injects_tool_verified_whitelist(self) -> None:
        seed = [
            HumanMessage(content="find vulnerabilities"),
            _tool_result(verified_findings=[{"summary": "sub_469034 -> system (verified)"}]),
        ]

        system = await self._run(seed)

        self.assertIn("sub_469034 -> system (verified)", system)
        self.assertIn("ONLY these may be labeled 'verified'", system)
        self.assertNotIn("No verified vulnerability evidence was recorded", system)


class RuledOutStateTests(unittest.TestCase):
    def test_adds_and_dedups_ruled_out_paths(self) -> None:
        state = InvestigationState()
        path = "SetNetworkSettings IPAddress -> echo: blocked by tbsCheckHostIpEx"
        state.add_ruled_out_path(path)
        state.add_ruled_out_path(path)
        self.assertEqual(state.ruled_out_paths, [path])

    def test_compact_bounds_ruled_out_paths(self) -> None:
        state = InvestigationState()
        for index in range(60):
            state.add_ruled_out_path(f"path-{index}")
        state.compact()
        self.assertLessEqual(len(state.ruled_out_paths), 30)
        self.assertNotIn("path-0", state.ruled_out_paths)

    def test_prompt_dump_includes_ruled_out_paths(self) -> None:
        state = InvestigationState()
        state.add_ruled_out_path("excluded-chain")
        self.assertIn("ruled_out_paths", state.prompt_dump())


class RuledOutAnchorTests(unittest.TestCase):
    def test_lists_ruled_out_false_positives(self) -> None:
        state = {
            "messages": [
                ToolMessage(
                    content=json.dumps(
                        {
                            "ruled_out": [
                                {
                                    "path": "SetNetworkSettings IPAddress -> echo",
                                    "reason": "blocked by tbsCheckHostIpEx",
                                    "sink_ea": "0x43f64c",
                                }
                            ]
                        }
                    ),
                    name="record_investigation_exclusion",
                    tool_call_id="t1",
                )
            ]
        }

        anchor = _ruled_out_evidence_anchor(state)

        self.assertIn("Ruled-out false positives", anchor)
        self.assertIn("blocked by tbsCheckHostIpEx", anchor)

    def test_empty_when_no_exclusions(self) -> None:
        state = {
            "messages": [
                ToolMessage(
                    content=json.dumps({"pending_sinks": [{"sink_name": "system"}]}),
                    name="validate_sink_candidate",
                    tool_call_id="t1",
                )
            ]
        }
        self.assertEqual(_ruled_out_evidence_anchor(state), "")


class RuledOutPersistenceTests(unittest.TestCase):
    def test_structured_ruled_out_channel_updates_state(self) -> None:
        with TemporaryDirectory() as temporary_dir:
            repository = SqliteVulnRepository(f"{temporary_dir}/vulnagent.db")
            thread_id = repository.create_chat_thread()
            builder = ContextBuilder(repository, semantic_summary_enabled=False)
            messages = [
                HumanMessage(content="audit"),
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "r1",
                            "name": "record_investigation_exclusion",
                            "args": {
                                "path": "SetNetworkSettings IPAddress -> echo",
                                "reason": "blocked by tbsCheckHostIpEx",
                                "sink_ea": "0x43f64c",
                            },
                            "type": "tool_call",
                        }
                    ],
                ),
                ToolMessage(
                    content=json.dumps(
                        {
                            "ruled_out": [
                                {
                                    "path": "SetNetworkSettings IPAddress -> echo",
                                    "reason": "blocked by tbsCheckHostIpEx",
                                    "sink_ea": "0x43f64c",
                                }
                            ]
                        }
                    ),
                    name="record_investigation_exclusion",
                    tool_call_id="r1",
                ),
            ]

            builder.prepare(thread_id, messages)

            state = InvestigationState.model_validate(
                repository.get_investigation_state(thread_id)
            )
            self.assertEqual(len(state.ruled_out_paths), 1)
            self.assertIn("tbsCheckHostIpEx", state.ruled_out_paths[0])

    def test_rejected_candidate_derives_ruled_out(self) -> None:
        with TemporaryDirectory() as temporary_dir:
            repository = SqliteVulnRepository(f"{temporary_dir}/vulnagent.db")
            thread_id = repository.create_chat_thread()
            builder = ContextBuilder(repository, semantic_summary_enabled=False)
            messages = [
                HumanMessage(content="audit"),
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "v1",
                            "name": "validate_sink_candidate",
                            "args": {"sink_ea": "0x43f6e8", "caller_ea": "0x43f600"},
                            "type": "tool_call",
                        }
                    ],
                ),
                ToolMessage(
                    content=json.dumps(
                        {
                            "candidate_findings": [
                                {
                                    "candidate_id": "echo:0x43f6e8:0x43f600",
                                    "status": "rejected",
                                    "category": "command_injection",
                                    "sink_name": "echo",
                                    "sink_ea": "0x43f6e8",
                                    "caller_name": "SetNetworkSettings",
                                    "caller_ea": "0x43f600",
                                    "conclusion": "tbsCheckMaskEx rejects non-IPv4 payload",
                                }
                            ]
                        }
                    ),
                    name="validate_sink_candidate",
                    tool_call_id="v1",
                ),
            ]

            builder.prepare(thread_id, messages)

            state = InvestigationState.model_validate(
                repository.get_investigation_state(thread_id)
            )
            self.assertEqual(len(state.ruled_out_paths), 1)
            self.assertIn("tbsCheckMaskEx", state.ruled_out_paths[0])


class RuledOutToolExposureTests(unittest.TestCase):
    def test_record_investigation_exclusion_tool_is_exposed(self) -> None:
        tools = build_readonly_ida_tools(object())  # type: ignore[arg-type]
        names = {tool.name for tool in tools}
        self.assertIn("record_investigation_exclusion", names)

    def test_record_investigation_exclusion_returns_structured_payload(self) -> None:
        tools = build_readonly_ida_tools(object())  # type: ignore[arg-type]
        tool = next(tool for tool in tools if tool.name == "record_investigation_exclusion")
        result = tool.invoke(
            {"path": "A -> system", "reason": "guard blocks payload", "sink_ea": "0x1000"}
        )
        payload = json.loads(result)
        self.assertIn("ruled_out", payload)
        self.assertEqual(payload["ruled_out"][0]["sink_ea"], "0x1000")
        self.assertIn("guard blocks payload", payload["ruled_out"][0]["reason"])


class GraphRuledOutPromptTests(unittest.IsolatedAsyncioTestCase):
    async def _capture_system(self) -> str:
        from langchain_core.runnables import Runnable

        captured: dict[str, str] = {}

        class CaptureModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next((m for m in input if isinstance(m, SystemMessage)), None)
                captured["system"] = system.content if system else ""
                return AIMessage(content="ok")

        with patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: CaptureModel())
            await graph.ainvoke({"messages": [HumanMessage(content="挖掘命令注入")]})
        return captured.get("system", "")

    async def test_prompt_requires_guard_decompilation_and_exclusions(self) -> None:
        system = await self._capture_system()

        self.assertIn("MUST decompile that guard", system)
        self.assertIn("record_investigation_exclusion", system)
        self.assertIn("ruled_out_paths", system)
        self.assertIn("do not re-report", system)


class GraphFinalModeRuledOutAnchorTests(unittest.IsolatedAsyncioTestCase):
    def _capture_model(self, captured: dict[str, str]):
        from langchain_core.runnables import Runnable

        class FinalModeModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next((m for m in input if isinstance(m, SystemMessage)), None)
                captured["system"] = system.content if system else ""
                captured["count"] = captured.get("count", 0) + 1
                if captured["count"] < 3:
                    return AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": f"final-c{captured['count']}",
                                "name": "list_binary_functions",
                                "args": {},
                                "type": "tool_call",
                            }
                        ],
                    )
                return AIMessage(content="final summary")

        return FinalModeModel()

    async def test_final_mode_injects_ruled_out_false_positives(self) -> None:
        captured: dict[str, str] = {}
        seed = [
            HumanMessage(content="find vulnerabilities"),
            ToolMessage(
                content=json.dumps(
                    {
                        "ruled_out": [
                            {
                                "path": "SetNetworkSettings IPAddress -> echo",
                                "reason": "blocked by tbsCheckHostIpEx",
                                "sink_ea": "0x43f64c",
                            }
                        ]
                    }
                ),
                name="record_investigation_exclusion",
                tool_call_id="t1",
            ),
        ]
        with patch.dict("os.environ", {"VULN_AGENT_MAX_TOOL_CALLS": "1"}), patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: self._capture_model(captured))
            await graph.ainvoke({"messages": seed})

        system = captured.get("system", "")
        self.assertIn("Ruled-out false positives", system)
        self.assertIn("blocked by tbsCheckHostIpEx", system)


if __name__ == "__main__":
    unittest.main()
