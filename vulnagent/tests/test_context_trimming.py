from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import patch

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from vulnagent.agent.context_builder import ContextBudget, trim_messages_for_model
from vulnagent.agent.langgraph_agent import (
    _last_user_instruction,
    _message_budget_for_model,
    build_binary_vulnerability_agent,
)


def _message_chars(message: BaseMessage) -> int:
    return len(message.content) if isinstance(message.content, str) else 0


def _batch(seed: int, *, content: str | None = None) -> list[BaseMessage]:
    body = content or ("x" * 400)
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "id": f"call-{seed}",
                    "name": "get_function_context",
                    "args": {"ea": f"0x{seed:04x}"},
                    "type": "tool_call",
                }
            ],
        ),
        ToolMessage(content=body, name="get_function_context", tool_call_id=f"call-{seed}"),
    ]


def _anchor() -> HumanMessage:
    return HumanMessage(content="Audit the firmware login route")


def _sequence(*batches: list[BaseMessage]) -> list[BaseMessage]:
    return [_anchor(), *[message for batch in batches for message in batch]]


class TrimMessagesForModelTests(unittest.TestCase):
    def test_returns_unchanged_when_under_budget(self) -> None:
        messages = _sequence(_batch(1), _batch(2))

        trimmed = trim_messages_for_model(
            messages,
            max_tokens=10_000,
            max_message_tokens=2000,
        )

        self.assertEqual(len(trimmed), len(messages))
        self.assertEqual([m.tool_call_id for m in trimmed if isinstance(m, ToolMessage)],
                         ["call-1", "call-2"])

    def test_keeps_anchor_and_most_recent_batches(self) -> None:
        messages = _sequence(_batch(1), _batch(2), _batch(3))
        # Anchor (~7 tokens) + two batches (~102 each) fit in 220; batch 1 is dropped.
        trimmed = trim_messages_for_model(
            messages,
            max_tokens=220,
            max_message_tokens=2000,
        )

        kept_ids = [m.tool_call_id for m in trimmed if isinstance(m, ToolMessage)]
        self.assertEqual(kept_ids, ["call-2", "call-3"])
        self.assertNotIn("call-1", kept_ids)
        self.assertIn(_anchor().content, [m.content for m in trimmed])

    def test_no_orphan_tool_messages_after_trim(self) -> None:
        messages = _sequence(_batch(1), _batch(2), _batch(3))
        trimmed = trim_messages_for_model(
            messages,
            max_tokens=220,
            max_message_tokens=2000,
        )

        requested = {
            call["id"]
            for message in trimmed
            if isinstance(message, AIMessage)
            for call in message.tool_calls
        }
        returned = {
            message.tool_call_id
            for message in trimmed
            if isinstance(message, ToolMessage)
        }
        self.assertTrue(returned.issubset(requested))

    def test_clips_oversized_single_message(self) -> None:
        messages = _sequence(_batch(1, content="y" * 5000))
        max_message_chars = 100 * 4

        trimmed = trim_messages_for_model(
            messages,
            max_tokens=10_000,
            max_message_tokens=100,
        )

        tool_content = next(
            message.content for message in trimmed if isinstance(message, ToolMessage)
        )
        self.assertEqual(len(tool_content), max_message_chars)
        self.assertIn("[Content truncated", tool_content)

    def test_tiny_budget_still_keeps_task_anchor(self) -> None:
        messages = _sequence(_batch(1), _batch(2))
        trimmed = trim_messages_for_model(
            messages,
            max_tokens=1,
            max_message_tokens=2000,
        )

        self.assertEqual([message.content for message in trimmed], [_anchor().content])

    def test_empty_and_single_message_inputs(self) -> None:
        self.assertEqual(trim_messages_for_model([], max_tokens=100, max_message_tokens=100), [])
        single = [HumanMessage(content="hi")]
        self.assertEqual(
            trim_messages_for_model(single, max_tokens=1, max_message_tokens=100),
            single,
        )


class BoundedRecentTokensTests(unittest.TestCase):
    def test_response_reserve_is_honored_as_a_real_cap(self) -> None:
        budget = ContextBudget(
            max_input_tokens=5000,
            summary_tokens=300,
            state_tokens=300,
            response_reserve_tokens=400,
            recent_message_tokens=10_000,
        )

        self.assertEqual(budget.bounded_recent_message_tokens, 4000)
        self.assertLess(budget.bounded_recent_message_tokens, budget.recent_message_tokens)

    def test_defaults_still_prefer_recent_window(self) -> None:
        budget = ContextBudget()
        self.assertEqual(
            budget.bounded_recent_message_tokens,
            budget.recent_message_tokens,
        )


class MessageBudgetForModelTests(unittest.TestCase):
    def test_reserves_overhead_and_response_room(self) -> None:
        budget = ContextBudget(max_input_tokens=12_000, response_reserve_tokens=2400)
        instructions = "i" * 800   # ~200 tokens
        context_note = "n" * 1200  # ~300 tokens

        result = _message_budget_for_model(context_note, instructions, budget)

        self.assertEqual(result, 12_000 - 200 - 300 - 2400)

    def test_floors_so_the_model_never_starves(self) -> None:
        budget = ContextBudget(max_input_tokens=500)
        result = _message_budget_for_model("note", "instructions", budget)
        self.assertEqual(result, 1024)


class GraphPromptBoundingTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_loop_prompt_stays_bounded(self) -> None:
        from langchain_core.runnables import Runnable
        from langchain_core.tools import StructuredTool

        received_chars: list[int] = []
        call_counter = [0]

        def probe(seed: int) -> str:
            return "P" * 2000

        class FloodingModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                messages = [
                    message
                    for message in input
                    if isinstance(message, (AIMessage, HumanMessage, ToolMessage))
                ]
                received_chars.append(sum(_message_chars(message) for message in messages))
                call_counter[0] += 1
                if call_counter[0] < 10:
                    return AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": f"call-{call_counter[0]}",
                                "name": "probe",
                                "args": {"seed": call_counter[0]},
                                "type": "tool_call",
                            }
                        ],
                    )
                return AIMessage(content="analysis complete")

        tool = StructuredTool.from_function(
            probe,
            name="probe",
            description="Emit a large probe result.",
        )
        with patch.dict(
            "os.environ",
            {
                "VULN_CONTEXT_MAX_INPUT_TOKENS": "2000",
                "VULN_CONTEXT_RESPONSE_RESERVE_TOKENS": "100",
            },
        ), patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[tool],
        ):
            graph = build_binary_vulnerability_agent(lambda config: FloodingModel())
            await graph.ainvoke({"messages": [HumanMessage(content="probe the binary")]})

        self.assertGreater(len(received_chars), 3)  # flooding actually happened
        self.assertLess(max(received_chars), 2000 * 4)  # every prompt stayed bounded
        self.assertEqual(len(received_chars), 10)


class InstructionAnchoringTests(unittest.TestCase):
    def test_returns_most_recent_user_message(self) -> None:
        messages = [
            HumanMessage(content="先扫描"),
            AIMessage(content="扫描完成"),
            HumanMessage(content="webGetVar 为 source 的命令注入有哪些"),
        ]
        self.assertEqual(
            _last_user_instruction(messages),
            "webGetVar 为 source 的命令注入有哪些",
        )

    def test_skips_tool_tail_and_finds_user_message(self) -> None:
        messages = [
            HumanMessage(content="挖掘 RCE"),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "c1",
                        "name": "scan_dangerous_sink_calls",
                        "args": {},
                        "type": "tool_call",
                    }
                ],
            ),
            ToolMessage(content="sinks", name="scan_dangerous_sink_calls", tool_call_id="c1"),
        ]
        self.assertEqual(_last_user_instruction(messages), "挖掘 RCE")

    def test_empty_when_no_user_message(self) -> None:
        self.assertEqual(_last_user_instruction([AIMessage(content="hi")]), "")

    def test_truncates_long_instruction(self) -> None:
        messages = [HumanMessage(content="x" * 1000)]
        self.assertEqual(len(_last_user_instruction(messages, max_chars=100)), 100)

    def test_extracts_text_from_structured_content(self) -> None:
        messages = [HumanMessage(content=[{"type": "text", "text": "分析这个二进制"}])]
        self.assertIn("分析这个二进制", _last_user_instruction(messages))


class GraphInstructionAnchorTests(unittest.IsolatedAsyncioTestCase):
    async def test_prompt_contains_current_instruction_anchor(self) -> None:
        from langchain_core.runnables import Runnable

        captured: dict[str, str] = {}

        class AnchorModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next(
                    (m for m in input if isinstance(m, SystemMessage)),
                    None,
                )
                captured["system"] = system.content if system else ""
                return AIMessage(content="分析完成")

        with patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: AnchorModel())
            await graph.ainvoke(
                {"messages": [HumanMessage(content="webGetVar 为 source 的命令注入有哪些")]}
            )

        self.assertIn("Current user instruction:", captured["system"])
        self.assertIn("webGetVar 为 source 的命令注入有哪些", captured["system"])


class GraphResumeInstructionTests(unittest.IsolatedAsyncioTestCase):
    async def test_system_prompt_instructs_resume_on_continue(self) -> None:
        from langchain_core.runnables import Runnable

        captured: dict[str, str] = {}

        class CaptureModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next(
                    (m for m in input if isinstance(m, SystemMessage)),
                    None,
                )
                captured["system"] = system.content if system else ""
                return AIMessage(content="ok")

        with patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: CaptureModel())
            await graph.ainvoke({"messages": [HumanMessage(content="继续")]})

        self.assertIn("Current user instruction:\n继续", captured["system"])
        self.assertIn("do not restart discovery", captured["system"])
        self.assertIn("pending candidates", captured["system"])

    async def test_system_prompt_requires_guard_resolution_before_verified(self) -> None:
        from langchain_core.runnables import Runnable

        captured: dict[str, str] = {}

        class CaptureModel(Runnable):
            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                system = next(
                    (m for m in input if isinstance(m, SystemMessage)),
                    None,
                )
                captured["system"] = system.content if system else ""
                return AIMessage(content="ok")

        with patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: CaptureModel())
            await graph.ainvoke({"messages": [HumanMessage(content="挖掘命令注入")]})

        self.assertIn("guard", captured["system"])
        self.assertIn("guard is bypassable", captured["system"])
        self.assertIn("external or opaque function", captured["system"])


class GraphModelTimeoutRetryTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, stall_count: int) -> tuple[list[BaseMessage], int]:
        from langchain_core.runnables import Runnable

        class StallingModel(Runnable):
            def __init__(self, stalls: int) -> None:
                self.stalls = stalls
                self.calls = 0

            def bind_tools(self, tools):
                return self

            def invoke(self, input, config=None, **kwargs):
                self.calls += 1
                if self.calls <= self.stalls:
                    time.sleep(0.2)
                return AIMessage(content=f"response-{self.calls}")

            async def ainvoke(self, input, config=None, **kwargs):
                self.calls += 1
                if self.calls <= self.stalls:
                    await asyncio.sleep(0.2)
                return AIMessage(content=f"response-{self.calls}")

        model = StallingModel(stall_count)
        with patch.dict(
            "os.environ",
            {"VULN_AGENT_MODEL_TIMEOUT_SECONDS": "0.05"},
        ), patch(
            "vulnagent.agent.langgraph_agent.build_readonly_ida_tools",
            return_value=[],
        ):
            graph = build_binary_vulnerability_agent(lambda config: model)
            result = await graph.ainvoke({"messages": [HumanMessage(content="probe")]})
        return list(result["messages"]), model.calls

    async def test_single_stall_retries_and_keeps_the_turn_alive(self) -> None:
        messages, calls = await self._run(stall_count=1)

        self.assertEqual(calls, 2)  # first call stalled, retry succeeded
        self.assertEqual(messages[-1].content, "response-2")
        self.assertNotIn("budget", str(messages[-1].content))

    async def test_double_stall_reports_model_stall_not_budget_exhaustion(self) -> None:
        messages, calls = await self._run(stall_count=2)

        self.assertEqual(calls, 2)
        self.assertIn("transient model stall", messages[-1].content)
        self.assertNotIn("budget was reached", messages[-1].content)


if __name__ == "__main__":
    unittest.main()
