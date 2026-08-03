from __future__ import annotations

import json
import unittest

from langchain_core.messages import ToolMessage

from vulnagent.agent.execution_limits import AgentExecutionLimits, budget_stop_message, model_timeout_message
from vulnagent.agent.langgraph_agent import (
    _TOOL_DEGRADE_HINTS,
    _build_continuation_plan,
    _budget_warning,
)
from vulnagent.ida.schemas import SinkCallResult, SinkScanResult
from vulnagent.tools.recon_tools import IdaReconTools


def _sink(loc: str, caller: str, name: str, *, score: int = 90, category: str = "command") -> SinkCallResult:
    return SinkCallResult(
        loc=loc,
        caller_addr=caller,
        caller_name=caller,
        sink_name=name,
        callee_ea="0x500000",
        category=category,
        confidence=0.8,
        score=score,
        args=[{"index": 1, "expr": "cmd", "arg_type": "variable"}],
    )


class FakeSinkClient:
    def scan_sink_calls(self, sink_specs, roots=None, max_depth=8, max_functions=500):
        return SinkScanResult(
            scope="global-fallback",
            roots=roots or [],
            scanned_functions=4,
            results=[
                _sink("0x401010", "firmware_upgrade", "system", score=95),
                _sink("0x401020", "firmware_upgrade", "system", score=95),
                _sink("0x401030", "firmware_upgrade", "system", score=95),
                _sink("0x402010", "wlan_set", "strcpy", score=70, category="memory"),
                _sink("0x402020", "wlan_set", "system", score=60),
                _sink("0x403010", "time_set", "popen", score=55),
                _sink("0x404010", "sys_handle", "system", score=40),
            ],
        )


class SinkScanAggregationTests(unittest.TestCase):
    def test_aggregates_scan_output_by_caller_and_sink(self) -> None:
        payload = json.loads(IdaReconTools(FakeSinkClient()).scan_sink_calls())

        by_key = {
            (item["caller_name"], item["sink_name"]): item
            for item in payload["sink_aggregates"]
        }
        self.assertEqual(by_key[("firmware_upgrade", "system")]["count"], 3)
        self.assertEqual(by_key[("wlan_set", "strcpy")]["count"], 1)
        self.assertIn("Aggregated sink groups: 5", payload["text"])
        self.assertIn("3 x system", payload["text"])

    def test_pending_sinks_and_findings_are_bounded(self) -> None:
        payload = json.loads(IdaReconTools(FakeSinkClient()).scan_sink_calls())

        self.assertLessEqual(len(payload["pending_sinks"]), 20)
        self.assertLessEqual(len(payload["candidate_findings"]), 20)
        self.assertTrue(payload["pending_sinks"])
        self.assertIn("sink_aggregates", payload)
        self.assertIn("vulnagent.tool_result.v1", payload["format"])


class ContinuationPlanTests(unittest.TestCase):
    def test_builds_plan_from_completed_tool_results(self) -> None:
        state = {
            "messages": [
                ToolMessage(
                    content=json.dumps({
                        "format": "vulnagent.tool_result.v1",
                        "text": "Candidate investigation.",
                        "pending_sinks": [{
                            "sink_name": "system",
                            "sink_ea": "0x402000",
                            "caller_name": "applyConfig",
                            "category": "command-injection",
                        }],
                        "verified_findings": ["sub_1 -> system 0x402000"],
                        "missing_evidence": [{"reason": "Confirm filtering before system."}],
                        "confirmed_sources": [{"name": "websGetVar"}],
                    }),
                    name="investigate_vulnerability_candidates",
                    tool_call_id="t1",
                )
            ]
        }

        plan = _build_continuation_plan(state)

        self.assertIn("Continuation plan", plan)
        self.assertIn("system @ 0x402000", plan)
        self.assertIn("websGetVar", plan)
        self.assertIn("Confirm filtering", plan)
        self.assertIn("Pending sink candidates (1)", plan)

    def test_empty_when_no_tool_evidence(self) -> None:
        state = {"messages": [ToolMessage(content="plain", name="decompile_function", tool_call_id="t1")]}
        self.assertEqual(_build_continuation_plan(state), "")


class BudgetStopMessageTests(unittest.TestCase):
    def test_continuation_is_appended(self) -> None:
        message = budget_stop_message(
            "The model response timeout was reached.",
            "Continuation plan: pending candidates.",
        )
        self.assertIn("Continuation plan", message)
        self.assertIn("follow-up instruction", message)

    def test_legacy_message_without_continuation(self) -> None:
        message = budget_stop_message("The per-turn execution time limit was reached.")
        self.assertNotIn("Continuation plan", message)
        self.assertIn("focused follow-up", message)


class ModelTimeoutMessageTests(unittest.TestCase):
    def test_distinguishes_stall_from_budget_condition(self) -> None:
        message = model_timeout_message("Continuation plan: pending candidates.")
        self.assertIn("transient model stall", message)
        self.assertIn("not a budget limit", message)
        self.assertNotIn("budget was reached", message)
        self.assertIn("Continuation plan", message)

    def test_works_without_continuation(self) -> None:
        message = model_timeout_message()
        self.assertIn("retry the same instruction", message)
        self.assertNotIn("Continuation plan", message)


class ToolDegradeHintTests(unittest.TestCase):
    def test_scan_tool_has_scope_reduction_hint(self) -> None:
        hint = _TOOL_DEGRADE_HINTS["scan_dangerous_sink_calls"]
        self.assertIn("roots=", hint)
        self.assertIn("max_functions", hint)

    def test_heavy_tools_advise_lighter_alternatives(self) -> None:
        self.assertIn("get_function_signals", _TOOL_DEGRADE_HINTS["decompile_function"])
        self.assertIn("trace_argument_origin", _TOOL_DEGRADE_HINTS["trace_taint_call_chain"])


class BudgetWarningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.limits = AgentExecutionLimits(max_tool_calls=48, max_tool_loops=24)

    def test_no_warning_when_budget_fresh(self) -> None:
        state = {"tool_call_count": 5, "tool_loop_count": 2}
        self.assertEqual(_budget_warning(state, self.limits), "")

    def test_heads_up_warning_at_80_percent(self) -> None:
        state = {"tool_call_count": 39, "tool_loop_count": 3}
        warning = _budget_warning(state, self.limits)
        self.assertIn("most of the tool budget is spent", warning)
        self.assertIn("narrow, targeted tool call", warning)

    def test_exhausted_warning_forbids_more_tools(self) -> None:
        state = {"tool_call_count": 48, "tool_loop_count": 20}
        warning = _budget_warning(state, self.limits)
        self.assertIn("tool budget is exhausted", warning)
        self.assertIn("Do not request any more tools", warning)


if __name__ == "__main__":
    unittest.main()
