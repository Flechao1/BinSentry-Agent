from __future__ import annotations

import unittest

from vulnagent.agent.validation_planner import ValidationPlanner
from vulnagent.ida.schemas import ArgumentOriginResult, SinkCallResult


class FakeOriginClient:
    def __init__(self, results: dict[int, ArgumentOriginResult]) -> None:
        self.results = results
        self.calls: list[int] = []

    def trace_argument_origin(
        self,
        caller_ea,
        call_site,
        callee_ea,
        target_arg_idx=1,
        sources=None,
    ) -> ArgumentOriginResult:
        self.calls.append(target_arg_idx)
        return self.results[target_arg_idx]


def _sink(name: str, *, argument_index: int = 1) -> SinkCallResult:
    return SinkCallResult(
        loc="0x401020",
        caller_addr="0x401000",
        caller_name="web_handler",
        sink_name=name,
        callee_ea="0x43c000",
        args=[{"index": argument_index, "expr": "request_value", "arg_type": "variable"}],
    )


class ValidationPlannerTests(unittest.TestCase):
    def test_verifies_remote_input_to_command_sink(self) -> None:
        client = FakeOriginClient(
            {
                1: ArgumentOriginResult(
                    taint_status="tainted",
                    source_func="websGetVar",
                    source_expr="request_value",
                    reason="argument comes from Web request parameter",
                )
            }
        )

        finding = ValidationPlanner().validate(_sink("system"), client)

        self.assertEqual(finding.status, "verified")
        self.assertEqual(finding.category, "command-injection")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(client.calls, [1])

    def test_keeps_tainted_memory_sink_unverified_without_bounds_proof(self) -> None:
        client = FakeOriginClient(
            {
                2: ArgumentOriginResult(
                    taint_status="tainted",
                    source_func="cgiFormString",
                    source_expr="form_value",
                    reason="argument comes from CGI form input",
                )
            }
        )

        finding = ValidationPlanner().validate(_sink("strcpy", argument_index=2), client)

        self.assertEqual(finding.status, "unverified")
        self.assertEqual(finding.category, "memory-safety")
        self.assertTrue(any("destination buffer size" in item for item in finding.missing_evidence))

    def test_rejects_candidate_when_all_dangerous_arguments_are_clean(self) -> None:
        client = FakeOriginClient(
            {1: ArgumentOriginResult(taint_status="clean", reason="constant configuration value")}
        )

        finding = ValidationPlanner().validate(_sink("system"), client)

        self.assertEqual(finding.status, "rejected")
        self.assertEqual(finding.confidence, 0.85)

    def test_verifies_vendor_command_wrapper_case_insensitively(self) -> None:
        client = FakeOriginClient(
            {
                1: ArgumentOriginResult(
                    taint_status="tainted",
                    source_func="getRequestParam",
                    source_expr="param",
                    reason="request parameter reaches wrapper",
                )
            }
        )

        finding = ValidationPlanner().validate(_sink("CsteSystem"), client)

        self.assertEqual(finding.status, "verified")
        self.assertEqual(finding.category, "command-injection")
        self.assertEqual(finding.severity, "critical")

    def test_promotes_remote_memory_candidate_from_nvram_or_request_helpers(self) -> None:
        client = FakeOriginClient(
            {
                2: ArgumentOriginResult(
                    taint_status="tainted",
                    source_func="nvram_safe_get",
                    source_expr="value",
                    reason="configuration value is externally controlled",
                )
            }
        )

        finding = ValidationPlanner().validate(_sink("strncat", argument_index=2), client)

        self.assertEqual(finding.status, "unverified")
        self.assertEqual(finding.category, "memory-safety")
        self.assertEqual(finding.severity, "high")
        self.assertGreaterEqual(finding.confidence, 0.75)


if __name__ == "__main__":
    unittest.main()
