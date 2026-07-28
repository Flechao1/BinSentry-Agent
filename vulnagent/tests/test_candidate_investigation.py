from __future__ import annotations

import json
import unittest

from vulnagent.ida.schemas import ArgumentOriginResult, SinkCallResult, SinkScanResult
from vulnagent.tools.recon_tools import IdaReconTools


class FakeCandidateClient:
    def scan_sink_calls(self, sink_specs, roots=None, max_depth=8, max_functions=500):
        return SinkScanResult(
            scope="provided-roots" if roots else "global-fallback",
            roots=roots or [],
            scanned_functions=2,
            results=[
                SinkCallResult(
                    loc="0x401020",
                    caller_addr="0x401000",
                    caller_name="web_handler",
                    sink_name="system",
                    callee_ea="0x500000",
                    category="command",
                    confidence=0.8,
                    score=90,
                    args=[{"index": 1, "expr": "cmd", "arg_type": "variable"}],
                ),
                SinkCallResult(
                    loc="0x401040",
                    caller_addr="0x401000",
                    caller_name="web_handler",
                    sink_name="strcpy",
                    callee_ea="0x500100",
                    category="memory",
                    confidence=0.7,
                    score=70,
                    args=[{"index": 2, "expr": "value", "arg_type": "variable"}],
                ),
            ],
        )

    def trace_argument_origin(
        self,
        caller_ea,
        call_site,
        callee_ea,
        target_arg_idx=1,
        sources=None,
    ):
        if str(callee_ea).lower() == "0x500000":
            return ArgumentOriginResult(
                taint_status="tainted",
                source_func="websGetVar",
                source_expr="cmd",
                reason="argument comes from a Web request parameter",
            )
        return ArgumentOriginResult(
            taint_status="tainted",
            source_func="websGetVar",
            source_expr="value",
            reason="argument comes from a Web request parameter",
        )


class CandidateInvestigationToolTests(unittest.TestCase):
    def test_returns_conservative_structured_verdicts(self) -> None:
        result = IdaReconTools(FakeCandidateClient()).investigate_vulnerability_candidates(
            category="all",
            roots="0x401000",
            max_candidates=4,
        )
        payload = json.loads(result)
        findings = {item["sink_name"]: item for item in payload["candidate_findings"]}

        self.assertEqual(findings["system"]["status"], "verified")
        self.assertEqual(findings["system"]["category"], "command-injection")
        self.assertEqual(findings["strcpy"]["status"], "unverified")
        self.assertEqual(payload["validation_summary"]["counts"]["verified"], 1)
        self.assertEqual(payload["validation_summary"]["counts"]["unverified"], 1)
        self.assertEqual(len(payload["pending_sinks"]), 1)

    def test_rejects_invalid_category_without_backend_call(self) -> None:
        result = IdaReconTools(FakeCandidateClient()).investigate_vulnerability_candidates(
            category="sql-injection",
        )
        payload = json.loads(result)
        self.assertIn("Unsupported vulnerability category", payload["text"])
        self.assertTrue(payload["missing_evidence"])


if __name__ == "__main__":
    unittest.main()
