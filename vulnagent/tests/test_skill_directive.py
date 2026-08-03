from __future__ import annotations

import unittest

from vulnagent.agent.standalone import _extract_skill_directive
from vulnagent.skills import load_skill


class SkillDirectiveTests(unittest.TestCase):
    def test_plain_prompt_does_not_load_skill(self) -> None:
        directive = _extract_skill_directive("scan command injection candidates")

        self.assertEqual(directive.name, "")
        self.assertEqual(directive.prompt, "scan command injection candidates")
        self.assertEqual(directive.context_note, "")

    def test_skill_command_loads_vuln_discovery_for_current_turn(self) -> None:
        directive = _extract_skill_directive("/skill vuln_discovery scan command injection")

        self.assertEqual(directive.name, "vuln_discovery")
        self.assertEqual(directive.prompt, "scan command injection")
        self.assertIn("Explicitly loaded skill for this turn", directive.context_note)
        self.assertIn("Vulnerability Discovery Skill Index", directive.context_note)

    def test_focused_skill_command_loads_discovery_module(self) -> None:
        directive = _extract_skill_directive("/skill discovery rank firmware binaries")

        self.assertEqual(directive.name, "discovery")
        self.assertEqual(directive.prompt, "rank firmware binaries")
        self.assertIn("Discovery Skill", directive.context_note)

    def test_legacy_skill_alias_maps_to_new_validation_module(self) -> None:
        directive = _extract_skill_directive("/skill ida_validation verify sink")

        self.assertEqual(directive.name, "validation")
        self.assertEqual(directive.prompt, "verify sink")
        self.assertIn("Validation Skill", directive.context_note)

    def test_focused_skill_command_loads_intel_report_module(self) -> None:
        directive = _extract_skill_directive("/skill intel_report match CVE")

        self.assertEqual(directive.name, "intel_report")
        self.assertEqual(directive.prompt, "match CVE")
        self.assertIn("Intel Report Skill", directive.context_note)

    def test_load_skill_accepts_router_aliases(self) -> None:
        self.assertIn("Vulnerability Discovery Skill Index", load_skill("vuln_discovery"))
        self.assertIn("Vulnerability Discovery Skill Index", load_skill("vuln-discovery"))
        self.assertIn("Discovery Skill", load_skill("discover"))

    def test_load_skill_accepts_intel_report_aliases(self) -> None:
        self.assertIn("Intel Report Skill", load_skill("intel"))
        self.assertIn("Intel Report Skill", load_skill("report"))
        self.assertIn("Intel Report Skill", load_skill("intel_dedup"))


if __name__ == "__main__":
    unittest.main()
