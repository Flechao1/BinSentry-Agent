"""Load bundled Markdown playbooks for LLM prompts."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path


SKILLS_DIR = Path(__file__).resolve().parent

_SKILL_ALIASES = {
    "default": "vuln_discovery",
    "vuln-discovery": "vuln_discovery",
    "vuln_discovery": "vuln_discovery",
    "discover": "discovery",
    "attack_surface": "discovery",
    "attack-surface": "discovery",
    "static-buckets": "discovery",
    "static_buckets": "discovery",
    "static": "discovery",
    "triage": "discovery",
    "validate": "validation",
    "ida_validation": "validation",
    "ida-validation": "validation",
    "dynamic": "validation",
    "dynamic_validation": "validation",
    "dynamic-validation": "validation",
    "intel": "intel_report",
    "report": "intel_report",
    "reporting": "intel_report",
    "intel-report": "intel_report",
    "intel_report": "intel_report",
    "intel_dedup": "intel_report",
    "intel-dedup": "intel_report",
    "firmware-web-audit": "firmware_web_audit",
    "firmware_web_audit": "firmware_web_audit",
}


def resolve_skill_name(name: str) -> str:
    """Normalize a user-provided skill name through the alias table.

    Raises ValueError when the resolved name is not a valid skill identifier.
    """
    skill_name = _SKILL_ALIASES.get(name.strip().lower(), name.strip().lower())
    if not re.fullmatch(r"[a-z0-9_]+", skill_name):
        raise ValueError("invalid skill name")
    return skill_name


def load_skill(name: str) -> str:
    skill_name = resolve_skill_name(name)
    resource = resources.files("vulnagent.skills")
    if skill_name == "vuln_discovery":
        skill_resource = resource.joinpath("SKILL.md")
        skill_path = (SKILLS_DIR / "SKILL.md").resolve()
    else:
        skill_resource = resource.joinpath(skill_name, "SKILL.md")
        skill_path = (SKILLS_DIR / skill_name / "SKILL.md").resolve()

    if skill_resource.is_file():
        return skill_resource.read_text(encoding="utf-8")

    try:
        skill_path.relative_to(SKILLS_DIR)
    except ValueError as exc:
        raise ValueError("invalid skill name")
    if not skill_path.is_file():
        raise FileNotFoundError(f"skill not found: {name}")
    return skill_path.read_text(encoding="utf-8")
