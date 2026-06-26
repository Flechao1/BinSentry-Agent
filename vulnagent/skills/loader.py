"""Load bundled Markdown playbooks for LLM prompts."""

from __future__ import annotations

from pathlib import Path


SKILLS_DIR = Path(__file__).resolve().parent


def load_skill(name: str) -> str:
    skill_path = (SKILLS_DIR / name / "SKILL.md").resolve()
    if skill_path.parent.parent != SKILLS_DIR:
        raise ValueError("invalid skill name")
    return skill_path.read_text(encoding="utf-8")
