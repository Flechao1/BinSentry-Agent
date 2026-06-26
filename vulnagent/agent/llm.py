"""Standalone LLM configuration for the VulnAgent chat Agent."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from pydantic import SecretStr


load_dotenv()


def _configured_secret(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value or value in {"sk-your-key-here", "your-api-key"}:
        return ""
    return value


@dataclass(frozen=True)
class LlmSettings:
    provider: str
    api_key: str
    base_url: str | None
    model: str
    temperature: float = 0.0
    max_tokens: int = 2400

    @classmethod
    def from_env(cls) -> "LlmSettings":
        deepseek_key = _configured_secret("DEEPSEEK_API_KEY")
        if deepseek_key:
            return cls(
                provider="DeepSeek",
                api_key=deepseek_key,
                base_url=os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com").strip(),
                model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip(),
                temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
                max_tokens=int(os.getenv("VULN_CONTEXT_RESPONSE_RESERVE_TOKENS", "2400")),
            )

        compatible_key = _configured_secret("OPENAI_API_KEY")
        if compatible_key:
            return cls(
                provider="OpenAI-compatible",
                api_key=compatible_key,
                base_url=(
                    os.getenv("BASE_URL", "").strip()
                    or os.getenv("OPENAI_BASE_URL", "").strip()
                    or None
                ),
                model=os.getenv("MODEL", "gpt-4o-mini").strip(),
                temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
                max_tokens=int(os.getenv("VULN_CONTEXT_RESPONSE_RESERVE_TOKENS", "2400")),
            )

        raise ValueError("Configure DEEPSEEK_API_KEY or OPENAI_API_KEY to enable the LLM Agent.")


def get_llm_status() -> dict[str, str | bool]:
    """Return frontend-safe model configuration without exposing credentials."""
    try:
        settings = LlmSettings.from_env()
    except ValueError as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "provider": settings.provider,
        "model": settings.model,
        "base_url": settings.base_url or "default",
    }


def build_chat_model(settings: LlmSettings | None = None):
    """Build a LangChain chat model for DeepSeek or another OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI

    resolved = settings or LlmSettings.from_env()
    return ChatOpenAI(
        model=resolved.model,
        api_key=SecretStr(resolved.api_key),
        base_url=resolved.base_url,
        temperature=resolved.temperature,
        max_tokens=resolved.max_tokens,
        streaming=False,
    )
