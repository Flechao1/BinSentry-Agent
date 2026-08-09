"""Standalone LLM configuration for the VulnAgent chat Agent."""

from __future__ import annotations

import os
from dataclasses import dataclass
from threading import Lock

from dotenv import load_dotenv
from pydantic import SecretStr


load_dotenv()

_runtime_settings: "LlmSettings | None" = None
_runtime_settings_lock = Lock()


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
                model=os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash").strip(),
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


def get_active_llm_settings() -> LlmSettings:
    """Return the process override when configured, otherwise load .env settings."""
    with _runtime_settings_lock:
        if _runtime_settings is not None:
            return _runtime_settings
    return LlmSettings.from_env()


def set_runtime_llm_settings(settings: LlmSettings) -> LlmSettings:
    global _runtime_settings
    with _runtime_settings_lock:
        _runtime_settings = settings
    return settings


def reset_runtime_llm_settings() -> None:
    global _runtime_settings
    with _runtime_settings_lock:
        _runtime_settings = None


def get_llm_status() -> dict[str, str | bool]:
    """Return frontend-safe model configuration without exposing credentials."""
    try:
        settings = get_active_llm_settings()
    except ValueError as exc:
        return {"configured": False, "error": str(exc)}
    return {
        "configured": True,
        "provider": settings.provider,
        "model": settings.model,
        "base_url": settings.base_url or "default",
        "temperature": settings.temperature,
        "max_tokens": settings.max_tokens,
        "api_key_configured": bool(settings.api_key),
    }


def build_chat_model(settings: LlmSettings | None = None, *, streaming: bool = False):
    """Build a LangChain chat model for DeepSeek or another OpenAI-compatible API."""
    from langchain_openai import ChatOpenAI

    resolved = settings or get_active_llm_settings()
    return ChatOpenAI(
        model=resolved.model,
        api_key=SecretStr(resolved.api_key),
        base_url=resolved.base_url,
        temperature=resolved.temperature,
        max_tokens=resolved.max_tokens,
        streaming=streaming,
    )
