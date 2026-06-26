"""Bridge for registering VulnAgent in agent-service-toolkit."""

from __future__ import annotations

import os

import httpx
from langchain_core.runnables import RunnableConfig

from vulnagent.agent.langgraph_agent import build_binary_vulnerability_agent
from vulnagent.reports import FileReportStore
from vulnagent.reports.router import build_report_router


def build_toolkit_binary_vulnerability_agent():
    """Build an Agent using agent-service-toolkit's configured LLM providers."""
    from core import get_model, settings

    def model_factory(config: RunnableConfig):
        model_name = config.get("configurable", {}).get("model", settings.DEFAULT_MODEL)
        return get_model(model_name)

    include_write_tools = os.getenv("VULN_ENABLE_IDB_WRITES", "").lower() in {
        "1",
        "true",
        "yes",
    }
    return build_binary_vulnerability_agent(
        model_factory,
        include_write_tools=include_write_tools,
    )


def build_toolkit_vulnerability_router():
    """Expose report downloads and a frontend-friendly IDA backend status endpoint."""
    from fastapi import APIRouter

    report_dir = os.getenv("VULN_REPORT_DIR", "./reports")
    ida_backend_url = os.getenv("IDA_BACKEND_URL", "http://127.0.0.1:8765").rstrip("/")
    timeout = float(os.getenv("IDA_BACKEND_TIMEOUT", "120"))
    router = APIRouter()
    router.include_router(build_report_router(FileReportStore(report_dir)))

    @router.get("/vulnerability/status")
    async def vulnerability_status():
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                health_response = await client.get(f"{ida_backend_url}/health")
                health_response.raise_for_status()
                health = health_response.json()
                arch_response = await client.get(f"{ida_backend_url}/arch")
                arch_response.raise_for_status()
                arch = arch_response.json()
            return {
                "connected": True,
                "backend_url": ida_backend_url,
                "database": health.get("database", ""),
                "protocol_version": health.get("protocol_version", ""),
                "writable": health.get("writable", "false"),
                "architecture": arch.get("arch", "unknown"),
                "bits": arch.get("bits", 0),
                "endian": arch.get("endian", ""),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {
                "connected": False,
                "backend_url": ida_backend_url,
                "error": f"{type(exc).__name__}: {exc}",
            }

    return router
