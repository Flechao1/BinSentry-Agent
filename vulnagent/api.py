"""FastAPI application API for the React VulnAgent frontend."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from pydantic import BaseModel, Field

from vulnagent.agent.baseline_scan import BaselineScanConfig
from vulnagent.agent.llm import get_llm_status
from vulnagent.clients.ida_client import IdaClient
from vulnagent.harness import (
    BinaryVulnAgentHarness,
    HarnessBaselineScanRequest,
    HarnessTurnRequest,
)
from vulnagent.reports import FileReportStore
from vulnagent.storage import SqliteVulnRepository


load_dotenv()


class AgentChatRequest(BaseModel):
    prompt: str
    thread_id: str = ""
    new_thread: bool = False


class BaselineScanRequest(BaseModel):
    thread_id: str = ""
    new_thread: bool = False
    config: BaselineScanConfig = Field(default_factory=BaselineScanConfig)


def create_app() -> FastAPI:
    app = FastAPI(title="VulnAgent Application API")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_origin_regex=_cors_origin_regex(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        repository = _repository()
        ida_status: dict[str, Any]
        try:
            client = _ida_client()
            backend = client.validate_protocol()
            arch = client.detect_arch()
            ida_status = {
                "connected": True,
                "database": backend.database,
                "writable": backend.writable,
                "protocol_version": backend.protocol_version,
                "architecture": arch.arch,
                "bits": arch.bits,
                "endian": arch.endian,
            }
        except Exception as exc:  # noqa: BLE001 - surface frontend-readable status
            ida_status = {
                "connected": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        return {
            "ida": ida_status,
            "llm": get_llm_status(),
            "storage": {
                "db_path": str(repository.db_path),
                "summary": repository.get_summary(),
            },
        }

    @app.get("/api/harness/runs")
    def list_harness_runs(limit: int = 20) -> list[dict[str, Any]]:
        return _repository().list_harness_runs(limit=limit)

    @app.get("/api/harness/runs/{run_id}")
    def get_harness_run(run_id: str) -> dict[str, Any]:
        run = _repository().get_harness_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="unknown harness run")
        return run

    @app.get("/api/reports")
    def list_reports(limit: int = 50) -> list[dict[str, Any]]:
        return _repository().list_scan_runs(limit=limit)

    @app.get("/api/reports/{report_id}")
    def get_report(report_id: str) -> dict[str, Any]:
        try:
            return _repository().load_report(report_id).model_dump(mode="json")
        except FileNotFoundError:
            try:
                return _report_store().load(report_id).model_dump(mode="json")
            except (FileNotFoundError, ValueError) as exc:
                raise HTTPException(status_code=404, detail="unknown report") from exc

    @app.get("/api/chats")
    def list_chats(limit: int = 50) -> list[dict[str, Any]]:
        return _repository().list_chat_threads(limit=limit)

    @app.get("/api/chats/{thread_id}/messages")
    def get_chat_messages(thread_id: str) -> dict[str, Any]:
        repository = _repository()
        thread = repository.get_chat_thread(thread_id)
        if thread is None:
            raise HTTPException(status_code=404, detail="unknown chat thread")
        return {
            "thread": thread,
            "messages": _serialize_chat_messages(repository.load_chat_messages(thread_id)),
        }

    @app.post("/api/chats")
    def create_chat() -> dict[str, str]:
        thread_id = _repository().create_chat_thread(title="Frontend investigation")
        return {"thread_id": thread_id}

    @app.post("/api/agent/chat")
    async def agent_chat(request: AgentChatRequest) -> dict[str, Any]:
        repository = _repository()
        thread_id = request.thread_id
        if request.new_thread or not thread_id:
            thread_id = repository.create_chat_thread(title="Frontend investigation")
        messages = repository.load_chat_messages(thread_id)
        result = await _harness(repository).run_agent_chat(
            HarnessTurnRequest(
                prompt=request.prompt,
                thread_id=thread_id,
                messages=messages,
                ida_backend_url=_backend_url(),
                report_dir=_report_dir(),
            )
        )
        payload = result.model_dump(mode="json", exclude={"messages", "report"})
        payload["messages"] = _serialize_chat_messages(result.messages)
        return payload

    @app.post("/api/baseline/scan")
    async def baseline_scan(request: BaselineScanRequest) -> dict[str, Any]:
        repository = _repository()
        thread_id = request.thread_id
        if request.new_thread or not thread_id:
            thread_id = repository.create_chat_thread(title="Frontend baseline scan")
        result = await _harness(repository).run_baseline_scan(
            HarnessBaselineScanRequest(
                thread_id=thread_id,
                ida_backend_url=_backend_url(),
                report_dir=_report_dir(),
                config=request.config,
            )
        )
        return result.model_dump(mode="json", exclude={"messages", "report"})

    @app.get("/api/functions/{ea}/context")
    def function_context(ea: str) -> dict[str, Any]:
        try:
            return _ida_client().get_function_context(ea).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    return app


def _cors_origins() -> list[str]:
    raw = os.getenv(
        "VULN_API_CORS_ORIGINS",
        (
            "http://127.0.0.1:5173,http://localhost:5173,"
            "http://127.0.0.1:5174,http://localhost:5174"
        ),
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _cors_origin_regex() -> str:
    return os.getenv(
        "VULN_API_CORS_ORIGIN_REGEX",
        r"http://(127\.0\.0\.1|localhost):\d+",
    )


def _repository() -> SqliteVulnRepository:
    return SqliteVulnRepository.from_env()


def _backend_url() -> str:
    return os.getenv("IDA_BACKEND_URL", "http://127.0.0.1:8765")


def _report_dir() -> str:
    return os.getenv("VULN_REPORT_DIR", "./reports")


def _timeout() -> float:
    return float(os.getenv("IDA_BACKEND_TIMEOUT", "120"))


def _ida_client() -> IdaClient:
    return IdaClient(_backend_url(), timeout=_timeout())


def _report_store() -> FileReportStore:
    return FileReportStore(_report_dir())


def _harness(repository: SqliteVulnRepository) -> BinaryVulnAgentHarness:
    return BinaryVulnAgentHarness(repository=repository, timeout=_timeout())


app = create_app()


def _serialize_chat_messages(messages: list[BaseMessage]) -> list[dict[str, Any]]:
    """Return frontend-friendly chat messages without leaking LangChain internals."""
    serialized: list[dict[str, Any]] = []
    for index, message in enumerate(messages):
        item: dict[str, Any] = {
            "id": str(getattr(message, "id", "") or index),
            "content": _message_content_text(message.content),
        }
        if isinstance(message, HumanMessage):
            item["role"] = "user"
        elif isinstance(message, AIMessage):
            item["role"] = "assistant"
            item["tool_calls"] = [
                {
                    "id": tool_call.get("id", ""),
                    "name": tool_call.get("name", "unknown"),
                    "args": tool_call.get("args", {}),
                }
                for tool_call in message.tool_calls
            ]
        elif isinstance(message, ToolMessage):
            item.update(
                {
                    "role": "tool",
                    "name": getattr(message, "name", "") or "IDA tool",
                    "tool_call_id": message.tool_call_id,
                }
            )
        else:
            item["role"] = getattr(message, "type", "message")
        serialized.append(item)
    return serialized


def _message_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)
