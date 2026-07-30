"""FastAPI application API for the React VulnAgent frontend."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from pydantic import BaseModel, Field

from vulnagent.agent.baseline_scan import BaselineScanConfig
from vulnagent.agent.context_builder import ContextBuilder
from vulnagent.agent.llm import (
    LlmSettings,
    build_chat_model,
    get_active_llm_settings,
    get_llm_status,
    reset_runtime_llm_settings,
    set_runtime_llm_settings,
)
from vulnagent.clients.ida_client import IdaClient
from vulnagent.firmware.scanner import FirmwareFilesystemScanner, attach_ida_backend_commands
from vulnagent.harness import (
    BinaryVulnAgentHarness,
    HarnessBaselineScanRequest,
    HarnessTraceEvent,
    HarnessTurnRequest,
)
from vulnagent.ida.schemas import (
    CloseDatabaseRequest,
    ExportPatchedBinaryRequest,
    NopBytesRequest,
    OpenSessionRequest,
    PatchBytesRequest,
    PatchConditionalJumpRequest,
    RenameFunctionRequest,
    SaveDatabaseRequest,
    SetFunctionCommentRequest,
)
from vulnagent.intel import IntelQuery, VulnerabilityIntelService
from vulnagent.reports import FileReportStore
from vulnagent.storage import SqliteVulnRepository


load_dotenv()


_ACTIVE_CHAT_TASKS: dict[str, asyncio.Task[Any]] = {}


class AgentChatRequest(BaseModel):
    prompt: str
    thread_id: str = ""
    new_thread: bool = False


class AgentCancelRequest(BaseModel):
    thread_id: str = Field(..., min_length=1)


class ChatCreateRequest(BaseModel):
    title: str = Field(default="New investigation", min_length=1, max_length=72)


class ChatRenameRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=72)


class LlmConfigRequest(BaseModel):
    provider: Literal["DeepSeek", "OpenAI-compatible"] = "DeepSeek"
    model: str = Field(..., min_length=1, max_length=120)
    base_url: str = Field(default="", max_length=500)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2400, ge=256, le=128000)
    # Write-only: an empty value keeps the currently active key.
    api_key: str = Field(default="", max_length=500)


class BaselineScanRequest(BaseModel):
    thread_id: str = ""
    new_thread: bool = False
    config: BaselineScanConfig = Field(default_factory=BaselineScanConfig)


class FirmwareTriageRequest(BaseModel):
    root: str = Field(..., min_length=1)
    limit: int = Field(default=20, ge=1, le=100)
    ida_host: str = "127.0.0.1"
    ida_port: int = Field(default=8765, ge=1, le=65535)
    writable: bool = False


class VulnerabilityIntelRequest(BaseModel):
    vendor: str = ""
    product: str = ""
    firmware_version: str = ""
    component: str = ""
    vulnerability_type: str = ""
    route: str = ""
    sink: str = ""
    symbols: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    max_results: int = Field(default=10, ge=1, le=50)
    sources: list[Literal["cveorg", "nvd", "github"]] = Field(
        default_factory=lambda: ["cveorg", "nvd", "github"]
    )


class PatchBytesApiRequest(PatchBytesRequest):
    ea: str = Field(..., min_length=1)


class NopBytesApiRequest(NopBytesRequest):
    ea: str = Field(..., min_length=1)


class PatchConditionalJumpApiRequest(PatchConditionalJumpRequest):
    ea: str = Field(..., min_length=1)


class RenameFunctionApiRequest(RenameFunctionRequest):
    ea: str = Field(..., min_length=1)


class SetFunctionCommentApiRequest(SetFunctionCommentRequest):
    ea: str = Field(..., min_length=1)


class ExportPatchedBinaryApiRequest(ExportPatchedBinaryRequest):
    pass


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
            "patching": {
                "enabled": _writes_enabled(),
                "available": _writes_enabled() and _backend_writable(ida_status.get("writable")),
            },
            "storage": {
                "db_path": str(repository.db_path),
                "summary": repository.get_summary(),
            },
        }

    @app.get("/api/settings/llm")
    def get_llm_configuration() -> dict[str, Any]:
        return get_llm_status()

    @app.post("/api/settings/llm")
    def update_llm_configuration(request: LlmConfigRequest) -> dict[str, Any]:
        try:
            current = get_active_llm_settings()
        except ValueError:
            current = None
        api_key = request.api_key.strip() or (current.api_key if current else "")
        if not api_key:
            raise HTTPException(status_code=400, detail="API key is required for the active model")
        default_url = (
            "https://api.deepseek.com"
            if request.provider == "DeepSeek"
            else (current.base_url if current and current.base_url else "")
        )
        settings = LlmSettings(
            provider=request.provider,
            api_key=api_key,
            base_url=request.base_url.strip() or default_url or None,
            model=request.model.strip(),
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        set_runtime_llm_settings(settings)
        return get_llm_status()

    @app.post("/api/settings/llm/reset")
    def reset_llm_configuration() -> dict[str, Any]:
        reset_runtime_llm_settings()
        return get_llm_status()

    @app.post("/api/ida/open")
    def open_ida_database(request: OpenSessionRequest) -> dict[str, Any]:
        client = _ida_client()
        try:
            return client.open_database(
                request.idb_path,
                request.session_id,
                request.writable,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/ida/close")
    def close_ida_database(request: CloseDatabaseRequest) -> dict[str, Any]:
        client = _ida_client()
        try:
            return {"ok": client.close_database(save=request.save)}
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/ida/shutdown")
    def shutdown_ida_backend(request: CloseDatabaseRequest) -> dict[str, Any]:
        client = _ida_client()
        try:
            return {"ok": client.shutdown_backend(save=request.save)}
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

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
    def create_chat(request: ChatCreateRequest) -> dict[str, Any]:
        repository = _repository()
        thread_id = repository.create_chat_thread(title=request.title)
        return repository.get_chat_thread(thread_id) or {"id": thread_id, "title": request.title}

    @app.patch("/api/chats/{thread_id}")
    def rename_chat(thread_id: str, request: ChatRenameRequest) -> dict[str, Any]:
        thread = _repository().rename_chat_thread(thread_id, request.title)
        if thread is None:
            raise HTTPException(status_code=404, detail="unknown chat thread")
        return thread

    @app.post("/api/chats/{thread_id}/clear")
    def clear_chat(thread_id: str) -> dict[str, Any]:
        repository = _repository()
        if repository.get_chat_thread(thread_id) is None:
            raise HTTPException(status_code=404, detail="unknown chat thread")
        repository.clear_chat_thread(thread_id)
        return repository.get_chat_thread(thread_id) or {"id": thread_id}

    @app.delete("/api/chats/{thread_id}")
    def delete_chat(thread_id: str) -> dict[str, bool]:
        if not _repository().delete_chat_thread(thread_id):
            raise HTTPException(status_code=404, detail="unknown chat thread")
        return {"deleted": True}

    @app.post("/api/agent/chat")
    async def agent_chat(request: AgentChatRequest) -> dict[str, Any]:
        repository = _repository()
        thread_id = request.thread_id
        if request.new_thread or not thread_id:
            thread_id = repository.create_chat_thread(title="Frontend investigation")
        if _active_chat_task(thread_id) is not None:
            raise HTTPException(status_code=409, detail="An agent request is already running for this thread")
        messages = repository.load_chat_messages(thread_id)
        if _is_context_press_command(request.prompt):
            return _compress_chat_context(repository, thread_id, messages, request.prompt)
        task = asyncio.create_task(
            _harness(repository).run_agent_chat(
                HarnessTurnRequest(
                    prompt=request.prompt,
                    thread_id=thread_id,
                    messages=messages,
                    ida_backend_url=_backend_url(),
                    report_dir=_report_dir(),
                )
            )
        )
        _ACTIVE_CHAT_TASKS[thread_id] = task
        task.add_done_callback(
            lambda completed, active_thread_id=thread_id: _forget_chat_task(active_thread_id, completed)
        )
        try:
            result = await asyncio.shield(task)
            payload = result.model_dump(mode="json", exclude={"messages", "report"})
            payload["messages"] = _serialize_chat_messages(result.messages)
            return payload
        finally:
            if task.done() and _ACTIVE_CHAT_TASKS.get(thread_id) is task:
                _ACTIVE_CHAT_TASKS.pop(thread_id, None)

    @app.post("/api/agent/chat/cancel")
    async def cancel_agent_chat(request: AgentCancelRequest) -> dict[str, Any]:
        task = _active_chat_task(request.thread_id)
        if task is None:
            return {"canceled": False, "detail": "No active agent request for this thread"}
        task.cancel()
        if _ACTIVE_CHAT_TASKS.get(request.thread_id) is task:
            _ACTIVE_CHAT_TASKS.pop(request.thread_id, None)
        try:
            result = await asyncio.wait_for(asyncio.shield(task), timeout=5)
        except asyncio.TimeoutError:
            return {"canceled": True, "detail": "Cancellation requested; the task is still unwinding"}
        except asyncio.CancelledError:
            return {"canceled": True, "detail": "Cancellation requested"}
        finally:
            if task.done() and _ACTIVE_CHAT_TASKS.get(request.thread_id) is task:
                _ACTIVE_CHAT_TASKS.pop(request.thread_id, None)
        return {
            "canceled": result.status == "canceled",
            "run_id": result.run_id,
            "status": result.status,
            "thread_id": result.thread_id,
        }

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

    @app.post("/api/firmware/triage")
    def firmware_triage(request: FirmwareTriageRequest) -> dict[str, Any]:
        try:
            report = FirmwareFilesystemScanner(request.root).scan(limit=request.limit)
            attach_ida_backend_commands(
                report,
                host=request.ida_host,
                port=request.ida_port,
                read_only=not request.writable,
            )
            return report.to_dict()
        except Exception as exc:  # noqa: BLE001 - expose frontend-readable detail
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/intel/search")
    def search_vulnerability_intel(request: VulnerabilityIntelRequest) -> dict[str, Any]:
        try:
            query = IntelQuery(
                vendor=request.vendor,
                product=request.product,
                firmware_version=request.firmware_version,
                component=request.component,
                vulnerability_type=request.vulnerability_type,
                route=request.route,
                sink=request.sink,
                symbols=request.symbols,
                keywords=request.keywords,
                max_results=request.max_results,
            )
            return VulnerabilityIntelService().search(query, sources=request.sources).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - expose frontend-readable detail
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/bytes")
    def patch_bytes(request: PatchBytesApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.patch_bytes(
                request.ea,
                request.patched_hex,
                request.expected_original_hex,
                request.reason,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/nop")
    def nop_bytes(request: NopBytesApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.nop_bytes(
                request.ea,
                request.size,
                request.expected_original_hex,
                request.reason,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/conditional-jump")
    def patch_conditional_jump(request: PatchConditionalJumpApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.patch_conditional_jump(
                request.ea,
                request.mode,
                request.expected_original_hex,
                request.reason,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/rename-function")
    def rename_function_for_patch(request: RenameFunctionApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.rename_function(
                request.ea,
                request.new_name,
                request.reason,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/comment-function")
    def set_function_comment_for_patch(request: SetFunctionCommentApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.set_function_comment(
                request.ea,
                request.comment,
                request.repeatable,
                request.reason,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/save-database")
    def save_patched_database(request: SaveDatabaseRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.save_database(request.output_path).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

    @app.post("/api/patch/export-binary")
    def export_patched_binary(request: ExportPatchedBinaryApiRequest) -> dict[str, Any]:
        client = _writable_ida_client()
        try:
            return client.export_patched_binary(
                request.output_path,
                request.overwrite,
                request.source_path,
            ).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
            raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc

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


def _writes_enabled() -> bool:
    return os.getenv("VULN_ENABLE_IDB_WRITES", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _backend_writable(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _writable_ida_client() -> IdaClient:
    if not _writes_enabled():
        raise HTTPException(
            status_code=403,
            detail="IDB writes are disabled. Set VULN_ENABLE_IDB_WRITES=true and restart the API.",
        )
    client = _ida_client()
    try:
        backend = client.validate_protocol()
    except Exception as exc:  # noqa: BLE001 - show backend detail in frontend
        raise HTTPException(status_code=400, detail=f"{type(exc).__name__}: {exc}") from exc
    if not _backend_writable(backend.writable):
        raise HTTPException(
            status_code=400,
            detail="IDA backend is read-only. Restart it without --read-only before patching.",
        )
    return client


def _report_store() -> FileReportStore:
    return FileReportStore(_report_dir())


def _harness(repository: SqliteVulnRepository) -> BinaryVulnAgentHarness:
    return BinaryVulnAgentHarness(repository=repository, timeout=_timeout())


def _active_chat_task(thread_id: str) -> asyncio.Task[Any] | None:
    task = _ACTIVE_CHAT_TASKS.get(thread_id)
    if task is not None and task.done():
        _ACTIVE_CHAT_TASKS.pop(thread_id, None)
        return None
    return task


def _forget_chat_task(thread_id: str, task: asyncio.Task[Any]) -> None:
    if _ACTIVE_CHAT_TASKS.get(thread_id) is task:
        _ACTIVE_CHAT_TASKS.pop(thread_id, None)


app = create_app()


def _is_context_press_command(prompt: str) -> bool:
    normalized = " ".join(prompt.strip().lower().split())
    return normalized in {
        "/context",
        "/context press",
        "/context compress",
        "/context compact",
    }


def _compress_chat_context(
    repository: SqliteVulnRepository,
    thread_id: str,
    messages: list[BaseMessage],
    prompt: str,
) -> dict[str, Any]:
    keep_recent_turns = int(os.getenv("VULN_CONTEXT_PRESS_KEEP_RECENT_TURNS", "2"))
    builder = ContextBuilder(
        repository,
        summary_llm_factory=lambda: build_chat_model(get_active_llm_settings()),
    )
    compressed = builder.compress(
        thread_id,
        messages,
        keep_recent_turns=keep_recent_turns,
    )
    answer = (
        "Context compression completed.\n\n"
        f"- Original messages: {compressed.original_message_count}\n"
        f"- Summarized older messages: {compressed.summarized_message_count}\n"
        f"- Retained recent messages: {compressed.retained_message_count}\n"
        f"- Summary size: {compressed.summary_chars} chars\n\n"
        "Future turns will use the compressed summary plus the retained recent messages."
    )
    updated_messages = [
        *compressed.messages,
        HumanMessage(content=prompt),
        AIMessage(content=answer),
    ]
    repository.save_chat_messages(thread_id, updated_messages)

    run_id = uuid4().hex
    started_at = datetime.now(timezone.utc)
    finished_at = datetime.now(timezone.utc)
    trace_events = [
        HarnessTraceEvent(
            run_id=run_id,
            event_type="run_started",
            message="Context compression started",
            data={"thread_id": thread_id},
            created_at=started_at,
        ),
        HarnessTraceEvent(
            run_id=run_id,
            event_type="run_completed",
            message="Context compression completed",
            data={
                "original_message_count": compressed.original_message_count,
                "summarized_message_count": compressed.summarized_message_count,
                "retained_message_count": compressed.retained_message_count,
                "summary_chars": compressed.summary_chars,
            },
            created_at=finished_at,
        ),
    ]
    repository.persist_harness_run(
        run_id=run_id,
        mode="context_compression",
        status="completed",
        thread_id=thread_id,
        answer=answer,
        error="",
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
        trace_events=trace_events,
        metadata={
            "original_message_count": compressed.original_message_count,
            "summarized_message_count": compressed.summarized_message_count,
            "retained_message_count": compressed.retained_message_count,
            "summary_chars": compressed.summary_chars,
        },
    )
    return {
        "run_id": run_id,
        "status": "completed",
        "thread_id": thread_id,
        "answer": answer,
        "error": "",
        "messages": _serialize_chat_messages(updated_messages),
    }


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
                    "status": str(getattr(message, "status", "success") or "success"),
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
