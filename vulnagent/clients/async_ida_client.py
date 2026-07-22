"""Async HTTP client for the standalone IDA backend."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from vulnagent.clients.ida_client import normalize_ea, raise_for_status_with_detail
from vulnagent.ida.schemas import (
    ArchInfo,
    ArgumentOriginResult,
    BatchDecompileEntry,
    CallChainResult,
    DecompileResponse,
    FunctionContext,
    FunctionEntry,
    HealthResponse,
    ImportEntry,
    IndirectCallScanResult,
    PatchBytesResponse,
    PatchConditionalJumpRequest,
    RenameFunctionResponse,
    RouteAnalysisResult,
    SaveDatabaseResponse,
    SetFunctionCommentResponse,
    SinkScanResult,
    SourceCandidate,
    SourcePropagateResult,
    SourceScanResult,
    XrefRecord,
)


class AsyncIdaClient:
    """Async counterpart to :class:`IdaClient` for Agent workflows."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    async def __aenter__(self) -> "AsyncIdaClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        response = await self._client.request(method, path, json=json_body)
        raise_for_status_with_detail(response)
        return response.json()

    async def _request_object(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = await self._request(method, path, json_body)
        if not isinstance(payload, dict):
            raise ValueError(f"IDA backend returned non-object JSON: {type(payload).__name__}")
        return payload

    async def _request_list(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> list[Any]:
        payload = await self._request(method, path, json_body)
        if not isinstance(payload, list):
            raise ValueError(f"IDA backend returned non-list JSON: {type(payload).__name__}")
        return payload

    async def health(self) -> HealthResponse:
        return HealthResponse.model_validate(await self._request_object("GET", "/health"))

    async def validate_protocol(self, expected_version: str = "1.0") -> HealthResponse:
        health = await self.health()
        if health.protocol_version != expected_version:
            raise ValueError(
                "IDA backend protocol mismatch: "
                f"expected {expected_version}, got {health.protocol_version}"
            )
        if health.status not in {"ok", "created"}:
            raise ValueError(f"IDA backend is not ready: {health.status}")
        if not health.database:
            raise ValueError("IDA backend has no active database")
        return health

    async def detect_arch(self) -> ArchInfo:
        return ArchInfo.model_validate(await self._request_object("GET", "/arch"))

    async def get_imports(self) -> list[ImportEntry]:
        payload = await self._request_list("GET", "/imports")
        return [ImportEntry.model_validate(item) for item in payload]

    async def list_functions(self, pattern: str = "", limit: int = 500) -> list[FunctionEntry]:
        from urllib.parse import quote

        parts = [f"limit={limit}"]
        if pattern:
            parts.append(f"pattern={quote(pattern, safe='*?')}")
        payload = await self._request_list("GET", f"/functions?{'&'.join(parts)}")
        return [FunctionEntry.model_validate(item) for item in payload]

    async def get_function_context(self, ea: int | str) -> FunctionContext:
        payload = await self._request_object("GET", f"/functions/{normalize_ea(ea)}/context")
        return FunctionContext.model_validate(payload)

    async def decompile_function(self, ea: int | str) -> DecompileResponse:
        payload = await self._request_object("GET", f"/functions/{normalize_ea(ea)}/decompile")
        return DecompileResponse.model_validate(payload)

    async def get_function_xrefs(self, ea: int | str) -> dict[str, list[XrefRecord]]:
        payload = await self._request_object("GET", f"/functions/{normalize_ea(ea)}/xrefs")
        return {
            "to": [XrefRecord.model_validate(item) for item in payload.get("to", [])],
            "from": [XrefRecord.model_validate(item) for item in payload.get("from", [])],
        }

    async def get_address_xrefs(self, ea: int | str) -> dict[str, list[XrefRecord]]:
        payload = await self._request_object("GET", f"/addresses/{normalize_ea(ea)}/xrefs")
        return {
            "to": [XrefRecord.model_validate(item) for item in payload.get("to", [])],
            "from": [XrefRecord.model_validate(item) for item in payload.get("from", [])],
        }

    async def scan_source_candidates(
        self,
        limit: int = 100,
        min_score: float = 25.0,
    ) -> SourceScanResult:
        payload = await self._request_object(
            "GET",
            f"/sources/scan?limit={limit}&min_score={min_score}",
        )
        return SourceScanResult.model_validate(payload)

    async def find_route_handlers(self) -> RouteAnalysisResult:
        return RouteAnalysisResult.model_validate(
            await self._request_object("GET", "/sources/routes")
        )

    async def scan_indirect_calls(
        self,
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> IndirectCallScanResult:
        return IndirectCallScanResult.model_validate(
            await self._request_object(
                "GET",
                f"/indirect-calls/scan?max_functions={max_functions}&max_results={max_results}",
            )
        )

    async def propagate_sources(
        self,
        sources: list[str],
        max_rounds: int = 5,
    ) -> SourcePropagateResult:
        payload = await self._request_object(
            "POST",
            "/sources/propagate",
            {"sources": sources, "max_rounds": max_rounds},
        )
        return SourcePropagateResult.model_validate(payload)

    async def analyze_as_source(self, ea: int | str) -> SourceCandidate:
        payload = await self._request_object(
            "GET",
            f"/functions/{normalize_ea(ea)}/analyze-as-source",
        )
        return SourceCandidate.model_validate(payload)

    async def scan_sink_calls(
        self,
        sink_specs: dict[str, list],
        roots: list[int | str] | None = None,
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> SinkScanResult:
        payload = await self._request_object(
            "POST",
            "/sink-calls/scan",
            {
                "sink_specs": sink_specs,
                "roots": [normalize_ea(root) for root in roots or []],
                "max_depth": max_depth,
                "max_functions": max_functions,
            },
        )
        return SinkScanResult.model_validate(payload)

    async def trace_call_chain(
        self,
        ea: int | str,
        arg_index: int = 1,
        sources: list[str] | None = None,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[CallChainResult]:
        payload = await self._request_list(
            "POST",
            f"/functions/{normalize_ea(ea)}/trace-chain",
            {
                "arg_index": arg_index,
                "sources": sources or [],
                "max_depth": max_depth,
                "max_chains": max_chains,
            },
        )
        return [CallChainResult.model_validate(item) for item in payload]

    async def trace_argument_origin(
        self,
        caller_ea: int | str,
        call_site: int | str,
        callee_ea: int | str,
        target_arg_idx: int = 1,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult:
        payload = await self._request_object(
            "POST",
            f"/functions/{normalize_ea(caller_ea)}/trace-arg-origin",
            {
                "call_site": normalize_ea(call_site),
                "callee_ea": normalize_ea(callee_ea),
                "target_arg_idx": target_arg_idx,
                "sources": sources or [],
            },
        )
        return ArgumentOriginResult.model_validate(payload)

    async def batch_decompile(self, addresses: list[int | str]) -> list[BatchDecompileEntry]:
        payload = await self._request_list(
            "POST",
            "/batch/decompile",
            {"addresses": [normalize_ea(address) for address in addresses]},
        )
        return [BatchDecompileEntry.model_validate(item) for item in payload]

    async def rename_function(
        self,
        ea: int | str,
        new_name: str,
        reason: str = "",
    ) -> RenameFunctionResponse:
        payload = await self._request_object(
            "POST",
            f"/functions/{normalize_ea(ea)}/rename",
            {"new_name": new_name, "reason": reason},
        )
        return RenameFunctionResponse.model_validate(payload)

    async def set_function_comment(
        self,
        ea: int | str,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> SetFunctionCommentResponse:
        payload = await self._request_object(
            "POST",
            f"/functions/{normalize_ea(ea)}/comment",
            {"comment": comment, "repeatable": repeatable, "reason": reason},
        )
        return SetFunctionCommentResponse.model_validate(payload)

    async def patch_bytes(
        self,
        ea: int | str,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        payload = await self._request_object(
            "POST",
            f"/bytes/{normalize_ea(ea)}/patch",
            {
                "patched_hex": patched_hex,
                "expected_original_hex": expected_original_hex,
                "reason": reason,
            },
        )
        return PatchBytesResponse.model_validate(payload)

    async def nop_bytes(
        self,
        ea: int | str,
        size: int,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        payload = await self._request_object(
            "POST",
            f"/bytes/{normalize_ea(ea)}/nop",
            {
                "size": size,
                "expected_original_hex": expected_original_hex,
                "reason": reason,
            },
        )
        return PatchBytesResponse.model_validate(payload)

    async def patch_conditional_jump(
        self,
        ea: int | str,
        mode: str = "invert",
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        request = PatchConditionalJumpRequest(
            mode=mode,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        payload = await self._request_object(
            "POST",
            f"/instructions/{normalize_ea(ea)}/patch-conditional-jump",
            request.model_dump(),
        )
        return PatchBytesResponse.model_validate(payload)

    async def save_database(self, output_path: str = "") -> SaveDatabaseResponse:
        payload = await self._request_object(
            "POST",
            "/database/save",
            {"output_path": output_path},
        )
        return SaveDatabaseResponse.model_validate(payload)
