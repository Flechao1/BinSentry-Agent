from __future__ import annotations

from typing import Any

import requests

from vulnagent.ida.schemas import (
    ArchInfo,
    ArgumentOriginResult,
    BatchDecompileEntry,
    CallChainResult,
    CallRecord,
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
    SinkCallResult,
    SourceCandidate,
    SourcePropagateResult,
    SourceScanResult,
    StringRecord,
    XrefRecord,
)


def normalize_ea(ea: int | str) -> str:
    if isinstance(ea, int):
        if ea < 0:
            raise ValueError("address must be non-negative")
        return hex(ea)

    value = str(ea).strip().lower()
    if not value:
        raise ValueError("address is required")
    if value.startswith("0x"):
        number = int(value, 16)
    else:
        number = int(value, 16)
    if number < 0:
        raise ValueError("address must be non-negative")
    return hex(number)


def raise_for_status_with_detail(response: Any) -> None:
    """Raise an actionable error while preserving the backend response detail."""
    try:
        response.raise_for_status()
    except Exception as exc:
        try:
            payload = response.json()
        except Exception:
            payload = {}
        detail = payload.get("detail") if isinstance(payload, dict) else ""
        if not detail:
            detail = str(getattr(response, "text", "") or exc)
        status_code = getattr(response, "status_code", "unknown")
        raise RuntimeError(
            f"IDA backend request failed ({status_code}): {detail}"
        ) from exc


class IdaClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 120.0,
        transport: Any | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport or requests

    def _request(self, method: str, path: str, json_body: dict[str, Any] | None = None) -> Any:
        response = self.transport.request(
            method,
            f"{self.base_url}{path}",
            json=json_body,
            timeout=self.timeout,
        )
        raise_for_status_with_detail(response)
        return response.json()

    def _request_object(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = self._request(method, path, json_body)
        if not isinstance(payload, dict):
            raise ValueError(f"IDA backend returned non-object JSON: {type(payload).__name__}")
        return payload

    def _request_list(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> list[Any]:
        payload = self._request(method, path, json_body)
        if not isinstance(payload, list):
            raise ValueError(f"IDA backend returned non-list JSON: {type(payload).__name__}")
        return payload

    def health(self) -> HealthResponse:
        payload = self._request_object("GET", "/health")
        return HealthResponse.model_validate(payload)

    def validate_protocol(self, expected_version: str = "1.0") -> HealthResponse:
        health = self.health()
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

    def get_function_context(self, ea: int | str) -> FunctionContext:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/functions/{address}/context")
        return FunctionContext.model_validate(payload)

    def decompile_function(self, ea: int | str) -> DecompileResponse:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/functions/{address}/decompile")
        return DecompileResponse.model_validate(payload)

    def get_function_xrefs(self, ea: int | str) -> dict[str, list[XrefRecord]]:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/functions/{address}/xrefs")
        return {
            "to": [XrefRecord.model_validate(record) for record in payload.get("to", [])],
            "from": [XrefRecord.model_validate(record) for record in payload.get("from", [])],
        }

    def get_address_xrefs(self, ea: int | str) -> dict[str, list[XrefRecord]]:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/addresses/{address}/xrefs")
        return {
            "to": [XrefRecord.model_validate(record) for record in payload.get("to", [])],
            "from": [XrefRecord.model_validate(record) for record in payload.get("from", [])],
        }

    def get_function_calls(self, ea: int | str) -> list[CallRecord]:
        address = normalize_ea(ea)
        payload = self._request_list("GET", f"/functions/{address}/calls")
        return [CallRecord.model_validate(record) for record in payload]

    def get_function_strings(self, ea: int | str) -> list[StringRecord]:
        address = normalize_ea(ea)
        payload = self._request_list("GET", f"/functions/{address}/strings")
        return [StringRecord.model_validate(record) for record in payload]

    def get_function_constants(self, ea: int | str) -> list[int]:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/functions/{address}/constants")
        return [int(value) for value in payload.get("constants", [])]

    def get_function_imports(self, ea: int | str) -> list[str]:
        address = normalize_ea(ea)
        payload = self._request_object("GET", f"/functions/{address}/imports")
        return [str(value) for value in payload.get("imports", [])]

    def list_functions(self, pattern: str = "", limit: int = 500) -> list[FunctionEntry]:
        from urllib.parse import quote

        parts = [f"limit={limit}"]
        if pattern:
            parts.append(f"pattern={quote(pattern, safe='*?')}")
        path = f"/functions?{'&'.join(parts)}"
        payload = self._request_list("GET", path)
        return [FunctionEntry.model_validate(item) for item in payload]

    def get_imports(self) -> list[ImportEntry]:
        payload = self._request_list("GET", "/imports")
        return [ImportEntry.model_validate(item) for item in payload]

    def detect_arch(self) -> ArchInfo:
        payload = self._request_object("GET", "/arch")
        return ArchInfo.model_validate(payload)

    def find_sink_calls(self, ea: int | str, sink_specs: dict) -> list[SinkCallResult]:
        address = normalize_ea(ea)
        payload = self._request_list("POST", f"/functions/{address}/sink-calls", {"sink_specs": sink_specs})
        return [SinkCallResult.model_validate(item) for item in payload]

    def scan_sink_calls(
        self,
        sink_specs: dict[str, list],
        roots: list[int | str] | None = None,
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> SinkScanResult:
        body = {
            "sink_specs": sink_specs,
            "roots": [normalize_ea(root) for root in roots or []],
            "max_depth": max_depth,
            "max_functions": max_functions,
        }
        payload = self._request_object("POST", "/sink-calls/scan", body)
        return SinkScanResult.model_validate(payload)

    def trace_call_chain(
        self,
        ea: int | str,
        arg_index: int = 1,
        sources: list[str] | None = None,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[CallChainResult]:
        address = normalize_ea(ea)
        body: dict[str, Any] = {"arg_index": arg_index, "max_depth": max_depth, "max_chains": max_chains}
        if sources is not None:
            body["sources"] = sources
        payload = self._request_list("POST", f"/functions/{address}/trace-chain", body)
        return [CallChainResult.model_validate(item) for item in payload]

    def trace_argument_origin(
        self,
        caller_ea: int | str,
        call_site: int | str,
        callee_ea: int | str,
        target_arg_idx: int = 1,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult:
        body: dict[str, Any] = {
            "call_site": normalize_ea(call_site),
            "callee_ea": normalize_ea(callee_ea),
            "target_arg_idx": target_arg_idx,
        }
        if sources is not None:
            body["sources"] = sources
        payload = self._request_object("POST", f"/functions/{normalize_ea(caller_ea)}/trace-arg-origin", body)
        return ArgumentOriginResult.model_validate(payload)

    def batch_decompile(self, addresses: list[int | str]) -> list[BatchDecompileEntry]:
        payload = self._request_list("POST", "/batch/decompile", {
            "addresses": [normalize_ea(a) for a in addresses]
        })
        return [BatchDecompileEntry.model_validate(item) for item in payload]

    def scan_source_candidates(self, limit: int = 100, min_score: float = 25.0) -> SourceScanResult:
        path = f"/sources/scan?limit={limit}&min_score={min_score}"
        payload = self._request_object("GET", path)
        return SourceScanResult.model_validate(payload)

    def find_route_handlers(self) -> RouteAnalysisResult:
        payload = self._request_object("GET", "/sources/routes")
        return RouteAnalysisResult.model_validate(payload)

    def scan_indirect_calls(
        self,
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> IndirectCallScanResult:
        payload = self._request_object(
            "GET",
            f"/indirect-calls/scan?max_functions={max_functions}&max_results={max_results}",
        )
        return IndirectCallScanResult.model_validate(payload)

    def propagate_sources(self, sources: list[str], max_rounds: int = 5) -> SourcePropagateResult:
        payload = self._request_object("POST", "/sources/propagate", {
            "sources": sources,
            "max_rounds": max_rounds,
        })
        return SourcePropagateResult.model_validate(payload)

    def analyze_as_source(self, ea: int | str) -> SourceCandidate:
        payload = self._request_object("GET", f"/functions/{normalize_ea(ea)}/analyze-as-source")
        return SourceCandidate.model_validate(payload)

    def rename_function(
        self,
        ea: int | str,
        new_name: str,
        reason: str = "",
    ) -> RenameFunctionResponse:
        address = normalize_ea(ea)
        payload = self._request_object(
            "POST",
            f"/functions/{address}/rename",
            {"new_name": new_name, "reason": reason},
        )
        return RenameFunctionResponse.model_validate(payload)

    def set_function_comment(
        self,
        ea: int | str,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> SetFunctionCommentResponse:
        payload = self._request_object(
            "POST",
            f"/functions/{normalize_ea(ea)}/comment",
            {"comment": comment, "repeatable": repeatable, "reason": reason},
        )
        return SetFunctionCommentResponse.model_validate(payload)

    def patch_bytes(
        self,
        ea: int | str,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        payload = self._request_object(
            "POST",
            f"/bytes/{normalize_ea(ea)}/patch",
            {
                "patched_hex": patched_hex,
                "expected_original_hex": expected_original_hex,
                "reason": reason,
            },
        )
        return PatchBytesResponse.model_validate(payload)

    def nop_bytes(
        self,
        ea: int | str,
        size: int,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        payload = self._request_object(
            "POST",
            f"/bytes/{normalize_ea(ea)}/nop",
            {
                "size": size,
                "expected_original_hex": expected_original_hex,
                "reason": reason,
            },
        )
        return PatchBytesResponse.model_validate(payload)

    def patch_conditional_jump(
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
        payload = self._request_object(
            "POST",
            f"/instructions/{normalize_ea(ea)}/patch-conditional-jump",
            request.model_dump(),
        )
        return PatchBytesResponse.model_validate(payload)

    def save_database(self, output_path: str = "") -> SaveDatabaseResponse:
        payload = self._request_object("POST", "/database/save", {"output_path": output_path})
        return SaveDatabaseResponse.model_validate(payload)

    def close_database(self, save: bool = False) -> bool:
        payload = self._request_object("POST", "/database/close", {"save": save})
        return bool(payload.get("ok"))
