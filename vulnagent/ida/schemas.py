from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


IDA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_@$?]*$")
IDA_PROTOCOL_VERSION = "1.0"


class HealthResponse(BaseModel):
    status: str = "ok"
    backend: str
    database: str = ""
    protocol_version: str = IDA_PROTOCOL_VERSION
    writable: str = "false"


class OpenSessionRequest(BaseModel):
    idb_path: str = Field(..., min_length=1)
    session_id: str = ""
    writable: bool = True


class OpenSessionResponse(BaseModel):
    session_id: str
    idb_path: str
    database: str
    writable: bool


class RenameFunctionRequest(BaseModel):
    new_name: str = Field(..., min_length=1)
    reason: str = ""

    @field_validator("new_name")
    @classmethod
    def validate_new_name(cls, value: str) -> str:
        if not IDA_IDENTIFIER_RE.match(value):
            raise ValueError("new_name must be a valid IDA identifier")
        return value


class RenameFunctionResponse(BaseModel):
    ea: str
    old_name: str
    new_name: str
    ok: bool
    message: str = ""


class SetFunctionCommentRequest(BaseModel):
    comment: str = Field(..., min_length=1, max_length=4000)
    repeatable: bool = False
    reason: str = ""


class SetFunctionCommentResponse(BaseModel):
    ea: str
    ok: bool
    old_comment: str = ""
    new_comment: str = ""
    message: str = ""


class PatchBytesRequest(BaseModel):
    patched_hex: str = Field(..., min_length=2, max_length=512)
    expected_original_hex: str = Field(default="", max_length=512)
    reason: str = ""

    @field_validator("patched_hex", "expected_original_hex")
    @classmethod
    def validate_hex(cls, value: str) -> str:
        text = value.strip().replace(" ", "").lower()
        if not text:
            return text
        if len(text) % 2:
            raise ValueError("hex string length must be even")
        try:
            bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError("value must be hexadecimal bytes") from exc
        return text


class PatchBytesResponse(BaseModel):
    ea: str
    size: int = 0
    original_hex: str = ""
    patched_hex: str = ""
    ok: bool
    message: str = ""


class NopBytesRequest(BaseModel):
    size: int = Field(..., ge=1, le=128)
    expected_original_hex: str = Field(default="", max_length=256)
    reason: str = ""

    @field_validator("expected_original_hex")
    @classmethod
    def validate_expected_hex(cls, value: str) -> str:
        return PatchBytesRequest(
            patched_hex="90",
            expected_original_hex=value,
        ).expected_original_hex


class PatchConditionalJumpRequest(BaseModel):
    mode: Literal["invert", "force_taken", "force_not_taken"] = "invert"
    expected_original_hex: str = Field(default="", max_length=32)
    reason: str = ""

    @field_validator("expected_original_hex")
    @classmethod
    def validate_expected_hex(cls, value: str) -> str:
        return PatchBytesRequest(
            patched_hex="90",
            expected_original_hex=value,
        ).expected_original_hex


class DecompileResponse(BaseModel):
    ea: str
    name: str = ""
    prototype: str = ""
    pseudocode: str = ""
    ok: bool = True
    error: str = ""


class XrefRecord(BaseModel):
    frm: str
    to: str
    type_name: str = ""
    is_code: bool = False


class CallRecord(BaseModel):
    call_ea: str
    target_ea: str = ""
    target_name: str = ""
    is_import: bool = False


class StringRecord(BaseModel):
    ref_ea: str
    string_ea: str
    value: str


class SaveDatabaseRequest(BaseModel):
    output_path: str = ""


class SaveDatabaseResponse(BaseModel):
    path: str
    ok: bool
    message: str = ""


class CloseDatabaseRequest(BaseModel):
    save: bool = False


class CloseDatabaseResponse(BaseModel):
    ok: bool
    message: str = ""


class FunctionContext(BaseModel):
    ea: str
    name: str
    start_ea: str = ""
    end_ea: str = ""
    size: int = 0
    prototype: str = ""
    pseudocode: str = ""
    decompile_ok: bool = True
    decompile_error: str = ""
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    xrefs_to: list[str] = Field(default_factory=list)
    xrefs_from: list[str] = Field(default_factory=list)
    xref_records_to: list[XrefRecord] = Field(default_factory=list)
    xref_records_from: list[XrefRecord] = Field(default_factory=list)
    call_records: list[CallRecord] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    string_records: list[StringRecord] = Field(default_factory=list)
    constants: list[int] = Field(default_factory=list)
    imports_used: list[str] = Field(default_factory=list)
    confidence_hints: list[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: str
    detail: str = ""


# ============================================================================
# Taint Analysis Schemas
# ============================================================================


class FunctionEntry(BaseModel):
    ea: str
    name: str
    size: int = 0


class ImportEntry(BaseModel):
    ea: str
    name: str
    module: str = ""
    prototype: str = ""


class ArchInfo(BaseModel):
    arch: str
    bits: int = 0
    endian: str = ""


class SinkCallResult(BaseModel):
    loc: str
    caller_addr: str
    caller_name: str
    sink_name: str
    callee_ea: str = ""
    category: str = "unknown"
    confidence: float = 0.5
    args: list[dict] = Field(default_factory=list)
    score: float = 0.0


class TaintNodeResult(BaseModel):
    func_addr: str
    func_name: str
    call_site: str = ""
    arg_index: int = 0
    taint_status: str = "unknown"
    taint_reason: str = ""
    source_func: str = ""
    source_param: int | None = None
    source_expr: str = ""
    decompiled_code: str = ""


class CallChainResult(BaseModel):
    chain: list[TaintNodeResult] = Field(default_factory=list)
    taint_verified: bool = False
    chain_str: str = ""


class ArgumentOriginResult(BaseModel):
    taint_status: str = "unknown"
    source_param: int | None = None
    source_expr: str = ""
    source_func: str = ""
    reason: str = ""
    next_arg_index: int = 0


class BatchDecompileEntry(BaseModel):
    ea: str
    name: str = ""
    pseudocode: str = ""
    ok: bool = True
    error: str = ""


# ============================================================================
# Request Schemas for Taint Analysis Endpoints
# ============================================================================


class FindSinkCallsRequest(BaseModel):
    sink_specs: dict[str, list] = Field(default_factory=dict)


class ScanSinkCallsRequest(BaseModel):
    sink_specs: dict[str, list] = Field(default_factory=dict)
    roots: list[str] = Field(default_factory=list)
    max_depth: int = Field(default=8, ge=0, le=64)
    max_functions: int = Field(default=500, ge=1, le=10000)


class SinkScanResult(BaseModel):
    scope: str
    roots: list[str] = Field(default_factory=list)
    scanned_functions: int = 0
    truncated: bool = False
    results: list[SinkCallResult] = Field(default_factory=list)


class TraceCallChainRequest(BaseModel):
    arg_index: int = 1
    sources: list[str] = Field(default_factory=list)
    max_depth: int = 20
    max_chains: int = 5


class TraceArgumentOriginRequest(BaseModel):
    call_site: str = ""
    callee_ea: str = ""
    target_arg_idx: int = 1
    sources: list[str] = Field(default_factory=list)


class BatchDecompileRequest(BaseModel):
    addresses: list[str] = Field(default_factory=list)


# ============================================================================
# Source Analysis Schemas
# ============================================================================


class SourceCandidate(BaseModel):
    ea: str
    name: str
    score: float = 0.0
    xref_count: int = 0
    string_ratio: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    sample_strings: list[str] = Field(default_factory=list)
    decompiled_code: str = ""


class SourceScanResult(BaseModel):
    total_functions: int = 0
    candidates_scanned: int = 0
    results: list[SourceCandidate] = Field(default_factory=list)


class RouteRegistration(BaseModel):
    registration_ea: str
    registration_name: str = ""
    route_name: str = ""
    handler_ea: str
    handler_name: str = ""


class CrossHandlerCallee(BaseModel):
    ea: str
    name: str
    handler_count: int = 0
    total_handlers: int = 0
    ratio: float = 0.0
    decompiled_code: str = ""


class RouteAnalysisResult(BaseModel):
    registrations: list[RouteRegistration] = Field(default_factory=list)
    handlers: list[str] = Field(default_factory=list)
    cross_handler_callees: list[CrossHandlerCallee] = Field(default_factory=list)


class IndirectCallCandidate(BaseModel):
    caller_ea: str
    caller_name: str = ""
    call_ea: str = ""
    expr: str = ""
    target_expr: str = ""
    kind: str = "indirect_call"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class IndirectCallScanResult(BaseModel):
    scanned_functions: int = 0
    failed_decompilations: int = 0
    truncated: bool = False
    results: list[IndirectCallCandidate] = Field(default_factory=list)


class SourcePropagateRequest(BaseModel):
    sources: list[str] = Field(default_factory=list)
    max_rounds: int = 5


class SourcePropagateResult(BaseModel):
    new_sources: list[str] = Field(default_factory=list)
    rounds: int = 0
