from __future__ import annotations

from abc import ABC, abstractmethod

from vulnagent.ida.schemas import (
    ArchInfo,
    ArgumentOriginResult,
    BatchDecompileEntry,
    CallChainResult,
    CallRecord,
    DecompileResponse,
    FunctionContext,
    FunctionEntry,
    ImportEntry,
    IndirectCallScanResult,
    RenameFunctionResponse,
    NopBytesRequest,
    PatchBytesResponse,
    PatchConditionalJumpRequest,
    RouteAnalysisResult,
    SaveDatabaseResponse,
    SinkScanResult,
    SinkCallResult,
    SourceCandidate,
    SourcePropagateResult,
    SourceScanResult,
    SetFunctionCommentResponse,
    StringRecord,
    XrefRecord,
)
from vulnagent.ida.schemas import IDA_PROTOCOL_VERSION


class IdaBackendError(RuntimeError):
    """Base error for IDA backend failures."""


class IdaBackendUnavailable(IdaBackendError):
    """Raised when an IDA backend operation is requested without IDA runtime."""


def parse_address(value: int | str) -> int:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("address must be non-negative")
        return value

    text = str(value).strip().lower()
    if not text:
        raise ValueError("address is required")
    if text.startswith("0x"):
        text = text[2:]
    try:
        number = int(text, 16)
    except ValueError as exc:
        raise ValueError(f"invalid hex address: {value}") from exc
    if number < 0:
        raise ValueError("address must be non-negative")
    return number


def format_address(ea: int) -> str:
    return hex(parse_address(ea))


class IdaBackend(ABC):
    @abstractmethod
    def health(self) -> dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def get_function_context(self, ea: int) -> FunctionContext:
        raise NotImplementedError

    @abstractmethod
    def decompile_function(self, ea: int) -> DecompileResponse:
        raise NotImplementedError

    @abstractmethod
    def get_function_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        raise NotImplementedError

    @abstractmethod
    def get_address_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        """Return xrefs for any code or data address, not only function starts."""
        raise NotImplementedError

    @abstractmethod
    def get_function_calls(self, ea: int) -> list[CallRecord]:
        raise NotImplementedError

    @abstractmethod
    def get_function_strings(self, ea: int) -> list[StringRecord]:
        raise NotImplementedError

    @abstractmethod
    def get_function_constants(self, ea: int) -> list[int]:
        raise NotImplementedError

    @abstractmethod
    def get_function_imports(self, ea: int) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def rename_function(self, ea: int, new_name: str, reason: str = "") -> RenameFunctionResponse:
        raise NotImplementedError

    @abstractmethod
    def set_function_comment(
        self,
        ea: int,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> SetFunctionCommentResponse:
        raise NotImplementedError

    @abstractmethod
    def patch_bytes(
        self,
        ea: int,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        raise NotImplementedError

    @abstractmethod
    def nop_bytes(
        self,
        ea: int,
        request: NopBytesRequest,
    ) -> PatchBytesResponse:
        raise NotImplementedError

    @abstractmethod
    def patch_conditional_jump(
        self,
        ea: int,
        request: PatchConditionalJumpRequest,
    ) -> PatchBytesResponse:
        raise NotImplementedError

    @abstractmethod
    def save_database(self, output_path: str | None = None) -> SaveDatabaseResponse:
        raise NotImplementedError

    @abstractmethod
    def close_database(self, save: bool = False) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_functions(self, pattern: str = "", limit: int = 500) -> list[FunctionEntry]:
        raise NotImplementedError

    @abstractmethod
    def get_imports(self) -> list[ImportEntry]:
        raise NotImplementedError

    @abstractmethod
    def detect_arch(self) -> ArchInfo:
        raise NotImplementedError

    @abstractmethod
    def find_sink_calls(self, ea: int, sink_specs: dict[str, list]) -> list[SinkCallResult]:
        raise NotImplementedError

    @abstractmethod
    def scan_sink_calls(
        self,
        sink_specs: dict[str, list],
        roots: list[int] | None = None,
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> SinkScanResult:
        raise NotImplementedError

    @abstractmethod
    def trace_call_chain(
        self,
        ea: int,
        arg_index: int,
        sources: list[str] | None = None,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[CallChainResult]:
        raise NotImplementedError

    @abstractmethod
    def trace_argument_origin(
        self,
        caller_ea: int,
        call_site: int,
        callee_ea: int,
        target_arg_idx: int,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult:
        raise NotImplementedError

    @abstractmethod
    def batch_decompile(self, addresses: list[int]) -> list[BatchDecompileEntry]:
        raise NotImplementedError

    @abstractmethod
    def scan_source_candidates(self, limit: int = 100, min_score: float = 25.0) -> SourceScanResult:
        raise NotImplementedError

    @abstractmethod
    def find_route_handlers(self) -> RouteAnalysisResult:
        raise NotImplementedError

    @abstractmethod
    def propagate_sources(self, sources: list[str], max_rounds: int = 5) -> SourcePropagateResult:
        raise NotImplementedError

    @abstractmethod
    def analyze_as_source(self, ea: int) -> SourceCandidate:
        raise NotImplementedError

    @abstractmethod
    def scan_indirect_calls(
        self,
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> IndirectCallScanResult:
        raise NotImplementedError


class UnavailableIdaBackend(IdaBackend):
    def __init__(self, reason: str = "IDA backend is not configured") -> None:
        self.reason = reason

    def health(self) -> dict[str, str]:
        return {
            "status": "unavailable",
            "backend": "none",
            "database": "",
            "protocol_version": IDA_PROTOCOL_VERSION,
            "writable": "false",
            "reason": self.reason,
        }

    def get_function_context(self, ea: int) -> FunctionContext:
        raise IdaBackendUnavailable(self.reason)

    def decompile_function(self, ea: int) -> DecompileResponse:
        raise IdaBackendUnavailable(self.reason)

    def get_function_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        raise IdaBackendUnavailable(self.reason)

    def get_address_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        raise IdaBackendUnavailable(self.reason)

    def get_function_calls(self, ea: int) -> list[CallRecord]:
        raise IdaBackendUnavailable(self.reason)

    def get_function_strings(self, ea: int) -> list[StringRecord]:
        raise IdaBackendUnavailable(self.reason)

    def get_function_constants(self, ea: int) -> list[int]:
        raise IdaBackendUnavailable(self.reason)

    def get_function_imports(self, ea: int) -> list[str]:
        raise IdaBackendUnavailable(self.reason)

    def rename_function(self, ea: int, new_name: str, reason: str = "") -> RenameFunctionResponse:
        raise IdaBackendUnavailable(self.reason)

    def set_function_comment(
        self,
        ea: int,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> SetFunctionCommentResponse:
        raise IdaBackendUnavailable(self.reason)

    def patch_bytes(
        self,
        ea: int,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        raise IdaBackendUnavailable(self.reason)

    def nop_bytes(
        self,
        ea: int,
        request: NopBytesRequest,
    ) -> PatchBytesResponse:
        raise IdaBackendUnavailable(self.reason)

    def patch_conditional_jump(
        self,
        ea: int,
        request: PatchConditionalJumpRequest,
    ) -> PatchBytesResponse:
        raise IdaBackendUnavailable(self.reason)

    def save_database(self, output_path: str | None = None) -> SaveDatabaseResponse:
        raise IdaBackendUnavailable(self.reason)

    def close_database(self, save: bool = False) -> None:
        return None

    def list_functions(self, pattern: str = "", limit: int = 500) -> list[FunctionEntry]:
        raise IdaBackendUnavailable(self.reason)

    def get_imports(self) -> list[ImportEntry]:
        raise IdaBackendUnavailable(self.reason)

    def detect_arch(self) -> ArchInfo:
        raise IdaBackendUnavailable(self.reason)

    def find_sink_calls(self, ea: int, sink_specs: dict[str, list]) -> list[SinkCallResult]:
        raise IdaBackendUnavailable(self.reason)

    def scan_sink_calls(
        self,
        sink_specs: dict[str, list],
        roots: list[int] | None = None,
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> SinkScanResult:
        raise IdaBackendUnavailable(self.reason)

    def trace_call_chain(
        self,
        ea: int,
        arg_index: int,
        sources: list[str] | None = None,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[CallChainResult]:
        raise IdaBackendUnavailable(self.reason)

    def trace_argument_origin(
        self,
        caller_ea: int,
        call_site: int,
        callee_ea: int,
        target_arg_idx: int,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult:
        raise IdaBackendUnavailable(self.reason)

    def batch_decompile(self, addresses: list[int]) -> list[BatchDecompileEntry]:
        raise IdaBackendUnavailable(self.reason)

    def scan_source_candidates(self, limit: int = 100, min_score: float = 25.0) -> SourceScanResult:
        raise IdaBackendUnavailable(self.reason)

    def find_route_handlers(self) -> RouteAnalysisResult:
        raise IdaBackendUnavailable(self.reason)

    def propagate_sources(self, sources: list[str], max_rounds: int = 5) -> SourcePropagateResult:
        raise IdaBackendUnavailable(self.reason)

    def analyze_as_source(self, ea: int) -> SourceCandidate:
        raise IdaBackendUnavailable(self.reason)

    def scan_indirect_calls(
        self,
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> IndirectCallScanResult:
        raise IdaBackendUnavailable(self.reason)
