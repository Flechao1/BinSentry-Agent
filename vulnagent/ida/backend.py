from __future__ import annotations

from typing import Any

from vulnagent.ida.core import IdaBackend, IdaBackendError, UnavailableIdaBackend, parse_address
from vulnagent.ida.schemas import (
    BatchDecompileRequest,
    CloseDatabaseRequest,
    FindSinkCallsRequest,
    NopBytesRequest,
    PatchBytesRequest,
    PatchConditionalJumpRequest,
    RenameFunctionRequest,
    SaveDatabaseRequest,
    ScanSinkCallsRequest,
    SetFunctionCommentRequest,
    SourcePropagateRequest,
    TraceArgumentOriginRequest,
    TraceCallChainRequest,
)


class SimpleState:
    pass


class SimpleApp:
    """Small fallback used when FastAPI is not installed.

    It keeps imports and unit tests working in ordinary Python environments.
    Real HTTP serving requires installing FastAPI and Uvicorn.
    """

    def __init__(self, title: str) -> None:
        self.title = title
        self.state = SimpleState()

    def get(self, path: str) -> Any:
        def decorator(func: Any) -> Any:
            return func

        return decorator

    def post(self, path: str) -> Any:
        def decorator(func: Any) -> Any:
            return func

        return decorator


def _new_app(title: str) -> Any:
    try:
        from fastapi import FastAPI  # type: ignore
    except ImportError:
        return SimpleApp(title=title)
    return FastAPI(title=title)


def _api_error(exc: Exception) -> None:
    try:
        from fastapi import HTTPException  # type: ignore
    except ImportError:
        raise exc

    status_code = 503 if isinstance(exc, IdaBackendError) else 400
    raise HTTPException(status_code=status_code, detail=f"{type(exc).__name__}: {exc}") from exc


def create_app(backend: IdaBackend | None = None) -> Any:
    app = _new_app(title="VulnAgent IDA Backend")
    app.state.backend = backend or UnavailableIdaBackend()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return app.state.backend.health()

    @app.get("/functions/{ea}/context")
    async def get_function_context(ea: str) -> dict[str, Any]:
        try:
            context = app.state.backend.get_function_context(parse_address(ea))
            return context.model_dump()
        except Exception as exc:  # noqa: BLE001 - convert backend errors to HTTP errors
            _api_error(exc)

    @app.get("/functions/{ea}/decompile")
    async def decompile_function(ea: str) -> dict[str, Any]:
        try:
            result = app.state.backend.decompile_function(parse_address(ea))
            return result.model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/xrefs")
    async def get_function_xrefs(ea: str) -> dict[str, Any]:
        try:
            result = app.state.backend.get_function_xrefs(parse_address(ea))
            return {
                "to": [record.model_dump() for record in result["to"]],
                "from": [record.model_dump() for record in result["from"]],
            }
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/addresses/{ea}/xrefs")
    async def get_address_xrefs(ea: str) -> dict[str, Any]:
        try:
            result = app.state.backend.get_address_xrefs(parse_address(ea))
            return {
                "to": [record.model_dump() for record in result["to"]],
                "from": [record.model_dump() for record in result["from"]],
            }
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/calls")
    async def get_function_calls(ea: str) -> list[dict[str, Any]]:
        try:
            return [
                record.model_dump()
                for record in app.state.backend.get_function_calls(parse_address(ea))
            ]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/strings")
    async def get_function_strings(ea: str) -> list[dict[str, Any]]:
        try:
            return [
                record.model_dump()
                for record in app.state.backend.get_function_strings(parse_address(ea))
            ]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/constants")
    async def get_function_constants(ea: str) -> dict[str, list[int]]:
        try:
            return {"constants": app.state.backend.get_function_constants(parse_address(ea))}
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/imports")
    async def get_function_imports(ea: str) -> dict[str, list[str]]:
        try:
            return {"imports": app.state.backend.get_function_imports(parse_address(ea))}
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions")
    async def list_functions(pattern: str = "", limit: int = 500) -> list[dict[str, Any]]:
        try:
            return [f.model_dump() for f in app.state.backend.list_functions(pattern, limit)]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/imports")
    async def get_imports() -> list[dict[str, Any]]:
        try:
            return [i.model_dump() for i in app.state.backend.get_imports()]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/arch")
    async def detect_arch() -> dict[str, Any]:
        try:
            return app.state.backend.detect_arch().model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/functions/{ea}/sink-calls")
    async def find_sink_calls(ea: str, request: FindSinkCallsRequest) -> list[dict[str, Any]]:
        try:
            return [r.model_dump() for r in app.state.backend.find_sink_calls(
                parse_address(ea), request.sink_specs
            )]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/sink-calls/scan")
    async def scan_sink_calls(request: ScanSinkCallsRequest) -> dict[str, Any]:
        try:
            roots = [parse_address(root) for root in request.roots]
            return app.state.backend.scan_sink_calls(
                request.sink_specs,
                roots=roots or None,
                max_depth=request.max_depth,
                max_functions=request.max_functions,
            ).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/functions/{ea}/trace-chain")
    async def trace_call_chain(ea: str, request: TraceCallChainRequest) -> list[dict[str, Any]]:
        try:
            return [r.model_dump() for r in app.state.backend.trace_call_chain(
                parse_address(ea),
                request.arg_index,
                sources=request.sources if request.sources else None,
                max_depth=request.max_depth,
                max_chains=request.max_chains,
            )]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/functions/{ea}/trace-arg-origin")
    async def trace_argument_origin(ea: str, request: TraceArgumentOriginRequest) -> dict[str, Any]:
        try:
            return app.state.backend.trace_argument_origin(
                parse_address(ea),
                parse_address(request.call_site) if request.call_site else 0,
                parse_address(request.callee_ea) if request.callee_ea else 0,
                request.target_arg_idx,
                sources=request.sources if request.sources else None,
            ).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/batch/decompile")
    async def batch_decompile(request: BatchDecompileRequest) -> list[dict[str, Any]]:
        try:
            addresses = [parse_address(a) for a in request.addresses]
            return [e.model_dump() for e in app.state.backend.batch_decompile(addresses)]
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/sources/scan")
    async def scan_source_candidates(limit: int = 100, min_score: float = 25.0) -> dict[str, Any]:
        try:
            return app.state.backend.scan_source_candidates(limit, min_score).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/sources/routes")
    async def find_route_handlers() -> dict[str, Any]:
        try:
            return app.state.backend.find_route_handlers().model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/indirect-calls/scan")
    async def scan_indirect_calls(
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> dict[str, Any]:
        try:
            return app.state.backend.scan_indirect_calls(
                max_functions=max_functions,
                max_results=max_results,
            ).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/sources/propagate")
    async def propagate_sources(request: SourcePropagateRequest) -> dict[str, Any]:
        try:
            return app.state.backend.propagate_sources(
                request.sources, request.max_rounds
            ).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.get("/functions/{ea}/analyze-as-source")
    async def analyze_as_source(ea: str) -> dict[str, Any]:
        try:
            return app.state.backend.analyze_as_source(parse_address(ea)).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/functions/{ea}/rename")
    async def rename_function(ea: str, request: RenameFunctionRequest) -> dict[str, Any]:
        try:
            result = app.state.backend.rename_function(
                parse_address(ea),
                request.new_name,
                request.reason,
            )
            return result.model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/functions/{ea}/comment")
    async def set_function_comment(ea: str, request: SetFunctionCommentRequest) -> dict[str, Any]:
        try:
            result = app.state.backend.set_function_comment(
                parse_address(ea),
                request.comment,
                request.repeatable,
                request.reason,
            )
            return result.model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/bytes/{ea}/patch")
    async def patch_bytes(ea: str, request: PatchBytesRequest) -> dict[str, Any]:
        try:
            result = app.state.backend.patch_bytes(
                parse_address(ea),
                request.patched_hex,
                request.expected_original_hex,
                request.reason,
            )
            return result.model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/bytes/{ea}/nop")
    async def nop_bytes(ea: str, request: NopBytesRequest) -> dict[str, Any]:
        try:
            return app.state.backend.nop_bytes(parse_address(ea), request).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/instructions/{ea}/patch-conditional-jump")
    async def patch_conditional_jump(
        ea: str,
        request: PatchConditionalJumpRequest,
    ) -> dict[str, Any]:
        try:
            return app.state.backend.patch_conditional_jump(
                parse_address(ea),
                request,
            ).model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/database/save")
    async def save_database(request: SaveDatabaseRequest) -> dict[str, Any]:
        try:
            result = app.state.backend.save_database(request.output_path or None)
            return result.model_dump()
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    @app.post("/database/close")
    async def close_database(request: CloseDatabaseRequest) -> dict[str, Any]:
        try:
            app.state.backend.close_database(save=request.save)
            return {"ok": True, "message": "closed"}
        except Exception as exc:  # noqa: BLE001
            _api_error(exc)

    return app


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="VulnAgent headless IDA backend")
    parser.add_argument("--idb", required=True, help="Path to .i64/.idb or input binary")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--read-only", action="store_true", help="Disable mutating operations")
    args = parser.parse_args()

    try:
        import uvicorn  # type: ignore
    except ImportError as exc:
        raise RuntimeError("HTTP serving requires uvicorn and fastapi") from exc

    from vulnagent.ida.idalib_backend import IdalibBackend

    backend = IdalibBackend(args.idb, writable=not args.read_only)
    app = create_app(backend)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
