"""Command-line entrypoints for VulnAgent."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from vulnagent.agent.baseline_scan import BaselineScanConfig
from vulnagent.harness import (
    BinaryVulnAgentHarness,
    HarnessBaselineScanRequest,
    HarnessTurnRequest,
)
from vulnagent.firmware.scanner import (
    FirmwareFilesystemScanner,
    attach_ida_backend_commands,
    _format_table,
)
from vulnagent.intel import IntelQuery, VulnerabilityIntelService
from vulnagent.storage import SqliteVulnRepository


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ask":
        asyncio.run(_ask(args))
        return
    if args.command == "scan":
        asyncio.run(_scan(args))
        return
    if args.command == "serve":
        _serve(args)
        return
    if args.command == "runs":
        _runs(args)
        return
    if args.command == "show-run":
        _show_run(args)
        return
    if args.command == "api":
        _api(args)
        return
    if args.command in {"scan-firmware", "triage-firmware"}:
        _scan_firmware(args)
        return
    if args.command == "intel":
        _intel(args)
        return
    parser.print_help()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VulnAgent command line interface")
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Start the IDA backend service")
    serve.add_argument("--idb", required=True, help="Path to .i64/.idb or input binary")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--read-only", action="store_true", help="Disable mutating operations")

    ask = subparsers.add_parser("ask", help="Ask the Agent through the harness")
    _add_harness_common_args(ask)
    ask.add_argument("prompt", help="Question for the vulnerability analysis Agent")
    ask.add_argument("--thread-id", default="", help="Existing chat thread id")
    ask.add_argument("--new-thread", action="store_true", help="Create a new SQLite chat thread")
    ask.add_argument("--json", action="store_true", help="Print structured JSON result")

    scan = subparsers.add_parser("scan", help="Run Baseline Scan through the harness")
    _add_harness_common_args(scan)
    scan.add_argument("--thread-id", default="", help="Existing chat thread id")
    scan.add_argument("--new-thread", action="store_true", help="Create a new SQLite chat thread")
    scan.add_argument("--source-limit", type=int, default=100)
    scan.add_argument("--source-min-score", type=float, default=25.0)
    scan.add_argument("--sink-max-depth", type=int, default=8)
    scan.add_argument("--sink-max-functions", type=int, default=500)
    scan.add_argument(
        "--validation-max-candidates",
        type=int,
        default=8,
        help="Maximum high-priority sink candidates to validate automatically",
    )
    scan.add_argument("--max-findings", type=int, default=100)
    scan.add_argument("--json", action="store_true", help="Print structured JSON result")

    runs = subparsers.add_parser("runs", help="List persisted harness runs")
    runs.add_argument("--db-path", default="", help="SQLite database path")
    runs.add_argument("--limit", type=int, default=20)
    runs.add_argument("--json", action="store_true", help="Print structured JSON result")

    show_run = subparsers.add_parser("show-run", help="Show one persisted harness run")
    show_run.add_argument("run_id", help="Harness run id")
    show_run.add_argument("--db-path", default="", help="SQLite database path")
    show_run.add_argument("--json", action="store_true", help="Print structured JSON result")

    api = subparsers.add_parser("api", help="Start the VulnAgent application API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8787)
    api.add_argument("--reload", action="store_true")

    firmware = subparsers.add_parser(
        "scan-firmware",
        help="Scan an extracted firmware filesystem and rank binaries for IDA analysis",
    )
    _add_firmware_args(firmware)

    triage = subparsers.add_parser(
        "triage-firmware",
        help="Scan firmware and print suggested IDA backend startup commands",
    )
    _add_firmware_args(triage)
    triage.set_defaults(show_ida_commands=True)

    intel = subparsers.add_parser(
        "intel",
        help="Search CVE/GitHub intelligence for known vulnerability matches",
    )
    intel.add_argument("--vendor", default="")
    intel.add_argument("--product", default="")
    intel.add_argument("--firmware-version", default="")
    intel.add_argument("--component", default="")
    intel.add_argument("--vuln-type", default="")
    intel.add_argument("--route", default="")
    intel.add_argument("--sink", default="")
    intel.add_argument("--symbols", default="", help="Comma-separated function or symbol names")
    intel.add_argument("--keywords", default="", help="Comma-separated additional keywords")
    intel.add_argument(
        "--sources",
        default="cveorg,nvd,github",
        help="Comma-separated sources: cveorg,nvd,github",
    )
    intel.add_argument("--limit", type=int, default=10)
    intel.add_argument("--json", action="store_true")

    return parser


def _add_firmware_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("root", help="Extracted firmware filesystem directory, e.g. squashfs-root")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--json", action="store_true", help="Print structured JSON result")
    parser.add_argument("--show-ida-commands", action="store_true")
    parser.add_argument("--host", default="127.0.0.1", help="Host for suggested IDA backend command")
    parser.add_argument("--port", type=int, default=8765, help="Port for suggested IDA backend command")
    parser.add_argument("--writable", action="store_true", help="Generate writable backend command")


def _add_harness_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--backend-url",
        default="http://127.0.0.1:8765",
        help="IDA backend URL",
    )
    parser.add_argument("--report-dir", default="./reports", help="Report output directory")
    parser.add_argument("--db-path", default="", help="SQLite database path")
    parser.add_argument("--timeout", type=float, default=120.0, help="IDA/backend timeout")


async def _ask(args: argparse.Namespace) -> None:
    repository = _repository(args)
    thread_id = _thread_id(repository, args)
    messages = repository.load_chat_messages(thread_id) if thread_id else []
    harness = BinaryVulnAgentHarness(repository=repository, timeout=args.timeout)
    result = await harness.run_agent_chat(
        HarnessTurnRequest(
            prompt=args.prompt,
            thread_id=thread_id,
            messages=messages,
            ida_backend_url=args.backend_url,
            report_dir=args.report_dir,
        )
    )
    _print_result(result, as_json=args.json)


async def _scan(args: argparse.Namespace) -> None:
    repository = _repository(args)
    thread_id = _thread_id(repository, args)
    harness = BinaryVulnAgentHarness(repository=repository, timeout=args.timeout)
    result = await harness.run_baseline_scan(
        HarnessBaselineScanRequest(
            thread_id=thread_id,
            ida_backend_url=args.backend_url,
            report_dir=args.report_dir,
            config=BaselineScanConfig(
                source_limit=args.source_limit,
                source_min_score=args.source_min_score,
                sink_max_depth=args.sink_max_depth,
                sink_max_functions=args.sink_max_functions,
                validation_max_candidates=args.validation_max_candidates,
                max_findings=args.max_findings,
            ),
        )
    )
    _print_result(result, as_json=args.json)


def _serve(args: argparse.Namespace) -> None:
    try:
        import uvicorn  # type: ignore
    except ImportError as exc:
        raise RuntimeError("HTTP serving requires uvicorn and fastapi") from exc

    from vulnagent.ida.backend import create_app
    from vulnagent.ida.idalib_backend import IdalibBackend

    backend = IdalibBackend(args.idb, writable=not args.read_only)
    app = create_app(backend)
    server = uvicorn.Server(uvicorn.Config(app, host=args.host, port=args.port))
    app.state.shutdown_callback = lambda: setattr(server, "should_exit", True)
    server.run()


def _runs(args: argparse.Namespace) -> None:
    repository = _repository(args)
    runs = repository.list_harness_runs(limit=args.limit)
    if args.json:
        print(json.dumps(runs, ensure_ascii=False, indent=2, default=str))
        return
    if not runs:
        print("No harness runs found.")
        return
    for run in runs:
        print(
            f"{run['id']} | {run['mode']} | {run['status']} | "
            f"thread={run['thread_id'] or '-'} | report={run['report_id'] or '-'}"
        )


def _show_run(args: argparse.Namespace) -> None:
    repository = _repository(args)
    run = repository.get_harness_run(args.run_id)
    if run is None:
        print(f"Unknown harness run: {args.run_id}")
        return
    if args.json:
        print(json.dumps(run, ensure_ascii=False, indent=2, default=str))
        return
    print(f"Run ID: {run['id']}")
    print(f"Mode: {run['mode']}")
    print(f"Status: {run['status']}")
    print(f"Thread ID: {run['thread_id'] or '-'}")
    print(f"Report ID: {run['report_id'] or '-'}")
    if run["error"]:
        print(f"Error: {run['error']}")
    if run["answer"]:
        print(f"Answer: {run['answer']}")
    print("Trace:")
    for event in run["trace_events"]:
        print(f"  [{event['sequence']}] {event['event_type']}: {event['message']}")


def _api(args: argparse.Namespace) -> None:
    try:
        import uvicorn  # type: ignore
    except ImportError as exc:
        raise RuntimeError("HTTP serving requires uvicorn and fastapi") from exc

    uvicorn.run(
        "vulnagent.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def _scan_firmware(args: argparse.Namespace) -> None:
    report = FirmwareFilesystemScanner(args.root).scan(limit=args.limit)
    attach_ida_backend_commands(
        report,
        host=args.host,
        port=args.port,
        read_only=not args.writable,
    )
    if args.json:
        print(report.to_json())
        return
    print(_format_table(report, show_ida_commands=args.show_ida_commands))


def _intel(args: argparse.Namespace) -> None:
    query = IntelQuery(
        vendor=args.vendor,
        product=args.product,
        firmware_version=args.firmware_version,
        component=args.component,
        vulnerability_type=args.vuln_type,
        route=args.route,
        sink=args.sink,
        symbols=_split_csv(args.symbols),
        keywords=_split_csv(args.keywords),
        max_results=args.limit,
    )
    result = VulnerabilityIntelService().search(query, sources=_split_csv(args.sources))
    if args.json:
        print(result.model_dump_json(indent=2))
        return
    print(f"Assessment: {result.assessment}")
    if result.errors:
        print(f"Errors: {'; '.join(result.errors)}")
    if not result.matches:
        print("No strong public intelligence match found.")
        return
    for match in result.matches:
        ref = match.reference
        print(f"{match.score:3d} {match.confidence:6s} {ref.source:6s} {ref.identifier} {ref.url}")
        print(f"    reasons: {'; '.join(match.reasons)}")


def _repository(args: argparse.Namespace) -> SqliteVulnRepository:
    return SqliteVulnRepository(args.db_path) if args.db_path else SqliteVulnRepository.from_env()


def _thread_id(repository: SqliteVulnRepository, args: argparse.Namespace) -> str:
    if args.new_thread:
        return repository.create_chat_thread(title="CLI investigation")
    return args.thread_id


def _print_result(result: Any, *, as_json: bool) -> None:
    if as_json:
        print(
            result.model_dump_json(
                indent=2,
                exclude={"messages", "report"},
            )
        )
        return
    if result.status != "completed":
        print(f"FAILED: {result.error}")
        return
    if result.report_id:
        print(f"Report ID: {result.report_id}")
    if result.thread_id:
        print(f"Thread ID: {result.thread_id}")
    print(result.answer)
    if result.trace_events:
        trace_summary = [
            {
                "type": event.event_type,
                "message": event.message,
                "data": event.data,
            }
            for event in result.trace_events
        ]
        print("\nTrace:")
        print(json.dumps(trace_summary, ensure_ascii=False, indent=2, default=str))


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
