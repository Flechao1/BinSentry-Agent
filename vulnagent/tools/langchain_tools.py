"""LangChain tool adapters for conversational IDA investigation."""

from __future__ import annotations

from typing import Any

from vulnagent.clients.ida_client import IdaClient
from vulnagent.tools.firmware_tools import FirmwareFilesystemTools
from vulnagent.tools.intel_tools import VulnerabilityIntelTools
from vulnagent.tools.recon_tools import IdaReconTools


def build_readonly_ida_tools(client: IdaClient) -> list[Any]:
    """Create read-only LangChain tools without exposing IDB mutation methods."""
    from langchain_core.tools import StructuredTool

    firmware = FirmwareFilesystemTools()
    intel = VulnerabilityIntelTools()
    recon = IdaReconTools(client)
    return [
        StructuredTool.from_function(
            firmware.scan_firmware_filesystem,
            name="scan_firmware_filesystem",
            description=(
                "Scan an extracted firmware filesystem directory, rank ELF binaries "
                "worth importing into IDA, and summarize Web endpoints, startup "
                "references, sensitive files, and source/sink string markers. Use "
                "this before IDA analysis when the user provides a firmware root "
                "such as squashfs-root."
            ),
        ),
        StructuredTool.from_function(
            intel.search_vulnerability_intel,
            name="search_vulnerability_intel",
            description=(
                "Search CVE.org, NVD CVE, and GitHub public references for known "
                "vulnerability matches using observed firmware/finding evidence such "
                "as vendor, product, firmware version, route, sink, component, and "
                "symbols. Use this after a candidate or confirmed finding, not as "
                "proof by itself."
            ),
        ),
        StructuredTool.from_function(
            recon.check_backend,
            name="check_ida_backend",
            description="Check IDA backend availability, protocol version, and active database.",
        ),
        StructuredTool.from_function(
            recon.detect_arch,
            name="detect_binary_architecture",
            description="Detect architecture, bitness, and endianness for the active binary.",
        ),
        StructuredTool.from_function(
            recon.get_imports,
            name="list_binary_imports",
            description="List imported functions from the active binary.",
        ),
        StructuredTool.from_function(
            recon.list_functions,
            name="list_binary_functions",
            description="List functions, optionally filtering by a wildcard pattern.",
        ),
        StructuredTool.from_function(
            recon.get_function_context,
            name="get_function_context",
            description="Retrieve pseudocode, callers, callees, strings, constants, and imports.",
        ),
        StructuredTool.from_function(
            recon.decompile_function,
            name="decompile_function",
            description="Decompile one function by hexadecimal address.",
        ),
        StructuredTool.from_function(
            recon.get_function_xrefs,
            name="get_function_xrefs",
            description="Retrieve cross-references to and from one function.",
        ),
        StructuredTool.from_function(
            recon.get_address_xrefs,
            name="get_address_xrefs",
            description=(
                "Retrieve direct cross-references for any code or data address. Use "
                "this for strings, globals, tables, or an address that is not a "
                "function entry; use get_function_xrefs only for functions."
            ),
        ),
        StructuredTool.from_function(
            recon.get_function_signals,
            name="get_function_signals",
            description=(
                "Retrieve lightweight calls, imports, strings, and constants for one "
                "function. Prefer this before pseudocode tools when decompilation is "
                "not required."
            ),
        ),
        StructuredTool.from_function(
            recon.find_route_handlers,
            name="find_web_route_handlers",
            description=(
                "Find heuristic Web/CGI URL route-registration seeds, handlers, and "
                "common handler callees. This is useful baseline evidence but may be "
                "incomplete for indirect, dynamic, or framework-specific routing."
            ),
        ),
        StructuredTool.from_function(
            recon.scan_indirect_calls,
            name="scan_indirect_calls",
            description=(
                "Scan decompiled functions for indirect call candidates such as "
                "function pointers, callback fields, and dispatch tables. Use this "
                "when the static call graph or route discovery appears incomplete."
            ),
        ),
        StructuredTool.from_function(
            recon.scan_source_candidates,
            name="scan_taint_source_candidates",
            description="Find likely user-input getter functions using bounded heuristics.",
        ),
        StructuredTool.from_function(
            recon.analyze_as_source,
            name="analyze_function_as_source",
            description=(
                "Analyze one known function as a possible user-input source. Prefer "
                "this focused tool over a global source scan when an address is known."
            ),
        ),
        StructuredTool.from_function(
            recon.propagate_sources,
            name="propagate_taint_sources",
            description="Discover wrappers around known user-input getter functions.",
        ),
        StructuredTool.from_function(
            recon.find_sink_calls,
            name="find_function_sink_calls",
            description=(
                "Find dangerous sink calls inside one known function. Prefer this "
                "focused tool over a broad sink scan when an address is known."
            ),
        ),
        StructuredTool.from_function(
            recon.scan_sink_calls,
            name="scan_dangerous_sink_calls",
            description="Run a bounded scan for dangerous command and memory-operation sinks.",
        ),
        StructuredTool.from_function(
            recon.investigate_vulnerability_candidates,
            name="investigate_vulnerability_candidates",
            description=(
                "Run the bounded vulnerability verification loop: scan dangerous sinks, "
                "extract their arguments, trace argument origins, and return structured "
                "verified/unverified/rejected candidate findings plus missing evidence. "
                "Use this for a first vulnerability pass; use validate_sink_candidate "
                "for a later focused re-check."
            ),
        ),
        StructuredTool.from_function(
            recon.validate_sink_candidate,
            name="validate_sink_candidate",
            description=(
                "Validate one discovered sink candidate deterministically. It traces "
                "the dangerous arguments and returns a verified, unverified, or "
                "rejected verdict plus missing evidence. Use this before claiming a "
                "vulnerability."
            ),
        ),
        StructuredTool.from_function(
            recon.trace_call_chain,
            name="trace_taint_call_chain",
            description="Trace a sink argument backwards through callers toward known sources.",
        ),
        StructuredTool.from_function(
            recon.trace_argument_origin,
            name="trace_argument_origin",
            description=(
                "Trace one argument at a known callsite toward its origin. Prefer this "
                "focused tool when the caller, callsite, and callee are already known."
            ),
        ),
    ]
