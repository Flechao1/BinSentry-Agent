from __future__ import annotations

import json
from typing import Any

from vulnagent.clients.ida_client import IdaClient
from vulnagent.agent.validation_planner import ValidationPlanner
from vulnagent.ida.schemas import FunctionContext, SinkCallResult
from vulnagent.rules import get_default_sink_specs


def _join(values: list[object]) -> str:
    return ", ".join(str(value) for value in values) if values else "(none)"


def _json_result(text: str, **fields: Any) -> str:
    payload: dict[str, Any] = {
        "format": "vulnagent.tool_result.v1",
        "text": text,
        "confirmed_routes": [],
        "source_candidates": [],
        "confirmed_sources": [],
        "pending_sinks": [],
        "missing_evidence": [],
        "verified_findings": [],
        "candidate_findings": [],
        "known_vulnerability_matches": [],
        "function_notes": [],
        "indirect_call_sites": [],
    }
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def _dump_model(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    return {"value": str(value)}


def _aggregate_sinks(
    sinks: list[SinkCallResult],
    *,
    top_groups: int = 10,
    per_group_limit: int = 2,
    detail_limit: int = 20,
) -> tuple[list[SinkCallResult], list[dict[str, Any]]]:
    """Group sink calls by caller function and sink name.

    Returns the representative call sites to detail and a compact aggregate
    summary. Aggregation prevents a large scan (dozens of call sites across a
    handful of callers) from flooding the model context while still exposing
    every group and its volume.
    """
    groups: dict[tuple[str, str], list[SinkCallResult]] = {}
    for sink in sinks:
        key = (sink.caller_name or "unknown", sink.sink_name)
        groups.setdefault(key, []).append(sink)

    ordered = sorted(
        groups.items(),
        key=lambda item: (
            max(sink.score for sink in item[1]),
            len(item[1]),
        ),
        reverse=True,
    )[:top_groups]

    aggregates: list[dict[str, Any]] = []
    shown: list[SinkCallResult] = []
    for (caller, name), members in ordered:
        locs = [sink.loc for sink in members]
        aggregates.append({
            "caller_name": caller,
            "sink_name": name,
            "count": len(members),
            "category": members[0].category,
            "locations": locs[:5],
            "max_score": max(sink.score for sink in members),
        })
        shown.extend(members[:per_group_limit])
    return shown[:detail_limit], aggregates


def _dedupe_evidence(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in evidence:
        key = str(item.get("reason", "")).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


class IdaReconTools:
    """Agent-facing wrappers around the IDA HTTP backend."""

    def __init__(self, client: IdaClient) -> None:
        self.client = client
        self.validation_planner = ValidationPlanner()

    def get_function_context(self, ea: int | str) -> str:
        context = self.client.get_function_context(self._resolve_function_ea(ea))
        text = format_function_context(context)
        return _json_result(
            text,
            function_notes=[{
                "function_name": context.name,
                "function_ea": context.ea,
                "note": (
                    f"callers={len(context.callers)}, callees={len(context.callees)}, "
                    f"imports={_join(context.imports_used)}"
                ),
            }],
        )

    def check_backend(self) -> str:
        health = self.client.validate_protocol()
        return (
            f"IDA backend: {health.status}; protocol={health.protocol_version}; "
            f"database={health.database}; writable={health.writable}"
        )

    def decompile_function(self, ea: int | str) -> str:
        result = self.client.decompile_function(self._resolve_function_ea(ea))
        if not result.ok:
            text = f"[FAILED] decompile {result.ea}: {result.error}"
            return _json_result(
                text,
                missing_evidence=[{
                    "ea": result.ea,
                    "reason": f"Decompilation failed: {result.error}",
                }],
            )
        lines = [
            f"{result.name} @ {result.ea}",
            f"Prototype: {result.prototype or '(unknown)'}",
            "",
            "Pseudocode:",
            result.pseudocode,
        ]
        text = "\n".join(lines)
        return _json_result(
            text,
            function_notes=[{
                "function_name": result.name,
                "function_ea": result.ea,
                "note": "Function decompiled successfully.",
            }],
        )

    def get_function_xrefs(self, ea: int | str) -> str:
        xrefs = self.client.get_function_xrefs(self._resolve_function_ea(ea))
        return self._format_xrefs("Xrefs to function", xrefs)

    def get_address_xrefs(self, ea: int | str) -> str:
        """Retrieve direct xrefs for any code or data address, including globals."""
        xrefs = self.client.get_address_xrefs(ea)
        return self._format_xrefs("Xrefs to address", xrefs)

    def _format_xrefs(self, heading: str, xrefs: dict[str, list[Any]]) -> str:
        lines = [f"{heading}:"]
        lines.extend(
            f"- {record.frm} -> {record.to} ({record.type_name})"
            for record in xrefs["to"]
        )
        if len(lines) == 1:
            lines.append("- (none)")
        lines.append("")
        lines.append("Xrefs from address:")
        from_start = len(lines)
        lines.extend(
            f"- {record.frm} -> {record.to} ({record.type_name})"
            for record in xrefs["from"]
        )
        if len(lines) == from_start:
            lines.append("- (none)")
        return "\n".join(lines)

    def get_function_signals(self, ea: int | str) -> str:
        resolved_ea = self._resolve_function_ea(ea)
        calls = self.client.get_function_calls(resolved_ea)
        strings = self.client.get_function_strings(resolved_ea)
        constants = self.client.get_function_constants(resolved_ea)
        imports = self.client.get_function_imports(resolved_ea)

        lines = [
            f"Imports: {_join(imports)}",
            "Calls:",
        ]
        if calls:
            lines.extend(
                f"- {call.call_ea}: {call.target_name or call.target_ea}"
                + (" [import]" if call.is_import else "")
                for call in calls
            )
        else:
            lines.append("- (none)")

        lines.append("Strings:")
        if strings:
            lines.extend(
                f"- {record.ref_ea} -> {record.string_ea}: {record.value}"
                for record in strings
            )
        else:
            lines.append("- (none)")

        lines.append(f"Constants: {_join([hex(value) for value in constants])}")
        text = "\n".join(lines)
        return _json_result(
            text,
            function_notes=[{
                "function_ea": str(resolved_ea),
                "note": (
                    f"signals: calls={len(calls)}, imports={_join(imports)}, "
                    f"strings={len(strings)}, constants={len(constants)}"
                ),
            }],
        )

    def _resolve_function_ea(self, value: int | str) -> int | str:
        if isinstance(value, int):
            return value
        text = str(value).strip()
        if text.lower().startswith("0x") or text.isdigit():
            return text
        functions = self.client.list_functions(pattern=text, limit=10)
        exact = [function for function in functions if function.name == text]
        if len(exact) == 1:
            return exact[0].ea
        if len(functions) == 1:
            return functions[0].ea
        raise ValueError(
            f"Function name is ambiguous or unknown: {text}. Use list_binary_functions first."
        )

    # ------------------------------------------------------------------
    # Taint Analysis Tools
    # ------------------------------------------------------------------

    def list_functions(self, pattern: str = "", limit: int = 100) -> str:
        funcs = self.client.list_functions(pattern=pattern, limit=limit)
        if not funcs:
            return "(no functions found)"
        lines = [f"{len(funcs)} function(s):"]
        for f in funcs:
            lines.append(f"  {f.ea}  {f.name}  (size={f.size})")
        return "\n".join(lines)

    def get_imports(self) -> str:
        imports = self.client.get_imports()
        if not imports:
            return "(no imports)"
        lines = [f"{len(imports)} import(s):"]
        for i in imports:
            proto = f" // {i.prototype}" if i.prototype else ""
            mod = f" [{i.module}]" if i.module else ""
            lines.append(f"  {i.ea}  {i.name}{mod}{proto}")
        return "\n".join(lines)

    def detect_arch(self) -> str:
        arch = self.client.detect_arch()
        return f"Architecture: {arch.arch}, {arch.bits}-bit, {arch.endian}-endian"

    def find_sink_calls(self, ea: int | str, sink_names: str) -> str:
        """Find sink calls in a function.

        sink_names: comma-separated list of dangerous function names
                    (e.g., "system,execve,strcpy,sprintf")
        """
        names = [n.strip() for n in sink_names.split(",") if n.strip()]
        if not names:
            return "Error: provide at least one sink name"
        # Build sink_specs: each name -> [(index, 1), (range, 1, 32)]
        sink_specs = {_normalize_func_key(n): [("range", 1, 32)] for n in names}
        results = self.client.find_sink_calls(ea, sink_specs)
        if not results:
            return "(no sink calls found)"
        lines = [f"{len(results)} sink call(s) found:"]
        for r in results:
            lines.append(
                f"  [{r.category}] {r.sink_name} @ {r.loc} "
                f"(score={r.score}, confidence={r.confidence})"
            )
            for arg in r.args:
                lines.append(f"      arg {arg['index']}: {arg['expr'][:120]} [{arg['arg_type']}]")
        text = "\n".join(lines)
        pending_sinks = [
            {
                "sink_name": r.sink_name,
                "sink_ea": r.loc,
                "caller_ea": str(ea),
                "category": r.category,
                "reason": "Focused sink call requires source-to-sink validation.",
            }
            for r in results
        ]
        missing_evidence = [
            {
                "reason": (
                    f"Validate whether user-controlled input reaches "
                    f"{r.sink_name} @ {r.loc}."
                )
            }
            for r in results
        ]
        return _json_result(
            text,
            pending_sinks=pending_sinks,
            candidate_findings=[
                self.validation_planner.plan(result).model_dump(mode="json")
                for result in results
            ],
            missing_evidence=missing_evidence,
        )

    def scan_sink_calls(
        self,
        sink_names: str = "",
        roots: str = "",
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> str:
        """Run a bounded sink scan from optional comma-separated function roots."""
        if sink_names:
            names = [name.strip() for name in sink_names.split(",") if name.strip()]
            sink_specs = {_normalize_func_key(name): [("range", 1, 32)] for name in names}
        else:
            sink_specs = get_default_sink_specs()
        root_list = [root.strip() for root in roots.split(",") if root.strip()]
        result = self.client.scan_sink_calls(
            sink_specs,
            roots=root_list,
            max_depth=max_depth,
            max_functions=max_functions,
        )
        shown, aggregates = _aggregate_sinks(result.results)
        lines = [
            f"Sink scan scope: {result.scope}",
            f"Scanned functions: {result.scanned_functions}",
            f"Truncated: {result.truncated}",
            f"Sink calls: {len(result.results)}",
            f"Aggregated sink groups: {len(aggregates)}",
        ]
        for aggregate in aggregates:
            preview = ", ".join(aggregate["locations"][:3])
            extra = f" (+{aggregate['count'] - 3} more)" if aggregate["count"] > 3 else ""
            lines.append(
                f"  [{aggregate['category']}] {aggregate['caller_name']}: "
                f"{aggregate['count']} x {aggregate['sink_name']} @ {preview}{extra}"
            )
        if shown:
            lines.append(
                f"Representative call sites ({len(shown)} shown; "
                "remaining sites share the group summaries above):"
            )
            for sink in shown:
                lines.append(
                    f"  [{sink.category}] {sink.caller_name} @ {sink.caller_addr}: "
                    f"{sink.sink_name} @ {sink.loc} (score={sink.score})"
                )
        else:
            lines.append("No dangerous sink calls found in the scanned scope.")

        pending_sinks = [
            {
                "sink_name": sink.sink_name,
                "sink_ea": sink.loc,
                "caller_name": sink.caller_name,
                "caller_ea": sink.caller_addr,
                "category": sink.category,
                "reason": "Sink scan result requires source-to-sink validation.",
            }
            for sink in shown
        ]
        missing_evidence = _dedupe_evidence([
            {
                "reason": (
                    f"Validate whether user-controlled input reaches "
                    f"{sink.sink_name} @ {sink.loc}."
                )
            }
            for sink in shown
        ])
        return _json_result(
            "\n".join(lines),
            pending_sinks=pending_sinks,
            candidate_findings=[
                self.validation_planner.plan(sink).model_dump(mode="json")
                for sink in shown
            ],
            missing_evidence=missing_evidence,
            sink_aggregates=aggregates,
            function_notes=[{
                "note": "Sink scan aggregated by caller function and sink name.",
                "scope": result.scope,
                "sink_calls": len(result.results),
                "aggregate_groups": len(aggregates),
                "detailed_candidates": len(shown),
            }],
        )

    def investigate_vulnerability_candidates(
        self,
        category: str = "all",
        roots: str = "",
        sources: str = "",
        max_candidates: int = 8,
        max_depth: int = 12,
        max_functions: int = 1500,
    ) -> str:
        """Scan sinks and validate the highest-priority candidates in one bounded pass.

        This is the high-level verification loop for the Agent. It deliberately
        returns conservative statuses instead of treating a dangerous API call as
        a vulnerability. ``category`` accepts ``all``, ``command-injection``, or
        ``memory-safety``.
        """
        category = category.strip().lower() or "all"
        if category not in {"all", "command-injection", "memory-safety"}:
            return _json_result(
                f"Unsupported vulnerability category: {category}",
                missing_evidence=[{
                    "reason": "Use category all, command-injection, or memory-safety.",
                }],
            )
        max_candidates = max(1, min(int(max_candidates), 50))
        max_depth = max(0, min(int(max_depth), 32))
        max_functions = max(1, min(int(max_functions), 5000))

        specs = get_default_sink_specs()
        if category == "command-injection":
            specs = {
                name: value for name, value in specs.items()
                if name.lower() in {
                    "system", "popen", "exec", "execl", "execlp", "execle",
                    "execv", "execvp", "execve", "dosystem", "do_system",
                    "eval", "fork_exec", "twsystem", "cstesystem",
                }
            }
        elif category == "memory-safety":
            specs = {
                name: value for name, value in specs.items()
                if name.lower() in {
                    "strcpy", "strcat", "strncat", "sprintf", "vsprintf",
                    "sscanf", "memcpy", "memmove", "gets",
                }
            }

        root_list = [item.strip() for item in roots.split(",") if item.strip()]
        source_list = [item.strip() for item in sources.split(",") if item.strip()]
        scan = self.client.scan_sink_calls(
            specs,
            roots=root_list,
            max_depth=max_depth,
            max_functions=max_functions,
        )
        sinks = sorted(
            scan.results,
            key=lambda item: (
                1 if item.sink_name.lower() in {
                    "system", "popen", "exec", "execl", "execlp", "execle",
                    "execv", "execvp", "execve", "dosystem",
                } else 0,
                float(item.score),
                len(item.args),
            ),
            reverse=True,
        )[:max_candidates]

        candidates = []
        errors: list[str] = []
        for sink in sinks:
            try:
                candidates.append(
                    self.validation_planner.validate(
                        sink,
                        self.client,
                        known_sources=source_list or None,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - preserve an auditable candidate
                candidate = self.validation_planner.plan(sink)
                candidate.status = "unverified"
                candidate.conclusion = (
                    "Automatic argument-origin validation failed; manual review is required."
                )
                candidate.missing_evidence.append(
                    f"Retry argument tracing after tool error: {type(exc).__name__}: {exc}"
                )
                candidates.append(candidate)
                errors.append(f"{candidate.candidate_id}: {type(exc).__name__}: {exc}")

        counts = {
            status: sum(candidate.status == status for candidate in candidates)
            for status in ("verified", "unverified", "rejected")
        }
        lines = [
            f"Candidate investigation: category={category}",
            f"Scope={scan.scope}; scanned_functions={scan.scanned_functions}; "
            f"sink_calls={len(scan.results)}; truncated={scan.truncated}",
            f"Validated={len(candidates)}; verified={counts['verified']}; "
            f"unverified={counts['unverified']}; rejected={counts['rejected']}",
        ]
        status_rank = {"verified": 0, "unverified": 1, "rejected": 2}
        for candidate in sorted(
            candidates,
            key=lambda item: status_rank.get(item.status, 1),
        ):
            lines.append(
                f"[{candidate.status.upper()}] {candidate.category} "
                f"{candidate.sink_name} @ {candidate.sink_ea} "
                f"confidence={candidate.confidence:.2f}: {candidate.conclusion}"
            )
            for evidence in candidate.evidence[:3]:
                lines.append(f"  evidence: {evidence}")
            for missing in candidate.missing_evidence[:2]:
                lines.append(f"  next: {missing}")

        pending = [
            {
                "sink_name": candidate.sink_name,
                "sink_ea": candidate.sink_ea,
                "caller_name": candidate.caller_name,
                "caller_ea": candidate.caller_ea,
                "category": candidate.category,
                "reason": candidate.conclusion,
            }
            for candidate in candidates
            if candidate.status == "unverified"
        ]
        missing = [
            {"candidate_id": candidate.candidate_id, "reason": reason}
            for candidate in candidates
            for reason in candidate.missing_evidence
        ]
        return _json_result(
            "\n".join(lines),
            candidate_findings=[candidate.model_dump(mode="json") for candidate in candidates],
            pending_sinks=pending,
            missing_evidence=missing,
            verified_findings=[
                candidate.model_dump(mode="json")
                for candidate in candidates
                if candidate.status == "verified"
            ],
            function_notes=[{
                "note": "Candidate investigation completed in one bounded scan/validation pass.",
                "scope": scan.scope,
                "scanned_functions": scan.scanned_functions,
                "sink_calls": len(scan.results),
                "truncated": scan.truncated,
            }],
            validation_summary={
                "category": category,
                "counts": counts,
                "max_candidates": max_candidates,
                "errors": errors,
            },
        )

    def validate_sink_candidate(
        self,
        caller_ea: int | str,
        sink_ea: int | str,
        sink_name: str,
        callee_ea: int | str = "",
        sources: str = "",
    ) -> str:
        """Validate one sink candidate by tracing its dangerous arguments.

        Use this after a sink scan. It returns a conservative verified,
        unverified, or rejected verdict with the exact missing evidence.
        """
        name = _normalize_func_key(sink_name)
        results = self.client.find_sink_calls(
            caller_ea,
            {name: get_default_sink_specs().get(name, [("range", 1, 32)])},
        )
        target_ea = str(sink_ea).lower()
        sink = next(
            (
                result
                for result in results
                if result.sink_name == name and result.loc.lower() == target_ea
            ),
            None,
        )
        if sink is None:
            return _json_result(
                f"Sink candidate not found: {name} @ {sink_ea} in {caller_ea}.",
                missing_evidence=[{
                    "reason": "Re-scan the caller or confirm the exact sink call address.",
                }],
            )
        if callee_ea and not sink.callee_ea:
            sink = sink.model_copy(update={"callee_ea": str(callee_ea)})
        known_sources = [item.strip() for item in sources.split(",") if item.strip()]
        candidate = self.validation_planner.validate(
            sink,
            self.client,
            known_sources=known_sources,
        )
        payload = candidate.model_dump(mode="json")
        return _json_result(
            f"Candidate {candidate.candidate_id}: {candidate.status}. {candidate.conclusion}",
            candidate_findings=[payload],
            verified_findings=[payload] if candidate.status == "verified" else [],
            missing_evidence=[{"reason": item} for item in candidate.missing_evidence],
            pending_sinks=[] if candidate.status in {"verified", "rejected"} else [{
                "sink_name": candidate.sink_name,
                "sink_ea": candidate.sink_ea,
                "caller_name": candidate.caller_name,
                "caller_ea": candidate.caller_ea,
                "category": candidate.category,
                "reason": candidate.conclusion,
            }],
        )

    def trace_call_chain(
        self,
        ea: int | str,
        arg_index: int = 1,
        sources: str = "",
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> str:
        source_list = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
        chains = self.client.trace_call_chain(
            ea=ea,
            arg_index=arg_index,
            sources=source_list,
            max_depth=max_depth,
            max_chains=max_chains,
        )
        if not chains:
            return _json_result(
                "(no call chains found)",
                missing_evidence=[{
                    "reason": f"No call chain found for sink {ea}; try focused argument origin tracing.",
                }],
            )
        lines = [f"{len(chains)} call chain(s) found:"]
        verified_findings: list[dict[str, Any]] = []
        missing_evidence: list[dict[str, str]] = []
        for i, chain in enumerate(chains, 1):
            verdict = "VERIFIED" if chain.taint_verified else "UNVERIFIED"
            lines.append(f"\n--- Chain {i} [{verdict}] ---")
            lines.append(f"  Path: {chain.chain_str}")
            if chain.taint_verified:
                verified_findings.append({
                    "sink_ea": str(ea),
                    "source": source_list[0] if source_list else "",
                    "sink_name": "sink",
                    "reason": chain.chain_str,
                })
            else:
                missing_evidence.append({
                    "reason": f"Complete source-to-sink evidence for {chain.chain_str}.",
                })
            for node in chain.chain:
                extra = ""
                if node.taint_status != "unknown":
                    extra = f" [{node.taint_status}] {node.taint_reason}"
                lines.append(f"    {node.func_name} @ {node.func_addr} (arg {node.arg_index}){extra}")
        return _json_result(
            "\n".join(lines),
            verified_findings=verified_findings,
            missing_evidence=missing_evidence,
        )

    def trace_argument_origin(
        self,
        caller_ea: int | str,
        call_site: int | str,
        callee_ea: int | str,
        target_arg_idx: int = 1,
        sources: str = "",
    ) -> str:
        source_list = [s.strip() for s in sources.split(",") if s.strip()] if sources else None
        result = self.client.trace_argument_origin(
            caller_ea=caller_ea,
            call_site=call_site,
            callee_ea=callee_ea,
            target_arg_idx=target_arg_idx,
            sources=source_list,
        )
        lines = [
            f"Taint status: {result.taint_status}",
            f"Reason: {result.reason}",
        ]
        if result.source_func:
            lines.append(f"Source function: {result.source_func}")
        if result.source_param:
            lines.append(f"Source param: arg {result.source_param}")
        if result.source_expr:
            lines.append(f"Source expression: {result.source_expr}")
        if result.next_arg_index:
            lines.append(f"Next trace arg index: {result.next_arg_index}")
        confirmed_sources = []
        verified_findings = []
        missing_evidence = []
        if result.source_func:
            confirmed_sources.append({
                "name": result.source_func,
                "reason": result.reason,
            })
        if result.taint_status.lower() in {"tainted", "verified"}:
            verified_findings.append({
                "source": result.source_func or "source",
                "sink_ea": str(call_site),
                "sink_name": str(callee_ea),
                "reason": result.reason,
            })
        else:
            missing_evidence.append({
                "reason": (
                    result.reason
                    or f"Argument origin remains unresolved for {caller_ea}."
                )
            })
        return _json_result(
            "\n".join(lines),
            taint_status=result.taint_status,
            confirmed_sources=confirmed_sources,
            verified_findings=verified_findings,
            missing_evidence=missing_evidence,
        )

    def batch_decompile(self, addresses: str) -> str:
        """Decompile multiple functions at once.

        addresses: comma-separated list of hex addresses (e.g., "0x1000,0x2000,0x3000")
        """
        addrs = [a.strip() for a in addresses.split(",") if a.strip()]
        if not addrs:
            return "Error: provide at least one address"
        results = self.client.batch_decompile(addrs)
        lines = [f"Decompiled {len(results)} function(s):"]
        for r in results:
            if r.ok:
                lines.append(f"\n--- {r.name} @ {r.ea} ---")
                lines.append(r.pseudocode[:3000])
            else:
                lines.append(f"\n--- {r.ea}: FAILED ({r.error}) ---")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Source Analysis Tools
    # ------------------------------------------------------------------

    def scan_source_candidates(self, limit: str = "100", min_score: str = "25") -> str:
        """Scan all functions to find likely taint sources using heuristics.

        limit: max candidates to scan (default 100)
        min_score: minimum score to include in results (default 25)
        """
        result = self.client.scan_source_candidates(
            limit=int(limit), min_score=float(min_score)
        )
        if not result.results:
            return _json_result(
                f"Scanned {result.candidates_scanned} of {result.total_functions} functions. "
                f"No source candidates found above score threshold."
            )
        lines = [
            f"Source scan: {len(result.results)} candidates from "
            f"{result.total_functions} total functions:",
        ]
        for c in result.results:
            lines.append(
                f"\n  [{c.score:.0f}] {c.name} @ {c.ea} "
                f"(xrefs={c.xref_count}, str_ratio={c.string_ratio:.2f})"
            )
            lines.append(f"    Reasons: {'; '.join(c.reasons)}")
            if c.sample_strings:
                lines.append(f"    Sample strings: {', '.join(c.sample_strings)}")
            if c.decompiled_code:
                lines.append(f"    Pseudocode:\n{c.decompiled_code[:1500]}")
        return _json_result(
            "\n".join(lines),
            source_candidates=[
                {
                    "name": c.name,
                    "ea": c.ea,
                    "score": c.score,
                    "reason": "; ".join(c.reasons),
                }
                for c in result.results
            ],
        )

    def find_route_handlers(self) -> str:
        """Find heuristic route-registration seeds and cross-handler callees."""
        result = self.client.find_route_handlers()
        sections = [
            (
                "Heuristic baseline only: results may omit indirect, dynamic, or "
                "framework-specific route registrations."
            )
        ]

        if result.registrations:
            sections.append(f"Route registrations ({len(result.registrations)}):")
            for r in result.registrations:
                sections.append(
                    f"  {r.registration_name} @ {r.registration_ea}: "
                    f"\"{r.route_name}\" -> {r.handler_name} @ {r.handler_ea}"
                )
        else:
            sections.append("No route registrations found (not a web firmware or no patterns detected).")

        if result.handlers:
            sections.append(f"\nHandler functions ({len(result.handlers)}):")
            for h in result.handlers:
                sections.append(f"  {h}")

        if result.cross_handler_callees:
            sections.append(f"\nCross-handler callees ({len(result.cross_handler_callees)}):")
            for c in result.cross_handler_callees:
                sections.append(
                    f"  {c.name} @ {c.ea} - called by {c.handler_count}/{c.total_handlers} "
                    f"handlers (ratio={c.ratio:.2f})"
                )
        else:
            sections.append("\nNo cross-handler callees found.")

        return _json_result(
            "\n".join(sections),
            confirmed_routes=[
                {
                    "route": r.route_name,
                    "handler_name": r.handler_name,
                    "handler_ea": r.handler_ea,
                    "registration_name": r.registration_name,
                    "registration_ea": r.registration_ea,
                }
                for r in result.registrations
            ],
            function_notes=[
                {
                    "function_name": c.name,
                    "function_ea": c.ea,
                    "note": (
                        f"cross-handler callee: called by {c.handler_count}/"
                        f"{c.total_handlers} handlers"
                    ),
                }
                for c in result.cross_handler_callees
            ],
        )

    def scan_indirect_calls(
        self,
        max_functions: str = "1000",
        max_results: str = "200",
    ) -> str:
        """Scan decompiled functions for indirect calls such as callbacks and dispatch tables."""
        result = self.client.scan_indirect_calls(
            max_functions=int(max_functions),
            max_results=int(max_results),
        )
        lines = [
            "Indirect call scan:",
            f"  Scanned functions: {result.scanned_functions}",
            f"  Failed decompilations: {result.failed_decompilations}",
            f"  Truncated: {result.truncated}",
            f"  Indirect call candidates: {len(result.results)}",
        ]
        for item in result.results:
            lines.append(
                f"  [{item.kind}] {item.caller_name} @ {item.caller_ea}: "
                f"{item.call_ea or '(unknown call ea)'} -> {item.target_expr} "
                f"(confidence={item.confidence:.2f})"
            )
            if item.expr and item.expr != item.target_expr:
                lines.append(f"      expr: {item.expr[:180]}")
            if item.evidence:
                lines.append(f"      evidence: {'; '.join(item.evidence[:3])}")
        return _json_result(
            "\n".join(lines),
            indirect_call_sites=[
                {
                    "caller_name": item.caller_name,
                    "caller_ea": item.caller_ea,
                    "ea": item.call_ea,
                    "note": (
                        f"{item.kind}: {item.target_expr} "
                        f"(confidence={item.confidence:.2f})"
                    ),
                }
                for item in result.results
            ],
            missing_evidence=[
                {
                    "reason": (
                        f"Resolve possible targets for indirect call "
                        f"{item.call_ea or '(unknown call ea)'} in {item.caller_name}."
                    )
                }
                for item in result.results
            ],
        )

    def propagate_sources(self, sources: str, max_rounds: str = "5") -> str:
        """Propagate source labels through wrapper functions.

        sources: comma-separated list of known source function names
        max_rounds: max propagation rounds (default 5)
        """
        source_list = [s.strip() for s in sources.split(",") if s.strip()]
        if not source_list:
            return "Error: provide at least one source function name"
        result = self.client.propagate_sources(source_list, int(max_rounds))
        if not result.new_sources:
            return _json_result(
                f"Propagation complete after {result.rounds} round(s). "
                f"No new wrapper sources discovered."
            )
        lines = [
            f"Propagation complete after {result.rounds} round(s). "
            f"Discovered {len(result.new_sources)} wrapper source(s):",
        ]
        for s in result.new_sources:
            lines.append(f"  - {s}")
        return _json_result(
            "\n".join(lines),
            confirmed_sources=[{"name": source} for source in result.new_sources],
        )

    def analyze_as_source(self, ea: str) -> str:
        """Analyze whether a specific function matches the param-getter (source) pattern."""
        result = self.client.analyze_as_source(ea)
        lines = [
            f"Source analysis: {result.name} @ {result.ea}",
            f"  Score: {result.score:.1f}/100",
            f"  Xrefs: {result.xref_count}",
            f"  String ratio: {result.string_ratio:.2f}",
            f"  Reasons: {'; '.join(result.reasons)}",
        ]
        if result.sample_strings:
            lines.append(f"  Sample strings: {', '.join(result.sample_strings)}")
        if result.decompiled_code:
            lines.append(f"\n  Pseudocode:\n{result.decompiled_code[:1500]}")
        candidate = {
            "name": result.name,
            "ea": result.ea,
            "score": result.score,
            "reason": "; ".join(result.reasons),
        }
        return _json_result(
            "\n".join(lines),
            source_candidates=[candidate],
            confirmed_sources=[candidate] if result.score >= 75 else [],
            function_notes=[{
                "function_name": result.name,
                "function_ea": result.ea,
                "note": f"source score={result.score:.1f}; reasons={'; '.join(result.reasons)}",
            }],
        )


def _normalize_func_key(name: str) -> str:
    name = name.strip()
    if name.startswith("j_"):
        name = name[2:]
    if name.startswith("__imp_"):
        name = name[6:]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def format_function_context(context: FunctionContext) -> str:
    lines = [
        f"{context.name} @ {context.ea}",
        f"Prototype: {context.prototype or '(unknown)'}",
        f"Callers: {_join(context.callers)}",
        f"Callees: {_join(context.callees)}",
        f"Xrefs to: {_join(context.xrefs_to)}",
        f"Xrefs from: {_join(context.xrefs_from[:20])}",
        f"Imports: {_join(context.imports_used)}",
        f"Strings: {_join(context.strings)}",
        f"Constants: {_join([hex(value) for value in context.constants])}",
        f"Hints: {_join(context.confidence_hints)}",
        "",
        "Pseudocode:",
        context.pseudocode or "(decompile unavailable)",
    ]
    return "\n".join(lines)
