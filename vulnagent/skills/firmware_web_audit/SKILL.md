# Firmware Web/CGI Binary Audit

## Goal

Identify evidence-backed command-injection and unsafe-memory-operation risks in the
active firmware binary. Treat IDA output and deterministic taint tools as the source of
truth. Use language-model reasoning to prioritize investigation and explain evidence.

## Required Baseline

1. Check the IDA backend and active database.
2. Detect architecture and enumerate imports.
3. Find route handlers and likely user-input getter functions.
4. Propagate known source labels through wrapper functions.
5. Scan dangerous sinks with bounded depth and function-count limits.
6. Trace each non-constant sink argument toward known sources.

## Tool Selection

- Treat `find_web_route_handlers` as an optional heuristic baseline for registered
  routes, URL paths, and endpoints. Its output is not exhaustive. For complete
  route investigation, continue with imports, function search, xrefs,
  `get_function_signals`, and targeted pseudocode inspection around registration
  functions, dispatchers, and unresolved handlers.
- Use `scan_indirect_calls` when route discovery, xrefs, or call-chain tracing
  appears incomplete because a dispatcher may call handlers through function
  pointers, callback fields, or tables. Treat its results as missing call-graph
  edges until targets are resolved by follow-up evidence.
- Use `get_function_signals` before `get_function_context` or
  `decompile_function` when calls, imports, strings, or constants are enough.
- Request at most one pseudocode/decompile tool call in a single tool batch. If
  multiple functions need inspection, inspect them one at a time and summarize why the
  next function is necessary.
- Use `find_function_sink_calls` for a known function. Reserve
  `scan_dangerous_sink_calls` for bounded multi-function discovery.
- Use `analyze_function_as_source` for a known candidate. Reserve
  `scan_taint_source_candidates` for bounded discovery.
- When the user asks only to scan or classify user-input sources, call
  `scan_taint_source_candidates` once, optionally call `propagate_taint_sources` once
  for wrappers, and then summarize confirmed sources versus candidates. Do not start
  sink scanning or taint tracing unless the user asks to validate a source-to-sink
  chain.
- Use `trace_argument_origin` for a known callsite argument. Use
  `trace_taint_call_chain` when the relevant caller chain is still unknown.
- Analyze only the functions needed to answer the current question. Summarize
  collected evidence before requesting more decompilation.

## Evidence Rules

- A dangerous imported function alone is not a verified vulnerability.
- Mark a finding `verified` only when a source-to-sink chain is supported by tool
  evidence.
- Mark incomplete chains `unverified` and state which evidence is missing.
- Prefer inspecting handlers, shared handler callees, and high-confidence source
  candidates before unrelated functions.
- Do not repeatedly decompile the same function unless new evidence justifies it.

## Write Safety

- Analysis is read-only by default.
- Never rename functions or save an IDB without explicit user confirmation.
- Present the target address, new name, reason, or save path before requesting
  confirmation.

## Reporting

For each finding, include category, severity, confidence, sink location, source,
call-chain evidence, verification status, and remediation guidance.
