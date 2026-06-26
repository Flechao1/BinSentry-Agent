# Binary Vulnerability Agent Development Plan

## Summary

Customize `agent-service-toolkit` into a single-user vulnerability analysis service for
Web/CGI firmware binaries. Keep the IDA backend as an independent process. Use the
toolkit for chat interaction, automated scan orchestration, streamed progress updates,
LLM-assisted review, human-confirmed IDB writes, and JSON report export.

The first version supports one active IDA backend and one active sample. Deterministic
tools extract evidence. The LLM plans, reviews, and explains findings. It must not
traverse the entire binary without bounded workflow controls.

## Key Changes

### 1. IDA Protocol and Adapter Layer

- Keep the existing `vulnagent` IDA HTTP backend separate. Do not merge IDALib
  implementation code into the toolkit.
- Add a lightweight adapter layer under `agent-service-toolkit/src/binary_vuln/`:
  asynchronous HTTP client, Pydantic protocol models, LangChain tool wrappers, sink
  rules, and report models.
- Add configuration:

  ```env
  IDA_BACKEND_URL=http://127.0.0.1:8765
  IDA_BACKEND_TIMEOUT=120
  VULN_REPORT_DIR=./reports
  ```

- Extend the IDA `/health` response with `protocol_version`. Before scanning, validate
  the protocol version, database path, and backend availability to prevent drift
  between the copied adapter layer and the standalone backend.
- Add `POST /sink-calls/scan` to the IDA backend. Traverse the call graph from route
  handlers. If no handlers are identified, run a bounded global scan. Support
  `sink_specs`, `roots`, `max_depth`, and `max_functions`.

### 2. Dedicated LangGraph Agent

Add `binary-vulnerability-agent` and make it the default agent. Keep existing example
agents for comparison and regression testing.

The automated graph executes these stages and reports progress through the existing
`TaskData` SSE mechanism:

1. `check_backend`: check IDA service availability, protocol version, and current
   sample.
2. `collect_metadata`: retrieve architecture, imports, and function overview.
3. `discover_entrypoints`: identify Web/CGI route handlers, cross-handler callees, and
   source candidates.
4. `propagate_sources`: discover wrappers around parameter-reading functions.
5. `scan_sinks`: scan command execution and unsafe string operations:

   ```text
   system, popen, exec*, doSystem
   strcpy, strcat, sprintf, memcpy, memmove
   ```

6. `trace_taint`: trace non-constant sink arguments from source to sink.
7. `review_findings`: provide bounded evidence to the LLM and request structured
   severity, confidence, risk explanation, and remediation output.
8. `persist_report`: save a JSON report and return a Markdown summary in chat.

Keep conversational follow-up mode through `ToolNode`. Expose these read-only tools to
the LLM: architecture detection, import listing, function listing, decompilation,
function context, cross-references, source scanning, route discovery, sink scanning,
and taint tracing.

### 3. Controlled IDB Writes

- Start the IDA backend in writable mode, but keep analysis read-only by default.
- Expose `request_rename_function` and `request_save_database` to the LLM.
- Both tools use `interrupt()` to show the address, proposed name, reason, or save path.
- Only execute IDA write endpoints after the user explicitly confirms. Cancel on any
  other response.
- Do not expose direct rename or save tools that bypass confirmation nodes.

### 4. Reports and API

Write JSON reports to `VULN_REPORT_DIR/<report_id>.json` with this shape:

```text
report_id, report_version, created_at, thread_id
sample: database, architecture, bits, endian
scope, routes, source_candidates
findings[]:
  finding_id, category, severity, confidence
  sink, source, call_chain, evidence
  llm_review, remediation, verification_status
summary
```

Add endpoints:

```http
GET /reports/{report_id}
GET /{agent_id}/history
```

- Return JSON files through the report endpoint and validate `report_id` to reject path
  traversal.
- Keep the existing `/history` route for compatibility. The new route fixes the current
  behavior where history always reads from the default agent.

### 5. Streamlit Customization

- Show a sidebar button named `Start Baseline Scan` when
  `binary-vulnerability-agent` is selected.
- On click, use the existing `/stream` endpoint with:

  ```python
  agent_config={"workflow": "baseline_scan"}
  ```

- Reuse the existing status components to display scan phases, tool inputs, tool
  outputs, and errors.
- Add a report artifact message type. After scanning, show the Markdown summary and a
  JSON download button.
- Add a dedicated welcome message. Keep text chat and optional voice support.

## Public Interfaces

- IDA backend: add `protocol_version` and `/sink-calls/scan`.
- Toolkit: add `BinaryVulnerabilityReport`, `VulnerabilityFinding`, and
  `ReportArtifactData`.
- `AgentClient`: add `get_report(report_id)` and support the current `agent_id` in
  `get_history()`.
- `.env.example`: add IDA URL, timeout, and report directory configuration.

## Test Plan

- Test the adapter layer with a mock IDA HTTP server: normal responses, timeout,
  offline backend, incompatible protocol version, and invalid JSON.
- Test the scan graph: discovered routes, route fallback, no sinks, unverified chain,
  verified chain, decompilation failure, and report write failure.
- Test controlled writes: confirm execution, reject execution, reject invalid function
  names, and ensure no side effects occur without confirmation.
- Test report API: successful download, unknown report ID, invalid ID, and path
  traversal.
- Test Streamlit: scan button visibility, stage rendering, and JSON download.
- Run the existing toolkit suite to prevent regressions in chat, token streaming,
  history, and example agents.

## Acceptance Criteria

- After starting an independent IDA backend, a user can launch a baseline scan from
  Streamlit with one button.
- The page continuously reports scan progress without blocking SSE updates on
  synchronous IDA requests.
- Results include source, sink, call-chain evidence, LLM review, and a downloadable JSON
  report.
- Renaming functions and saving an IDB always require explicit human confirmation.
- When the IDA backend is unavailable or incompatible, the UI reports a clear error and
  does not generate an empty report.

## Assumptions

- Version 1 targets a single user, a single active sample, and Web/CGI firmware
  analysis.
- The toolkit copies only the HTTP adapter layer, not IDALib backend implementation.
- SQLite continues to store LangGraph checkpoints. Vulnerability reports are stored
  separately as JSON files.
- ChromaDB, RAG, multi-agent supervisors, multi-user concurrency, and task queues are
  outside the first-version scope.
