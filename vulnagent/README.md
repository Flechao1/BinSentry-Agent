# VulnAgent

`vulnagent` is a standalone Web/CGI firmware binary vulnerability analysis project.
IDA runs as a separate HTTP service. The React UI communicates with the VulnAgent
application API and persists analysis history in SQLite. JSON report artifacts remain
available for export and interoperability.

## Install

Create a Python environment for the UI:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r vulnagent/requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r vulnagent\requirements.txt
```

Copy the workspace `.env.example` file to `.env` and fill in the LLM API key if the
defaults need to change.

## Quick Start

Run from the workspace root. Start the IDA backend first, then the application API and
the React UI.

### 1. Configure LLM

Create or update `.env`:

```env
DEEPSEEK_API_KEY=your-api-key
DEEPSEEK_API_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
LLM_TEMPERATURE=0.0

IDA_BACKEND_URL=http://127.0.0.1:8765
VULN_DB_PATH=./data/vulnagent.db
```

LLM configuration is only required for Agent Chat. Baseline Scan and function browsing
can run without an LLM key.

### 2. Start IDA Backend

Read-only analysis mode:

```powershell
python -m vulnagent --idb "E:\PythonCode\LATTE_Reproduction\dataset\CVE-2022-43000-dir-816-goahead.i64" --host 127.0.0.1 --port 8765 --read-only
```

Writable mode for confirmed IDB modifications:

```powershell
python -m vulnagent --idb "E:\path\to\sample.i64" --host 127.0.0.1 --port 8765
```

Keep the backend terminal open. If port `8765` is already occupied, either stop the old
process or start on a different port and update `IDA_BACKEND_URL`.

### 3. Start the application API

Open a second terminal from the workspace root:

```powershell
python -m vulnagent api --host 127.0.0.1 --port 8787
```

### 4. Start the React UI

Open a third terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

The UI connects to `http://127.0.0.1:8787` by default. In the sidebar, confirm that
the IDA backend is `Connected`.

### 5. Typical Workflow

1. Open the UI and check that the backend status is `Connected`.
2. Click `Start Baseline Scan` to discover routes, Sources, and dangerous Sinks.
3. The scan automatically traces the arguments of its highest-priority sink candidates
   and classifies them as `verified`, `unverified`, or `rejected`.
4. Review the `Candidate Findings` view for evidence and missing validation steps.
5. In `Agent Chat`, create or select an investigation session before asking focused
   follow-up questions. Sessions retain their messages, tool events, summary, and
   investigation state in SQLite; they can be renamed, cleared, or deleted from the
   sidebar.

Useful Agent Chat prompts:

```text
请总结当前样本中已发现的 Web 路由、Source 候选和危险 Sink。
请扫描可能的用户输入 Source，并区分确认的 source 和候选 source。
请分析 0x4055b8 的调用者、被调用函数、字符串和可疑参数来源。
请围绕 system 调用追踪参数来源，并说明还缺少哪些证据。
请根据当前 Baseline Scan 结果给出下一步漏洞验证计划。
```

### 5. Run Tests

```powershell
python -m compileall -q vulnagent
python -m unittest vulnagent.tests.test_vulnerability_workflow
```

## Documentation

- [Development Plan](docs/DEVELOPMENT_PLAN.md)
- [Resume Project Description](docs/RESUME_PROJECT.md)

## Project Structure

```text
vulnagent/
  agent/          LangGraph orchestration, baseline scanning, memory, and guardrails
  clients/        Synchronous and asynchronous IDA HTTP clients
  docs/           Project plan and resume-ready technical description
  ida/            FastAPI IDA service, IDALib backend, and protocol schemas
  integrations/   Optional agent-service-toolkit adapter
  reports/        Structured report models and JSON artifact storage
  rules/          Dangerous sink definitions
  skills/         Domain audit playbook injected into the Agent prompt
  storage/        SQLite persistence and schema initialization
  tests/          Workflow regression tests
  tools/          LangChain IDA tools and controlled write adapters
  ui/             Streamlit analysis workspace
```

## IDA Backend

Start one backend for one active sample:

```bash
python -m vulnagent --idb /path/to/sample.i64 --host 127.0.0.1 --port 8765
```

Use `--read-only` when IDB mutation is not needed.

## Standalone UI

Start the UI from the workspace root:

```bash
python -m streamlit run vulnagent/ui/app.py
```

Open `http://127.0.0.1:8501`. The page shows the active sample, IDA architecture,
scan limits, baseline scan progress, findings, routes, source candidates, saved JSON
reports, persistent Agent chat history, and a function decompiler view.

The standalone UI performs deterministic scanning and does not require an LLM API key.

## LLM Agent Chat

Configure DeepSeek in the workspace `.env` file:

```env
DEEPSEEK_API_KEY=your-new-api-key
DEEPSEEK_API_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
LLM_TEMPERATURE=0.0
```

Open the `Agent Chat` view in the standalone UI. The Agent uses LangGraph and read-only
IDA tools to answer questions such as:

```text
Find Web route handlers and summarize the exposed endpoints.
List dangerous command execution sinks using a bounded scan.
Decompile 0x4055b8 and explain its callers and callees.
Trace the first argument of a system call toward likely user-input sources.
```

The API key is read from the local environment and is not displayed in the UI.

The React frontend also provides `Model Settings`. It can apply a runtime override
for the provider, model, base URL, temperature, and output-token budget. An empty API
key keeps the current key from `.env`; runtime overrides are cleared when the API
process restarts or when `Reset to .env` is selected.

## Known Vulnerability Intelligence

VulnAgent includes a read-only vulnerability intelligence module for correlating
firmware evidence with public references. It searches CVE.org website-backed data,
NVD, and GitHub first and then applies deterministic matching scores; the LLM can
explain the result, but it should not invent CVE IDs from memory.

Agent-facing tool:

```text
search_vulnerability_intel
```

CLI example:

```bash
python -m vulnagent intel \
  --vendor "D-Link" \
  --product "DIR-882" \
  --firmware-version "1.30B06" \
  --component "lighttpd" \
  --vuln-type "command injection" \
  --route "/dws/api/" \
  --sink "system" \
  --symbols "set_ws_action,check_dws_cookie" \
  --sources "cveorg,nvd,github"
```

Application API endpoint:

```text
POST /api/intel/search
```

Optional environment variables:

```env
# CVE.org website-backed lookup does not require a token.
NVD_API_KEY=your-nvd-api-key
GITHUB_TOKEN=your-github-token
```

Use this after a candidate or confirmed finding exists. The output distinguishes
strong matches from weak keyword overlap and includes matched terms, scoring reasons,
source URLs, and lookup errors.

## SQLite Storage

SQLite is enabled by default without an additional service or Python dependency:

```env
VULN_DB_PATH=./data/vulnagent.db
```

The database stores sample metadata, scan runs, findings, Agent chat threads, complete
LangChain messages, and tool invocation events. IDA databases and exported JSON reports
remain separate files. The Streamlit sidebar shows the active database and lets you
switch, create, or clear investigation chats.

## Short-Term Agent Memory

The standalone Agent keeps the complete conversation in SQLite, but sends a bounded
context to the LLM. Older turns are compacted into a semantic investigation summary
when an LLM is configured; if summarization fails, the Agent falls back to the
deterministic rule summary so chat execution remains non-fatal. Recent turns remain
detailed, oversized historical tool outputs are clipped only in the LLM context copy,
and structured investigation state is injected into each model call. Tool results and
Baseline Scan reports are parsed into a bounded evidence index containing confirmed
routes, source candidates, confirmed sources, pending sinks, verified findings, and
missing evidence. Full tool output remains in SQLite; only the compact index is
injected into the prompt.

Agent-facing IDA tools return `vulnagent.tool_result.v1` JSON with a readable `text`
field plus structured evidence fields such as `confirmed_sources`, `pending_sinks`,
`missing_evidence`, and `function_notes`. Context construction consumes those fields
directly and falls back to legacy text parsing only for old chat history.

The default context budget can be adjusted in `.env`:

```env
VULN_CONTEXT_RECENT_TURNS=8
VULN_CONTEXT_MAX_INPUT_TOKENS=12000
VULN_CONTEXT_SUMMARY_TOKENS=1200
VULN_CONTEXT_STATE_TOKENS=1200
VULN_CONTEXT_RECENT_TOKENS=7200
VULN_CONTEXT_RESPONSE_RESERVE_TOKENS=2400
VULN_CONTEXT_MAX_MESSAGE_TOKENS=1800
VULN_CONTEXT_SEMANTIC_SUMMARY=true
```

This stage intentionally does not use embeddings, a vector database, or RAG.

## Agent Execution Limits

Each conversational turn has hard execution limits. The Agent rejects repeated tool
calls, executes IDA tools sequentially, and stops with a focused follow-up prompt when
the budget is exhausted:

```env
VULN_AGENT_MAX_TOOL_CALLS=48
VULN_AGENT_MAX_TOOL_LOOPS=24
VULN_AGENT_MAX_TOOL_CALLS_PER_BATCH=8
VULN_AGENT_MAX_DECOMPILE_CALLS=20
VULN_AGENT_MAX_DECOMPILE_CALLS_PER_BATCH=1
VULN_AGENT_MAX_SCAN_CALLS=16
VULN_AGENT_MAX_SCAN_CALLS_PER_BATCH=1
VULN_AGENT_MAX_TAINT_TRACE_CALLS=16
VULN_AGENT_MAX_TAINT_TRACE_CALLS_PER_BATCH=2
VULN_AGENT_MAX_TURN_SECONDS=300
VULN_AGENT_TOOL_TIMEOUT_SECONDS=60
VULN_AGENT_MODEL_TIMEOUT_SECONDS=90
```

The Agent uses a tool-call scheduler rather than a user-intent classifier. It evaluates
the actual tool calls emitted by the model, executes a bounded useful subset, returns
skipped calls as tool errors, and then forces a final answer from completed evidence
when a policy boundary is reached.

## Optional LangGraph Agent

The reusable Agent components remain available for conversational analysis. Configure
the process that hosts the LangGraph Agent:

```env
IDA_BACKEND_URL=http://127.0.0.1:8765
IDA_BACKEND_TIMEOUT=120
VULN_REPORT_DIR=./reports
VULN_ENABLE_IDB_WRITES=false
```

Keep `VULN_ENABLE_IDB_WRITES=false` unless the host UI supports LangGraph interrupt
resumption. When enabled, rename and save tools still require explicit confirmation.

### Controlled Binary / IDB Modification

Writable mode is intentionally opt-in. Start the IDA backend without `--read-only`,
enable write tools only in a host that supports LangGraph interrupts, and save patched
databases to a copy when possible:

```env
VULN_ENABLE_IDB_WRITES=true
```

Supported confirmed write operations:

- Rename a function.
- Set a function comment with an analysis reason.
- Patch exact bytes, optionally guarded by `expected_original_hex`.
- Replace a byte range with NOP bytes.
- Patch supported conditional jumps: x86 short/near Jcc and MIPS `beq`/`bne`.
- Save the active IDA database.

The Agent can only request these mutations. The write tools pause with a confirmation
payload before execution, and the backend refuses mutation when it was started in
read-only mode.

### Register in agent-service-toolkit

The workspace already includes an optional `agent-service-toolkit` adapter. A separate
host can register it with:

```python
from vulnagent.integrations.agent_service_toolkit import (
    build_toolkit_binary_vulnerability_agent,
)
```

### Baseline Scan Workflow

Invoke the registered Agent with:

```python
agent_config={"workflow": "baseline_scan"}
```

The graph performs bounded Web/CGI discovery, source propagation, sink scanning, taint
tracing for the top-priority sink candidates, and JSON/SQLite report persistence. Each
candidate is classified as `verified`, `unverified`, or `rejected` with its evidence and
missing proof recorded. Without that workflow flag, the same graph acts as a
conversational read-only reverse-engineering assistant.
