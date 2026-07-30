# VulnAgent-V2 Release Notes

## v0.4.0 - Reports Package and IDA Backend Improvements

### Highlights

- Reconstructed the missing `vulnagent/reports` Python package with report models (`BinaryVulnerabilityReport`, `VulnerabilityFinding`, `CandidateFindingRecord`, `SampleInfo`), JSON artifact storage (`FileReportStore`), and FastAPI report router (`build_report_router`).
- Resolved `ModuleNotFoundError: No module named 'vulnagent.reports'` that prevented the API server and IDA backend from starting.
- Included `delink/` firmware decryption tool source for convenience.

### Bug Fixes

- Fixed import chain failure caused by the absent `vulnagent/reports` package referenced throughout the agent, harness, storage, and API layers.

## v0.2.0 - Agent Console and Harness Release

This release upgrades VulnAgent from a primarily Streamlit-based prototype into a more complete Agent application with a React console, Harness runtime, persistent traces, and improved chat experience.

### Highlights

- Added a React + Vite frontend console for Agent Chat, findings, sources, and Harness trace views.
- Added FastAPI application API for the React frontend, including health, reports, runs, functions, chat, and baseline scan endpoints.
- Added Agent Harness runtime to unify `agent_chat` and `baseline_scan` execution, result objects, trace events, and SQLite persistence.
- Added Harness run and trace persistence in SQLite, with CLI/API/UI query support.
- Added structured frontend chat rendering:
  - Markdown assistant responses.
  - Tool call cards.
  - Tool result cards.
  - Tool Calls visibility toggle.
- Added chat history loading from SQLite through `/api/chats/{thread_id}/messages`.
- Improved frontend layout:
  - Fixed chat input area.
  - Sticky Investigation State side panel.
  - Recent Harness Runs and Trace Timeline panels.
  - Topbar overlap fixes.
  - Sidebar visual style cleanup.
- Added CORS support for dynamic Vite development ports.

### Backend and Agent Changes

- Introduced `vulnagent.api` as the application API layer for the React frontend.
- Introduced `vulnagent.cli` command routing for API/server entry points.
- Added Harness schemas and runtime modules under `vulnagent/harness`.
- Extended SQLite storage for Harness runs, trace events, chat history, tool events, and investigation state.
- Improved provider-safe message serialization for frontend display.

### Frontend Changes

- Added `frontend/` React app.
- Added `react-markdown` and `remark-gfm` for Markdown rendering.
- Added API client and TypeScript models for reports, runs, chats, messages, and function context.
- Reworked Agent Chat layout to behave more like a normal Agent console.

### Validation

- `npm run build`
- `python -m compileall -q vulnagent`
- FastAPI TestClient check for chat history endpoints.
- Playwright smoke checks for:
  - Page load.
  - Topbar overlap.
  - Sidebar styling.
  - Tool Calls toggle.
  - Chat input visibility.
  - Sticky Investigation State panel.

