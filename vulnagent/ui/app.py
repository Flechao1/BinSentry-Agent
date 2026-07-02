"""Standalone Streamlit interface for binary vulnerability analysis."""

from __future__ import annotations

import asyncio
import html
import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from dotenv import load_dotenv
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage

from vulnagent.agent.baseline_scan import BaselineScanConfig, ScanProgress
from vulnagent.agent.context_builder import ContextBudget
from vulnagent.agent import execution_limits as agent_limits
from vulnagent.agent.llm import get_llm_status
from vulnagent.clients.ida_client import IdaClient
from vulnagent.harness import (
    BinaryVulnAgentHarness,
    HarnessBaselineScanRequest,
    HarnessTurnRequest,
)
from vulnagent.reports import BinaryVulnerabilityReport, FileReportStore
from vulnagent.reports.store import REPORT_ID_RE
from vulnagent.storage import SqliteVulnRepository


load_dotenv()

APP_TITLE = "VulnAgent"
DEFAULT_BACKEND_URL = os.getenv("IDA_BACKEND_URL", "http://127.0.0.1:8765")
DEFAULT_TIMEOUT = float(os.getenv("IDA_BACKEND_TIMEOUT", "120"))
DEFAULT_REPORT_DIR = os.getenv("VULN_REPORT_DIR", "./reports")
DEFAULT_DB_PATH = os.getenv("VULN_DB_PATH", "./data/vulnagent.db")
AGENT_PROMPT_SUGGESTIONS = [
    "Find Web route handlers and summarize the exposed endpoints.",
    "Run a bounded sink scan for command execution risks.",
    "List imported dangerous functions and prioritize investigation targets.",
    "Find likely user-input source functions and explain the evidence.",
]
DECOMPILE_TOOLS = agent_limits.DECOMPILE_TOOLS
DISCOVERY_SCAN_TOOLS = getattr(
    agent_limits,
    "DISCOVERY_SCAN_TOOLS",
    getattr(agent_limits, "SCAN_TOOLS", set()),
)
TAINT_TRACE_TOOLS = getattr(agent_limits, "TAINT_TRACE_TOOLS", set())


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --va-ink: #111827;
            --va-ink-soft: #334155;
            --va-muted: #667085;
            --va-line: #dde3ea;
            --va-line-strong: #c6d0dc;
            --va-panel: #ffffff;
            --va-canvas: #f4f6f8;
            --va-sidebar: #0f172a;
            --va-sidebar-soft: #151f34;
            --va-sidebar-line: #25324a;
            --va-sidebar-muted: #94a3b8;
            --va-accent: #b4232d;
            --va-accent-dark: #8f1d25;
            --va-accent-soft: #fff1f2;
            --va-green: #15803d;
            --va-green-bg: #dcfce7;
            --va-amber: #a16207;
            --va-amber-bg: #fef3c7;
            --va-red-bg: #fee2e2;
            --va-blue: #2563eb;
            --va-blue-bg: #dbeafe;
            --va-gold: #b78b35;
        }
        [data-testid="stAppViewContainer"] {
            background: var(--va-canvas);
            color: var(--va-ink);
        }
        [data-testid="stHeader"] {
            background: rgba(244, 246, 248, 0.94);
            border-bottom: 1px solid rgba(198, 208, 220, 0.55);
        }
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
            border-right: 1px solid var(--va-sidebar-line);
            color: #e5e7eb;
        }
        [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
            gap: 0.65rem;
        }
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] span,
        [data-testid="stSidebar"] small,
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
            color: #cbd5e1;
        }
        [data-testid="stSidebar"] [data-testid="stExpander"] {
            background: rgba(255, 255, 255, 0.045);
            border: 1px solid var(--va-sidebar-line);
            box-shadow: none;
        }
        [data-testid="stSidebar"] [data-baseweb="input"],
        [data-testid="stSidebar"] [data-baseweb="select"] > div {
            background: #0b1220;
            border-color: #2b3a55;
        }
        [data-testid="stSidebar"] input {
            color: #f8fafc;
        }
        [data-testid="stSidebar"] .stButton button {
            min-height: 2.35rem;
            background: rgba(255, 255, 255, 0.04);
            border-color: #334155;
            color: #e5e7eb;
        }
        [data-testid="stSidebar"] .stButton button:hover {
            background: rgba(255, 255, 255, 0.08);
            border-color: #64748b;
            color: #ffffff;
        }
        .block-container {
            max-width: 1540px;
            padding-top: 1.1rem;
            padding-bottom: 2.5rem;
        }
        h1, h2, h3 {
            color: var(--va-ink);
            letter-spacing: 0;
        }
        h2 {
            font-size: 1.3rem;
        }
        h3 {
            font-size: 1.02rem;
        }
        .stButton button,
        .stDownloadButton button,
        [data-baseweb="input"],
        [data-baseweb="select"] > div,
        [data-testid="stExpander"],
        [data-testid="stAlert"],
        [data-testid="stMetric"],
        [data-testid="stChatMessage"] {
            border-radius: 6px !important;
        }
        .stButton button,
        .stDownloadButton button {
            border-color: var(--va-line-strong);
            color: var(--va-ink-soft);
            font-weight: 650;
            transition: border-color 150ms ease, background 150ms ease, color 150ms ease;
        }
        .stButton button:hover,
        .stDownloadButton button:hover {
            border-color: var(--va-gold);
            color: var(--va-ink);
            background: #fbfcfb;
        }
        .stButton button[kind="primary"] {
            background: var(--va-accent);
            border-color: var(--va-accent);
            color: #ffffff;
            box-shadow: 0 8px 20px rgba(180, 35, 45, 0.16);
        }
        .stButton button[kind="primary"]:hover {
            background: var(--va-accent-dark);
            border-color: var(--va-accent-dark);
            color: #ffffff;
        }
        [data-baseweb="input"]:focus-within,
        [data-baseweb="select"] > div:focus-within {
            border-color: var(--va-gold);
            box-shadow: 0 0 0 1px rgba(168, 138, 82, 0.24);
        }
        [data-baseweb="button-group"] button[aria-pressed="true"] {
            background: var(--va-ink);
            border-color: var(--va-ink);
            color: #ffffff;
        }
        [data-testid="stMetricLabel"] {
            color: var(--va-muted);
        }
        [data-testid="stMetricValue"] {
            color: var(--va-ink);
        }
        [data-testid="stChatMessage"] {
            padding: 0.78rem 0.95rem;
            margin-bottom: 0.55rem;
            background: var(--va-panel);
            border: 1px solid var(--va-line);
            box-shadow: 0 1px 2px rgba(17, 24, 39, 0.035);
        }
        [data-testid="stChatInput"] {
            border-color: var(--va-line-strong);
        }
        [data-testid="stDataFrame"] {
            border: 1px solid var(--va-line);
            border-radius: 6px;
            overflow: hidden;
        }
        hr {
            border-color: var(--va-line);
        }
        .va-brand {
            display: flex;
            align-items: center;
            gap: 0.7rem;
            padding: 0.2rem 0 0.7rem;
            border-bottom: 1px solid var(--va-sidebar-line);
        }
        .va-brand-mark {
            display: grid;
            width: 2.45rem;
            height: 2.45rem;
            place-items: center;
            border-radius: 6px;
            background: linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%);
            color: #ffffff;
            font-size: 0.72rem;
            font-weight: 800;
            box-shadow: inset 0 -2px 0 rgba(255, 255, 255, 0.15), 0 8px 18px rgba(0, 0, 0, 0.25);
        }
        .va-brand-name {
            color: #f8fafc;
            font-size: 1.05rem;
            font-weight: 750;
            line-height: 1.1;
        }
        .va-brand-subtitle,
        .va-kicker,
        .va-sidebar-heading {
            color: var(--va-muted);
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
        }
        .va-page-header {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 1.05rem;
            padding: 1rem 0 0.35rem;
        }
        .va-page-title {
            margin: 0.1rem 0 0;
            color: var(--va-ink);
            font-size: 2.05rem;
            font-weight: 760;
            line-height: 1.1;
        }
        .va-page-subtitle {
            margin-top: 0.35rem;
            color: var(--va-muted);
            font-size: 0.88rem;
        }
        .va-workspace-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            margin: 1.1rem 0 0.8rem;
            padding-bottom: 0.65rem;
            border-bottom: 1px solid var(--va-line);
        }
        .va-workspace-header::after {
            width: 2.2rem;
            height: 2px;
            margin-left: auto;
            content: "";
            background: var(--va-gold);
        }
        .va-workspace-title {
            margin: 0.08rem 0 0;
            color: var(--va-ink);
            font-size: 1.35rem;
            font-weight: 740;
        }
        .va-inline-status {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.55rem;
            padding: 0.48rem 0.62rem;
            border: 1px solid var(--va-sidebar-line);
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.045);
            color: #e5e7eb;
            font-size: 0.82rem;
            font-weight: 650;
        }
        .va-inline-status + .va-inline-status {
            margin-top: 0.35rem;
        }
        .va-pill {
            display: inline-flex;
            align-items: center;
            gap: 0.28rem;
            border-radius: 999px;
            padding: 0.16rem 0.48rem;
            font-size: 0.68rem;
            font-weight: 750;
        }
        .va-pill::before {
            width: 0.42rem;
            height: 0.42rem;
            border-radius: 50%;
            content: "";
            background: currentColor;
        }
        .va-pill-ok {
            background: var(--va-green-bg);
            color: var(--va-green);
        }
        .va-pill-warn {
            background: var(--va-amber-bg);
            color: var(--va-amber);
        }
        .va-pill-error {
            background: var(--va-red-bg);
            color: var(--va-accent);
        }
        .va-sidebar-heading {
            margin: 0.65rem 0 0.2rem;
            color: #94a3b8;
        }
        .va-meta-stack {
            color: var(--va-sidebar-muted);
            font-size: 0.74rem;
            line-height: 1.65;
            padding: 0.6rem 0.65rem;
            border: 1px solid var(--va-sidebar-line);
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.035);
        }
        .va-status-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.8rem;
            margin: 0.7rem 0 1rem;
        }
        .va-status-card {
            min-height: 6.3rem;
            padding: 0.9rem 1rem;
            border: 1px solid var(--va-line);
            border-left: 3px solid var(--va-line-strong);
            border-radius: 6px;
            background: var(--va-panel);
            box-shadow: 0 8px 24px rgba(17, 24, 39, 0.045);
        }
        .va-status-card-ok {
            border-left-color: var(--va-green);
        }
        .va-status-card-warn {
            border-left-color: var(--va-amber);
        }
        .va-status-card-error {
            border-left-color: var(--va-accent);
        }
        .va-status-card-info {
            border-left-color: var(--va-blue);
        }
        .va-status-label {
            color: var(--va-muted);
            font-size: 0.72rem;
            font-weight: 720;
            text-transform: uppercase;
            letter-spacing: 0;
        }
        .va-status-value {
            margin-top: 0.48rem;
            color: var(--va-ink);
            font-size: 1.58rem;
            font-weight: 760;
            line-height: 1.1;
        }
        .va-status-sub {
            margin-top: 0.45rem;
            color: var(--va-muted);
            font-size: 0.76rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .va-chat-empty {
            margin: 0.2rem 0 0.8rem;
            padding: 0.85rem 1rem;
            border: 1px solid var(--va-line);
            border-radius: 6px;
            background: #f8fafc;
            color: var(--va-ink-soft);
            font-size: 0.86rem;
        }
        .va-side-panel {
            position: sticky;
            top: 4.2rem;
        }
        .va-panel-card {
            margin-bottom: 0.85rem;
            padding: 0.85rem 0.9rem;
            border: 1px solid var(--va-line);
            border-radius: 6px;
            background: var(--va-panel);
            box-shadow: 0 8px 24px rgba(17, 24, 39, 0.04);
        }
        .va-panel-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            margin-bottom: 0.65rem;
            color: var(--va-ink);
            font-size: 0.82rem;
            font-weight: 760;
        }
        .va-panel-kv {
            display: grid;
            grid-template-columns: minmax(5.5rem, 0.8fr) minmax(0, 1.2fr);
            gap: 0.42rem 0.65rem;
            color: var(--va-ink-soft);
            font-size: 0.76rem;
            line-height: 1.35;
        }
        .va-panel-kv span:nth-child(odd) {
            color: var(--va-muted);
        }
        .va-mini-list {
            display: flex;
            flex-direction: column;
            gap: 0.38rem;
        }
        .va-mini-item {
            padding: 0.44rem 0.5rem;
            border: 1px solid #e5eaf0;
            border-radius: 6px;
            background: #f8fafc;
            color: var(--va-ink-soft);
            font-size: 0.74rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .va-mini-empty {
            color: var(--va-muted);
            font-size: 0.76rem;
        }
        .va-budget-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.45rem;
        }
        .va-budget-item {
            padding: 0.55rem;
            border: 1px solid #e5eaf0;
            border-radius: 6px;
            background: #f8fafc;
        }
        .va-budget-label {
            color: var(--va-muted);
            font-size: 0.66rem;
            font-weight: 720;
            text-transform: uppercase;
        }
        .va-budget-value {
            margin-top: 0.18rem;
            color: var(--va-ink);
            font-size: 1rem;
            font-weight: 760;
        }
        .va-tool-card {
            margin: 0.35rem 0 0.45rem;
            padding: 0.62rem 0.72rem;
            border: 1px solid #dbe4ee;
            border-left: 3px solid var(--va-blue);
            border-radius: 6px;
            background: #f8fafc;
        }
        .va-tool-card-result {
            border-left-color: var(--va-green);
        }
        .va-run-item {
            width: 100%;
            margin: 0.35rem 0;
            padding: 0.5rem 0.55rem;
            border: 1px solid #e5eaf0;
            border-left: 3px solid var(--va-blue);
            border-radius: 6px;
            background: #f8fafc;
            color: var(--va-ink-soft);
            font-size: 0.74rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .va-run-item-failed {
            border-left-color: var(--va-accent);
            background: #fff7f7;
        }
        .va-trace-item {
            position: relative;
            margin: 0 0 0.45rem 0.35rem;
            padding: 0.48rem 0.55rem 0.48rem 0.72rem;
            border-left: 2px solid var(--va-line-strong);
            background: #f8fafc;
            border-radius: 0 6px 6px 0;
            color: var(--va-ink-soft);
            font-size: 0.74rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .va-trace-item::before {
            position: absolute;
            top: 0.7rem;
            left: -0.32rem;
            width: 0.55rem;
            height: 0.55rem;
            border-radius: 50%;
            content: "";
            background: var(--va-blue);
            border: 2px solid #ffffff;
        }
        .va-trace-item-failed::before {
            background: var(--va-accent);
        }
        .va-trace-type {
            color: var(--va-ink);
            font-weight: 760;
        }
        .va-trace-meta {
            margin-top: 0.18rem;
            color: var(--va-muted);
            font-size: 0.68rem;
        }
        .va-tool-title {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            color: var(--va-ink);
            font-size: 0.8rem;
            font-weight: 760;
        }
        .va-tool-subtitle {
            margin-top: 0.25rem;
            color: var(--va-muted);
            font-size: 0.72rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }
        .va-report-hero {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 1rem;
            align-items: start;
            margin-bottom: 0.9rem;
            padding: 1rem;
            border: 1px solid var(--va-line);
            border-radius: 6px;
            background: var(--va-panel);
            box-shadow: 0 8px 24px rgba(17, 24, 39, 0.04);
        }
        .va-report-title {
            color: var(--va-ink);
            font-size: 1.08rem;
            font-weight: 760;
        }
        .va-report-meta {
            margin-top: 0.3rem;
            color: var(--va-muted);
            font-size: 0.78rem;
            overflow-wrap: anywhere;
        }
        .va-finding-card {
            margin-bottom: 0.75rem;
            padding: 0.85rem 0.95rem;
            border: 1px solid var(--va-line);
            border-left: 3px solid var(--va-amber);
            border-radius: 6px;
            background: var(--va-panel);
        }
        .va-finding-card-high,
        .va-finding-card-critical {
            border-left-color: var(--va-accent);
        }
        .va-finding-card-low {
            border-left-color: var(--va-blue);
        }
        .va-finding-head {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 0.75rem;
        }
        .va-finding-title {
            color: var(--va-ink);
            font-size: 0.94rem;
            font-weight: 760;
            line-height: 1.35;
        }
        .va-finding-meta {
            margin-top: 0.35rem;
            color: var(--va-muted);
            font-size: 0.76rem;
        }
        @media (max-width: 720px) {
            .block-container {
                padding-top: 0.75rem;
            }
            .va-status-grid {
                grid-template-columns: 1fr;
            }
            .va-side-panel {
                position: static;
            }
            .va-report-hero,
            .va-finding-head {
                grid-template-columns: 1fr;
                flex-direction: column;
            }
            .va-page-header,
            .va-workspace-header {
                align-items: flex-start;
                flex-direction: column;
            }
            .va-page-title {
                font-size: 1.55rem;
            }
            .va-workspace-header::after {
                margin-left: 0;
            }
        }
        @media (min-width: 721px) and (max-width: 1180px) {
            .va-status-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_brand() -> None:
    st.markdown(
        """
        <div class="va-brand">
            <div class="va-brand-mark">VA</div>
            <div>
                <div class="va-brand-name">VulnAgent</div>
                <div class="va-brand-subtitle">IDA Agent Workspace</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_inline_status(label: str, state: str, detail: str) -> None:
    st.markdown(
        (
            '<div class="va-inline-status">'
            f"<span>{html.escape(label)}</span>"
            f'<span class="va-pill va-pill-{html.escape(state)}">'
            f"{html.escape(detail)}</span>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def _render_page_header() -> None:
    st.markdown(
        """
        <div class="va-page-header">
            <div>
                <div class="va-kicker">Firmware security workspace</div>
                <h1 class="va-page-title">VulnAgent Analysis Console</h1>
                <div class="va-page-subtitle">IDA-backed vulnerability triage, evidence tracking, and Agent investigation</div>
            </div>
            <span class="va-pill va-pill-ok">Read-only analysis</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_workspace_header(kicker: str, title: str, detail: str = "") -> None:
    detail_html = (
        f'<span class="va-pill va-pill-ok">{html.escape(detail)}</span>' if detail else ""
    )
    st.markdown(
        (
            '<div class="va-workspace-header"><div>'
            f'<div class="va-kicker">{html.escape(kicker)}</div>'
            f'<div class="va-workspace-title">{html.escape(title)}</div>'
            f"</div>{detail_html}</div>"
        ),
        unsafe_allow_html=True,
    )


def _report_store() -> FileReportStore:
    return FileReportStore(st.session_state.get("report_dir", DEFAULT_REPORT_DIR))


def _repository() -> SqliteVulnRepository:
    return SqliteVulnRepository(st.session_state.get("db_path", DEFAULT_DB_PATH))


def _harness() -> BinaryVulnAgentHarness:
    return BinaryVulnAgentHarness(
        repository=_repository(),
        timeout=DEFAULT_TIMEOUT,
    )


def _ida_client() -> IdaClient:
    return IdaClient(
        st.session_state.get("backend_url", DEFAULT_BACKEND_URL),
        timeout=DEFAULT_TIMEOUT,
    )


def _load_report(report_id: str) -> BinaryVulnerabilityReport | None:
    if not report_id:
        return None
    try:
        return _report_store().load(report_id)
    except (FileNotFoundError, ValueError):
        try:
            return _repository().load_report(report_id)
        except (FileNotFoundError, ValueError):
            return None


def _available_reports() -> list[str]:
    report_dir = _report_store().report_dir
    file_report_ids = (
        sorted(
            (
            path.stem
            for path in report_dir.glob("*.json")
            if REPORT_ID_RE.fullmatch(path.stem)
            ),
            reverse=True,
        )
        if report_dir.is_dir()
        else []
    )
    database_report_ids = [run["id"] for run in _repository().list_scan_runs()]
    return list(dict.fromkeys([*database_report_ids, *file_report_ids]))


def _get_backend_status() -> dict[str, Any]:
    try:
        client = _ida_client()
        health = client.validate_protocol()
        arch = client.detect_arch()
        return {
            "connected": True,
            "database": health.database,
            "writable": health.writable,
            "protocol_version": health.protocol_version,
            "architecture": arch.arch,
            "bits": arch.bits,
            "endian": arch.endian,
        }
    except Exception as exc:  # noqa: BLE001 - surface backend failures in the UI
        return {
            "connected": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _scan_config() -> BaselineScanConfig:
    return BaselineScanConfig(
        source_limit=st.session_state.source_limit,
        source_min_score=st.session_state.source_min_score,
        sink_max_depth=st.session_state.sink_max_depth,
        sink_max_functions=st.session_state.sink_max_functions,
        taint_max_depth=st.session_state.taint_max_depth,
        max_findings=st.session_state.max_findings,
    )


async def _run_baseline_scan(
    progress_callback,
) -> BinaryVulnerabilityReport:
    result = await _harness().run_baseline_scan(
        HarnessBaselineScanRequest(
            thread_id=st.session_state.get("active_chat_thread_id", ""),
            ida_backend_url=st.session_state.backend_url,
            report_dir=st.session_state.report_dir,
            config=_scan_config(),
        ),
        progress_callback=progress_callback,
    )
    if result.status != "completed" or result.report is None:
        raise RuntimeError(result.error or "Baseline scan failed")
    st.session_state.active_harness_run_id = result.run_id
    return result.report


def _start_scan() -> None:
    status = st.status("Starting baseline scan", expanded=True)

    def report_progress(progress: ScanProgress) -> None:
        status.update(label=progress.message, state="running")
        status.write({"stage": progress.stage, **progress.data})

    try:
        report = asyncio.run(_run_baseline_scan(report_progress))
    except Exception as exc:  # noqa: BLE001 - surface scanner failures in the UI
        status.update(label="Baseline scan failed", state="error")
        status.error(f"{type(exc).__name__}: {exc}")
        return

    status.update(label="Baseline scan complete", state="complete", expanded=False)
    st.session_state.active_report_id = report.report_id
    st.session_state.workspace_mode = "Analysis Workspace"
    st.session_state.analysis_view = "Report"


def _upsert_active_sample(status: dict[str, Any]) -> str | None:
    if not status["connected"]:
        return st.session_state.get("active_sample_id")
    sample_id = _repository().upsert_sample(
        status["database"],
        architecture=status["architecture"],
        bits=status["bits"],
        endian=status["endian"],
    )
    st.session_state.active_sample_id = sample_id
    return sample_id


def _ensure_active_chat_thread(sample_id: str | None) -> str:
    repository = _repository()
    thread_id = st.session_state.get("active_chat_thread_id")
    thread = repository.get_chat_thread(thread_id) if thread_id else None
    if thread is None or thread["sample_id"] != sample_id:
        threads = repository.list_chat_threads(sample_id=sample_id)
        thread_id = (
            threads[0]["id"]
            if threads
            else repository.create_chat_thread(sample_id=sample_id)
        )
        st.session_state.active_chat_thread_id = thread_id
    if st.session_state.get("loaded_chat_thread_id") != thread_id:
        st.session_state.agent_messages = repository.load_chat_messages(thread_id)
        st.session_state.loaded_chat_thread_id = thread_id
    return thread_id


def _render_chat_history(sample_id: str | None) -> None:
    repository = _repository()
    thread_id = _ensure_active_chat_thread(sample_id)
    st.markdown('<div class="va-sidebar-heading">Investigation chats</div>', unsafe_allow_html=True)
    if st.button(":material/add: New Agent Chat", width="stretch"):
        thread_id = repository.create_chat_thread(sample_id=sample_id)
        st.session_state.active_chat_thread_id = thread_id
        st.session_state.loaded_chat_thread_id = thread_id
        st.session_state.agent_messages = []
        st.rerun()

    threads = repository.list_chat_threads(sample_id=sample_id)
    thread_by_id = {thread["id"]: thread for thread in threads}
    thread_ids = list(thread_by_id)
    selected = st.selectbox(
        "Agent Chats",
        options=thread_ids,
        index=thread_ids.index(thread_id),
        format_func=lambda item: thread_by_id[item]["title"],
    )
    if selected != thread_id:
        st.session_state.active_chat_thread_id = selected
        st.session_state.loaded_chat_thread_id = selected
        st.session_state.agent_messages = repository.load_chat_messages(selected)
        st.rerun()
    if st.button(":material/delete: Clear Agent Chat", width="stretch"):
        repository.clear_chat_thread(thread_id)
        st.session_state.agent_messages = []
        st.rerun()


def _render_sidebar() -> dict[str, Any]:
    with st.sidebar:
        _render_brand()
        with st.expander(":material/settings: Connections & Storage"):
            st.session_state.backend_url = st.text_input(
                "IDA Backend",
                value=st.session_state.get("backend_url", DEFAULT_BACKEND_URL),
            ).rstrip("/")
            st.session_state.report_dir = st.text_input(
                "Report Directory",
                value=st.session_state.get("report_dir", DEFAULT_REPORT_DIR),
            )
            st.session_state.db_path = st.text_input(
                "SQLite Database",
                value=st.session_state.get("db_path", DEFAULT_DB_PATH),
            )

        status = _get_backend_status()
        sample_id = _upsert_active_sample(status)
        st.markdown('<div class="va-sidebar-heading">Runtime status</div>', unsafe_allow_html=True)
        if status["connected"]:
            _render_inline_status("IDA Backend", "ok", "Connected")
            st.caption(status["database"])
            st.write(
                f"`{status['architecture']}` | `{status['bits']}-bit` | `{status['endian']}`"
            )
        else:
            _render_inline_status("IDA Backend", "error", "Disconnected")
            st.caption(status["error"])

        llm_status = get_llm_status()
        if llm_status["configured"]:
            _render_inline_status("LLM Agent", "ok", "Configured")
            st.caption(f"{llm_status['provider']} / {llm_status['model']}")
        else:
            _render_inline_status("LLM Agent", "warn", "Not configured")
            st.caption(llm_status["error"])

        database_summary = _repository().get_summary()
        st.markdown(
            (
                '<div class="va-meta-stack">'
                f"SQLite &nbsp; {database_summary['samples']} samples / "
                f"{database_summary['scans']} scans / {database_summary['threads']} chats<br>"
                f"Memory &nbsp; {os.getenv('VULN_CONTEXT_RECENT_TURNS', '8')} recent turns<br>"
                f"Budget &nbsp; {os.getenv('VULN_AGENT_MAX_TOOL_CALLS', '48')} tools / "
                f"{os.getenv('VULN_AGENT_MAX_TURN_SECONDS', '300')}s per turn"
                "</div>"
            ),
            unsafe_allow_html=True,
        )
        _render_chat_history(sample_id)

        with st.expander("Scan Limits"):
            st.number_input("Source candidates", 1, 10000, 100, key="source_limit")
            st.number_input("Minimum source score", 0.0, 100.0, 25.0, key="source_min_score")
            st.number_input("Sink traversal depth", 0, 64, 8, key="sink_max_depth")
            st.number_input("Functions to scan", 1, 10000, 500, key="sink_max_functions")
            st.number_input("Taint traversal depth", 1, 100, 20, key="taint_max_depth")
            st.number_input("Maximum findings", 1, 1000, 100, key="max_findings")

        if st.button(
            ":material/search: Start Baseline Scan",
            type="primary",
            width="stretch",
            disabled=not status["connected"],
        ):
            _start_scan()

        reports = _available_reports()
        if reports:
            st.markdown('<div class="va-sidebar-heading">Saved reports</div>', unsafe_allow_html=True)
            selected = st.selectbox(
                "Saved Reports",
                options=reports,
                label_visibility="collapsed",
                index=reports.index(st.session_state.active_report_id)
                if st.session_state.get("active_report_id") in reports
                else 0,
            )
            if st.button(":material/folder_open: Open Report", width="stretch"):
                st.session_state.active_report_id = selected
                st.session_state.workspace_mode = "Analysis Workspace"
                st.session_state.analysis_view = "Report"
                st.rerun()

        return status


def _render_status_band(status: dict[str, Any], report: BinaryVulnerabilityReport | None) -> None:
    findings = len(report.findings) if report else 0
    verified = (
        sum(finding.verification_status == "verified" for finding in report.findings)
        if report
        else 0
    )
    cards = [
        (
            "IDA Backend",
            "Online" if status["connected"] else "Offline",
            status.get("database", status.get("error", "No backend connection")),
            "ok" if status["connected"] else "error",
        ),
        (
            "Architecture",
            str(status.get("architecture", "unknown")),
            f"{status.get('endian', 'unknown')} endian",
            "info",
        ),
        ("Bits", str(status.get("bits", 0)), "analysis target width", "info"),
        ("Findings", str(findings), "selected report", "warn" if findings else "info"),
        ("Verified", str(verified), "evidence-backed findings", "ok" if verified else "info"),
    ]
    card_html = "".join(
        (
            f'<div class="va-status-card va-status-card-{tone}">'
            f'<div class="va-status-label">{html.escape(label)}</div>'
            f'<div class="va-status-value">{html.escape(value)}</div>'
            f'<div class="va-status-sub">{html.escape(str(subtitle))}</div>'
            "</div>"
        )
        for label, value, subtitle, tone in cards
    )
    st.markdown(
        f'<div class="va-status-grid">{card_html}</div>',
        unsafe_allow_html=True,
    )


def _active_thread_id() -> str:
    return str(st.session_state.get("active_chat_thread_id", ""))


def _short_text(value: Any, limit: int = 110) -> str:
    text = str(value).replace("\n", " ").strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."


def _render_mini_list(items: list[Any], *, empty: str, limit: int = 5) -> None:
    if not items:
        st.markdown(
            f'<div class="va-mini-empty">{html.escape(empty)}</div>',
            unsafe_allow_html=True,
        )
        return
    rows = []
    for item in items[:limit]:
        if isinstance(item, dict):
            value = item.get("route") or item.get("sink_name") or item.get("handler_name") or item
        else:
            value = item
        rows.append(f'<div class="va-mini-item">{html.escape(_short_text(value))}</div>')
    if len(items) > limit:
        rows.append(f'<div class="va-mini-item">+{len(items) - limit} more</div>')
    st.markdown(
        f'<div class="va-mini-list">{"".join(rows)}</div>',
        unsafe_allow_html=True,
    )


def _render_budget_grid(items: list[tuple[str, Any]]) -> None:
    rows = "".join(
        (
            '<div class="va-budget-item">'
            f'<div class="va-budget-label">{html.escape(label)}</div>'
            f'<div class="va-budget-value">{html.escape(str(value))}</div>'
            "</div>"
        )
        for label, value in items
    )
    st.markdown(f'<div class="va-budget-grid">{rows}</div>', unsafe_allow_html=True)


def _render_investigation_state_panel(thread_id: str) -> None:
    state = _repository().get_investigation_state(thread_id) if thread_id else None
    state = state or {}
    phase = state.get("phase", "initial_recon")
    active_function = state.get("active_function") or "none"
    active_sink = state.get("active_sink") or {}
    pending_sinks = state.get("pending_sinks", [])
    confirmed_routes = state.get("confirmed_routes", [])
    confirmed_sources = state.get("confirmed_sources", [])
    missing_evidence = state.get("missing_evidence", [])
    verified_findings = state.get("verified_findings", [])
    indirect_calls = state.get("indirect_call_sites", [])

    st.markdown('<div class="va-side-panel">', unsafe_allow_html=True)
    st.markdown(
        (
            '<div class="va-panel-card">'
            '<div class="va-panel-title"><span>Investigation State</span>'
            f'<span class="va-pill va-pill-ok">{html.escape(str(phase))}</span></div>'
            '<div class="va-panel-kv">'
            f"<span>Active fn</span><span>{html.escape(_short_text(active_function, 72))}</span>"
            f"<span>Routes</span><span>{len(confirmed_routes)}</span>"
            f"<span>Sources</span><span>{len(confirmed_sources)}</span>"
            f"<span>Pending sinks</span><span>{len(pending_sinks)}</span>"
            f"<span>Verified</span><span>{len(verified_findings)}</span>"
            f"<span>Indirect calls</span><span>{len(indirect_calls)}</span>"
            "</div></div>"
        ),
        unsafe_allow_html=True,
    )

    with st.container():
        st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
        st.markdown('<div class="va-panel-title">Confirmed Routes</div>', unsafe_allow_html=True)
        _render_mini_list(confirmed_routes, empty="No route evidence yet.")
        st.markdown("</div>", unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
        st.markdown('<div class="va-panel-title">Sources & Sinks</div>', unsafe_allow_html=True)
        st.markdown('<div class="va-kicker">Confirmed sources</div>', unsafe_allow_html=True)
        _render_mini_list(confirmed_sources, empty="No confirmed source yet.", limit=4)
        st.markdown('<div class="va-kicker" style="margin-top:0.65rem;">Pending sinks</div>', unsafe_allow_html=True)
        _render_mini_list(pending_sinks, empty="No pending sink yet.", limit=4)
        if active_sink:
            with st.expander("Active sink"):
                st.json(active_sink)
        st.markdown("</div>", unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
        st.markdown('<div class="va-panel-title">Missing Evidence</div>', unsafe_allow_html=True)
        _render_mini_list(missing_evidence, empty="No missing evidence recorded.", limit=5)
        st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)


def _render_budget_panel(thread_id: str, messages: list[BaseMessage] | None = None) -> None:
    context_budget = ContextBudget.from_env()
    execution_limits = agent_limits.AgentExecutionLimits.from_env()
    summary = _repository().get_chat_summary(thread_id) if thread_id else None
    events = _repository().list_tool_events(thread_id) if thread_id else []
    message_count = len(messages or [])
    decompile_events = sum(event["tool_name"] in DECOMPILE_TOOLS for event in events)
    discovery_events = sum(event["tool_name"] in DISCOVERY_SCAN_TOOLS for event in events)
    taint_events = sum(event["tool_name"] in TAINT_TRACE_TOOLS for event in events)

    st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
    st.markdown('<div class="va-panel-title">Context Budget</div>', unsafe_allow_html=True)
    _render_budget_grid(
        [
            ("input", context_budget.max_input_tokens),
            ("recent", context_budget.recent_message_tokens),
            ("summary", context_budget.summary_tokens),
            ("state", context_budget.state_tokens),
            ("messages", message_count),
            ("summarized", summary["summarized_until_sequence"] if summary else 0),
        ]
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
    st.markdown('<div class="va-panel-title">Tool Budget</div>', unsafe_allow_html=True)
    _render_budget_grid(
        [
            ("tools", execution_limits.max_tool_calls),
            ("tools/batch", getattr(execution_limits, "max_tool_calls_per_batch", 0)),
            ("loops", execution_limits.max_tool_loops),
            ("decompile", execution_limits.max_decompile_calls),
            ("decomp/batch", getattr(execution_limits, "max_decompile_calls_per_batch", 0)),
            ("discovery", execution_limits.max_scan_calls),
            ("scan/batch", getattr(execution_limits, "max_scan_calls_per_batch", 0)),
            ("taint", getattr(execution_limits, "max_taint_trace_calls", 0)),
            ("taint/batch", getattr(execution_limits, "max_taint_trace_calls_per_batch", 0)),
        ]
    )
    st.caption(
        f"Current thread has {decompile_events} decompile events. "
        f"{discovery_events} discovery scan events and {taint_events} taint trace events. "
        "Each Agent turn resets the scheduling budget."
    )
    st.markdown("</div>", unsafe_allow_html=True)


def _decode_tool_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _decode_json_field(value: Any, default: Any) -> Any:
    if not value:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value


def _render_recent_tool_events(thread_id: str, *, limit: int = 6) -> None:
    events = _repository().list_tool_events(thread_id)[-limit:] if thread_id else []
    st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
    st.markdown('<div class="va-panel-title">Recent Tool Events</div>', unsafe_allow_html=True)
    if not events:
        st.markdown(
            '<div class="va-mini-empty">No tool events in this thread.</div>',
            unsafe_allow_html=True,
        )
    for event in reversed(events):
        output = _decode_tool_json(event.get("output_json", ""))
        st.markdown(
            (
                '<div class="va-mini-item">'
                f"<strong>{html.escape(str(event['tool_name']))}</strong><br>"
                f"{html.escape(_short_text(output, 130))}"
                "</div>"
            ),
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)


def _render_recent_harness_runs(*, limit: int = 8) -> None:
    repository = _repository()
    runs = repository.list_harness_runs(limit=limit)
    active_run_id = st.session_state.get("active_harness_run_id", "")
    if not active_run_id and runs:
        active_run_id = runs[0]["id"]
        st.session_state.active_harness_run_id = active_run_id

    st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
    st.markdown('<div class="va-panel-title">Recent Harness Runs</div>', unsafe_allow_html=True)
    if not runs:
        st.markdown(
            '<div class="va-mini-empty">No harness runs have been recorded.</div>',
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)
        return

    for index, run in enumerate(runs):
        is_active = run["id"] == active_run_id
        state = "ok" if run["status"] == "completed" else "error"
        run_class = "va-run-item" if run["status"] == "completed" else "va-run-item va-run-item-failed"
        st.markdown(
            (
                f'<div class="{run_class}">'
                f'<strong>{html.escape(str(run["mode"]))}</strong> '
                f'<span class="va-pill va-pill-{state}">{html.escape(str(run["status"]))}</span><br>'
                f"{html.escape(_short_text(run['id'], 34))}<br>"
                f"<span>{html.escape(_short_text(run.get('started_at', ''), 36))}</span>"
                f"{' | active' if is_active else ''}"
                "</div>"
            ),
            unsafe_allow_html=True,
        )
        if st.button(
            f"Open run {index + 1}",
            key=f"harness-run-open-{run['id']}",
            width="stretch",
        ):
            st.session_state.active_harness_run_id = run["id"]
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)


def _render_harness_trace_panel() -> None:
    run_id = st.session_state.get("active_harness_run_id", "")
    run = _repository().get_harness_run(run_id) if run_id else None
    st.markdown('<div class="va-panel-card">', unsafe_allow_html=True)
    st.markdown('<div class="va-panel-title">Trace Timeline</div>', unsafe_allow_html=True)
    if not run:
        st.markdown(
            '<div class="va-mini-empty">Select a harness run to inspect its trace.</div>',
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)
        return

    state = "ok" if run["status"] == "completed" else "error"
    st.markdown(
        (
            '<div class="va-panel-kv">'
            f"<span>Run</span><span>{html.escape(_short_text(run['id'], 72))}</span>"
            f"<span>Mode</span><span>{html.escape(str(run['mode']))}</span>"
            f"<span>Status</span><span><span class=\"va-pill va-pill-{state}\">{html.escape(str(run['status']))}</span></span>"
            f"<span>Report</span><span>{html.escape(run.get('report_id') or '-')}</span>"
            f"<span>Thread</span><span>{html.escape(run.get('thread_id') or '-')}</span>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )
    if run.get("error"):
        st.error(run["error"])

    action_columns = st.columns(2)
    if run.get("report_id") and action_columns[0].button(
        ":material/description: Open Report",
        key=f"harness-open-report-{run['id']}",
        width="stretch",
    ):
        st.session_state.active_report_id = run["report_id"]
        st.session_state.workspace_mode = "Analysis Workspace"
        st.session_state.analysis_view = "Report"
        st.rerun()
    if run.get("thread_id") and action_columns[1].button(
        ":material/chat: Open Chat",
        key=f"harness-open-chat-{run['id']}",
        width="stretch",
    ):
        st.session_state.active_chat_thread_id = run["thread_id"]
        st.session_state.loaded_chat_thread_id = run["thread_id"]
        st.session_state.agent_messages = _repository().load_chat_messages(run["thread_id"])
        st.session_state.workspace_mode = "Agent Chat"
        st.rerun()

    for event in run.get("trace_events", []):
        data = _decode_json_field(event.get("data_json"), {})
        event_type = str(event.get("event_type", ""))
        item_class = (
            "va-trace-item va-trace-item-failed"
            if "fail" in event_type.lower()
            else "va-trace-item"
        )
        st.markdown(
            (
                f'<div class="{item_class}">'
                f'<div class="va-trace-type">[{event.get("sequence", 0)}] '
                f"{html.escape(event_type)}</div>"
                f"<div>{html.escape(_short_text(event.get('message', ''), 130))}</div>"
                f'<div class="va-trace-meta">{html.escape(_short_text(data, 150))}</div>'
                "</div>"
            ),
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)


def _render_right_rail(thread_id: str, messages: list[BaseMessage] | None = None) -> None:
    _render_investigation_state_panel(thread_id)
    _render_recent_harness_runs()
    _render_harness_trace_panel()
    _render_budget_panel(thread_id, messages)
    _render_recent_tool_events(thread_id)


def _render_report(report: BinaryVulnerabilityReport | None) -> None:
    if report is None:
        st.info("No report selected.")
        return

    verified = sum(finding.verification_status == "verified" for finding in report.findings)
    high_risk = sum(finding.severity in {"critical", "high"} for finding in report.findings)
    st.markdown(
        (
            '<div class="va-report-hero">'
            "<div>"
            '<div class="va-kicker">Baseline Scan Report</div>'
            f'<div class="va-report-title">{html.escape(report.summary or "Binary vulnerability scan")}</div>'
            f'<div class="va-report-meta">Report {html.escape(report.report_id)} | '
            f"Scope {html.escape(report.scope)} | "
            f"{html.escape(str(report.sample.architecture))} / {html.escape(str(report.sample.bits))}-bit "
            f"{html.escape(str(report.sample.endian))}</div>"
            "</div>"
            '<div class="va-budget-grid" style="min-width:18rem;">'
            '<div class="va-budget-item"><div class="va-budget-label">Routes</div>'
            f'<div class="va-budget-value">{len(report.routes)}</div></div>'
            '<div class="va-budget-item"><div class="va-budget-label">Sources</div>'
            f'<div class="va-budget-value">{len(report.source_candidates)}</div></div>'
            '<div class="va-budget-item"><div class="va-budget-label">Findings</div>'
            f'<div class="va-budget-value">{len(report.findings)}</div></div>'
            '<div class="va-budget-item"><div class="va-budget-label">Verified</div>'
            f'<div class="va-budget-value">{verified}</div></div>'
            "</div>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )
    actions = st.columns([1, 1, 4])
    with actions[0]:
        st.download_button(
            ":material/download: JSON",
            data=report.model_dump_json(indent=2),
            file_name=f"{report.report_id}.json",
            mime="application/json",
            width="stretch",
        )
    with actions[1]:
        st.caption(f"{high_risk} high-risk findings")
    if not report.findings:
        st.info("No sink findings were produced.")
        return

    for finding in report.findings:
        sink = finding.sink
        severity_class = f"va-finding-card-{finding.severity}"
        st.markdown(
            (
                f'<div class="va-finding-card {severity_class}">'
                '<div class="va-finding-head">'
                "<div>"
                f'<div class="va-finding-title">{html.escape(finding.category)} | '
                f"{html.escape(sink.caller_name)} -> {html.escape(sink.sink_name)}</div>"
                f'<div class="va-finding-meta">Call site {html.escape(sink.loc)} | '
                f"Category {html.escape(sink.category)} | Confidence {finding.confidence:.2f}</div>"
                "</div>"
                f'<span class="va-pill va-pill-{"ok" if finding.verification_status == "verified" else "warn"}">'
                f"{html.escape(finding.verification_status)}</span>"
                "</div></div>"
            ),
            unsafe_allow_html=True,
        )
        with st.expander(
            f"{finding.severity.upper()} evidence: {sink.caller_name} -> {sink.sink_name}",
        ):
            columns = st.columns(4)
            columns[0].metric("Severity", finding.severity)
            columns[1].metric("Confidence", f"{finding.confidence:.2f}")
            columns[2].metric("Call Site", sink.loc)
            columns[3].metric("Status", finding.verification_status)
            if finding.source:
                st.write(f"Source: `{finding.source}`")
            st.write("Evidence")
            for evidence in finding.evidence:
                st.write(f"- {evidence}")
            if finding.remediation:
                st.write(f"Remediation: {finding.remediation}")
            if finding.call_chains:
                with st.expander("Call Chains"):
                    for chain in finding.call_chains:
                        st.code(chain.chain_str or json.dumps(chain.model_dump(), indent=2))


def _render_routes(report: BinaryVulnerabilityReport | None) -> None:
    if report is None or not report.routes:
        st.info("No route registrations in the selected report.")
        return
    st.dataframe(
        [route.model_dump() for route in report.routes],
        width="stretch",
        hide_index=True,
    )


def _render_sources(report: BinaryVulnerabilityReport | None) -> None:
    if report is None or not report.source_candidates:
        st.info("No source candidates in the selected report.")
        return
    st.dataframe(
        [source.model_dump(exclude={"decompiled_code"}) for source in report.source_candidates],
        width="stretch",
        hide_index=True,
    )


def _render_function_explorer(status: dict[str, Any]) -> None:
    address = st.text_input("Function Address", placeholder="0x4055b8")
    if st.button(
        ":material/code: Decompile",
        disabled=not status["connected"] or not address,
    ):
        try:
            result = _ida_client().get_function_context(address)
            st.session_state.function_context = result.model_dump()
        except Exception as exc:  # noqa: BLE001 - surface backend failures in the UI
            st.error(f"{type(exc).__name__}: {exc}")

    context = st.session_state.get("function_context")
    if not context:
        return

    st.subheader(context["name"])
    st.caption(
        f"`{context['start_ea']}` - `{context['end_ea']}` | "
        f"{context['size']} bytes | `{context['prototype']}`"
    )
    details, references, strings = st.tabs(["Pseudocode", "References", "Strings"])
    with details:
        if context["decompile_ok"]:
            st.code(context["pseudocode"], language="c")
        else:
            st.error(context["decompile_error"])
    with references:
        st.write("Callers", context["callers"])
        st.write("Callees", context["callees"])
        st.write("Imports", context["imports_used"])
    with strings:
        st.dataframe(context["string_records"], width="stretch", hide_index=True)


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, indent=2)


def _tool_input_summary(args: dict[str, Any]) -> str:
    if not args:
        return "no arguments"
    parts = []
    for key, value in list(args.items())[:4]:
        parts.append(f"{key}={_short_text(value, 44)}")
    if len(args) > 4:
        parts.append(f"+{len(args) - 4} more")
    return ", ".join(parts)


def _render_agent_message(message: BaseMessage) -> None:
    if isinstance(message, HumanMessage):
        with st.chat_message("user"):
            st.write(_message_text(message.content))
        return

    if isinstance(message, ToolMessage):
        with st.chat_message("assistant", avatar=":material/build:"):
            content = _message_text(message.content)
            st.markdown(
                (
                    '<div class="va-tool-card va-tool-card-result">'
                    '<div class="va-tool-title">'
                    f"<span>Tool result: {html.escape(message.name or 'IDA tool')}</span>"
                    '<span class="va-pill va-pill-ok">complete</span>'
                    "</div>"
                    f'<div class="va-tool-subtitle">{html.escape(_short_text(content, 180))}</div>'
                    "</div>"
                ),
                unsafe_allow_html=True,
            )
            with st.expander("Full tool output"):
                st.code(_message_text(message.content))
        return

    if isinstance(message, AIMessage):
        with st.chat_message("assistant"):
            if message.content:
                st.write(_message_text(message.content))
            for tool_call in message.tool_calls:
                args = tool_call.get("args", {})
                st.markdown(
                    (
                        '<div class="va-tool-card">'
                        '<div class="va-tool-title">'
                        f"<span>Tool call: {html.escape(tool_call['name'])}</span>"
                        '<span class="va-pill va-pill-warn">queued</span>'
                        "</div>"
                        f'<div class="va-tool-subtitle">{html.escape(_tool_input_summary(args))}</div>'
                        "</div>"
                    ),
                    unsafe_allow_html=True,
                )
                with st.expander("Tool arguments"):
                    st.json(tool_call["args"])


def _render_agent_chat(status: dict[str, Any]) -> None:
    llm_status = get_llm_status()
    detail = llm_status["model"] if llm_status["configured"] and status["connected"] else ""
    _render_workspace_header("Primary workspace", "Agent Chat", detail)
    if not llm_status["configured"]:
        st.warning("Configure `DEEPSEEK_API_KEY` in `.env` to enable Agent chat.")
    elif not status["connected"]:
        st.warning("Start the IDA backend before asking the Agent to inspect the binary.")
    else:
        st.caption(
            f"`{llm_status['provider']}` / `{llm_status['model']}` / read-only IDA tools"
        )

    messages: list[BaseMessage] = st.session_state.setdefault("agent_messages", [])
    prompt = st.session_state.pop("suggested_agent_prompt", "")
    if not messages:
        st.markdown(
            '<div class="va-chat-empty">Select an investigation prompt or ask a focused binary analysis question.</div>',
            unsafe_allow_html=True,
        )
        columns = st.columns(2)
        for index, suggestion in enumerate(AGENT_PROMPT_SUGGESTIONS):
            if columns[index % 2].button(
                suggestion,
                key=f"agent-suggestion-{index}",
                width="stretch",
                disabled=not llm_status["configured"] or not status["connected"],
            ):
                prompt = suggestion

    for message in messages:
        _render_agent_message(message)

    prompt = prompt or st.chat_input(
        "Ask about routes, functions, sources, sinks, or taint chains",
        disabled=not llm_status["configured"] or not status["connected"],
    )
    if not prompt:
        return

    with st.status("Agent is analyzing the binary", expanded=True) as agent_status:
        try:
            result = asyncio.run(
                _harness().run_agent_chat(
                    HarnessTurnRequest(
                        prompt=prompt,
                        messages=messages,
                        thread_id=st.session_state.active_chat_thread_id,
                        ida_backend_url=st.session_state.backend_url,
                        report_dir=st.session_state.report_dir,
                    )
                )
            )
            if result.status != "completed":
                raise RuntimeError(result.error or "Agent request failed")
            st.session_state.agent_messages = result.messages
            st.session_state.active_harness_run_id = result.run_id
        except Exception as exc:  # noqa: BLE001 - surface LLM and tool failures in the UI
            agent_status.update(label="Agent request failed", state="error")
            st.error(f"{type(exc).__name__}: {exc}")
            return
        agent_status.update(label="Agent response complete", state="complete")
    st.rerun()


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon=":material/security:", layout="wide")
    _inject_styles()
    st.session_state.setdefault("workspace_mode", "Agent Chat")
    st.session_state.setdefault("analysis_view", "Report")

    status = _render_sidebar()
    report = _load_report(st.session_state.get("active_report_id", ""))

    _render_page_header()
    _render_status_band(status, report)
    st.divider()

    workspace_mode = st.segmented_control(
        "Workspace",
        ["Agent Chat", "Analysis Workspace"],
        default=st.session_state.workspace_mode,
        label_visibility="collapsed",
    )
    st.session_state.workspace_mode = workspace_mode or "Agent Chat"
    thread_id = _active_thread_id()

    if st.session_state.workspace_mode == "Agent Chat":
        workspace, right_rail = st.columns([3.2, 1.15], gap="large")
        with workspace:
            _render_agent_chat(status)
        with right_rail:
            _render_right_rail(thread_id, st.session_state.get("agent_messages", []))
        return

    workspace, right_rail = st.columns([3.2, 1.15], gap="large")
    with workspace:
        _render_workspace_header("Evidence workspace", "Analysis Workspace")
        analysis_views = ["Report", "Routes", "Sources", "Function Explorer"]
        active_view = st.segmented_control(
            "Analysis View",
            analysis_views,
            default=st.session_state.analysis_view,
            label_visibility="collapsed",
        )
        st.session_state.analysis_view = active_view or "Report"

        match st.session_state.analysis_view:
            case "Report":
                _render_report(report)
            case "Routes":
                _render_routes(report)
            case "Sources":
                _render_sources(report)
            case "Function Explorer":
                _render_function_explorer(status)
    with right_rail:
        _render_right_rail(thread_id, st.session_state.get("agent_messages", []))


if __name__ == "__main__":
    main()
