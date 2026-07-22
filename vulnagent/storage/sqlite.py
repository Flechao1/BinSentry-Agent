from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from vulnagent.reports.models import BinaryVulnerabilityReport

DEFAULT_PROJECT_ID = "default"
DEFAULT_DB_PATH = "./data/vulnagent.db"
SCHEMA_VERSION = 3


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class SqliteVulnRepository:
    """SQLite persistence for analysis history, findings, and agent conversations."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @classmethod
    def from_env(cls) -> SqliteVulnRepository:
        return cls(os.getenv("VULN_DB_PATH", DEFAULT_DB_PATH))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS samples (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    database_path TEXT NOT NULL UNIQUE,
                    file_name TEXT NOT NULL,
                    sha256 TEXT NOT NULL DEFAULT '',
                    architecture TEXT NOT NULL DEFAULT 'unknown',
                    bits INTEGER NOT NULL DEFAULT 0,
                    endian TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    sample_id TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT '',
                    config_json TEXT NOT NULL DEFAULT '{}',
                    summary TEXT NOT NULL DEFAULT '',
                    report_path TEXT NOT NULL DEFAULT '',
                    report_json TEXT NOT NULL DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    sink_name TEXT NOT NULL DEFAULT '',
                    sink_address TEXT NOT NULL DEFAULT '',
                    source_name TEXT NOT NULL DEFAULT '',
                    verification_status TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    remediation TEXT NOT NULL DEFAULT '',
                    finding_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS chat_threads (
                    id TEXT PRIMARY KEY,
                    sample_id TEXT REFERENCES samples(id) ON DELETE SET NULL,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chat_messages (
                    id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    message_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(thread_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS tool_events (
                    id TEXT PRIMARY KEY,
                    thread_id TEXT NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
                    tool_call_id TEXT NOT NULL DEFAULT '',
                    tool_name TEXT NOT NULL,
                    input_json TEXT NOT NULL DEFAULT '{}',
                    output_json TEXT NOT NULL DEFAULT 'null',
                    status TEXT NOT NULL DEFAULT 'complete',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS harness_runs (
                    id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    thread_id TEXT REFERENCES chat_threads(id) ON DELETE SET NULL,
                    report_id TEXT DEFAULT '',
                    answer TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS harness_trace_events (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES harness_runs(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    data_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS chat_summaries (
                    thread_id TEXT PRIMARY KEY REFERENCES chat_threads(id) ON DELETE CASCADE,
                    summary TEXT NOT NULL DEFAULT '',
                    summarized_until_sequence INTEGER NOT NULL DEFAULT -1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS investigation_states (
                    thread_id TEXT PRIMARY KEY REFERENCES chat_threads(id) ON DELETE CASCADE,
                    state_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analyst_notes (
                    id TEXT PRIMARY KEY,
                    sample_id TEXT REFERENCES samples(id) ON DELETE CASCADE,
                    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            now = _utc_now()
            connection.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, applied_at)
                VALUES (?, ?)
                """,
                (SCHEMA_VERSION, now),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO projects(id, name, description, created_at, updated_at)
                VALUES (?, ?, '', ?, ?)
                """,
                (DEFAULT_PROJECT_ID, "Default Project", now, now),
            )

    def upsert_sample(
        self,
        database_path: str,
        *,
        architecture: str = "unknown",
        bits: int = 0,
        endian: str = "",
        sha256: str = "",
    ) -> str:
        resolved_path = str(Path(database_path).expanduser().resolve())
        now = _utc_now()
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT id FROM samples WHERE database_path = ?",
                (resolved_path,),
            ).fetchone()
            sample_id = existing["id"] if existing else uuid4().hex
            connection.execute(
                """
                INSERT INTO samples(
                    id, project_id, database_path, file_name, sha256,
                    architecture, bits, endian, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(database_path) DO UPDATE SET
                    file_name = excluded.file_name,
                    sha256 = CASE
                        WHEN excluded.sha256 = '' THEN samples.sha256
                        ELSE excluded.sha256
                    END,
                    architecture = CASE
                        WHEN excluded.architecture = 'unknown' THEN samples.architecture
                        ELSE excluded.architecture
                    END,
                    bits = CASE WHEN excluded.bits = 0 THEN samples.bits ELSE excluded.bits END,
                    endian = CASE
                        WHEN excluded.endian = '' THEN samples.endian
                        ELSE excluded.endian
                    END,
                    updated_at = excluded.updated_at
                """,
                (
                    sample_id,
                    DEFAULT_PROJECT_ID,
                    resolved_path,
                    Path(resolved_path).name,
                    sha256,
                    architecture,
                    bits,
                    endian,
                    now,
                    now,
                ),
            )
        return sample_id

    def persist_report(
        self,
        report: BinaryVulnerabilityReport,
        *,
        report_path: str = "",
        config: Any = None,
    ) -> str:
        sample = report.sample
        sample_id = self.upsert_sample(
            sample.database,
            architecture=sample.architecture,
            bits=sample.bits,
            endian=sample.endian,
        )
        report_json = report.model_dump(mode="json")
        config_json = (
            config.model_dump(mode="json") if hasattr(config, "model_dump") else config or {}
        )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_runs(
                    id, sample_id, status, scope, config_json, summary,
                    report_path, report_json, started_at, finished_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    scope = excluded.scope,
                    config_json = excluded.config_json,
                    summary = excluded.summary,
                    report_path = excluded.report_path,
                    report_json = excluded.report_json,
                    finished_at = excluded.finished_at
                """,
                (
                    report.report_id,
                    sample_id,
                    "completed",
                    report.scope,
                    _json_dumps(config_json),
                    report.summary,
                    report_path,
                    _json_dumps(report_json),
                    report.created_at.isoformat(),
                    _utc_now(),
                ),
            )
            connection.execute("DELETE FROM findings WHERE scan_run_id = ?", (report.report_id,))
            for finding in report.findings:
                finding_json = finding.model_dump(mode="json")
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, scan_run_id, category, severity, confidence,
                        sink_name, sink_address, source_name, verification_status,
                        evidence_json, remediation, finding_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        report.report_id,
                        finding.category,
                        finding.severity,
                        finding.confidence,
                        finding.sink.sink_name,
                        finding.sink.loc,
                        finding.source,
                        finding.verification_status,
                        _json_dumps(finding.evidence),
                        finding.remediation,
                        _json_dumps(finding_json),
                    ),
                )
        return report.report_id

    def list_scan_runs(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, sample_id, status, scope, summary, report_path, started_at, finished_at
                FROM scan_runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def load_report(self, report_id: str) -> BinaryVulnerabilityReport:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT report_json FROM scan_runs WHERE id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            raise FileNotFoundError(f"Unknown SQLite report: {report_id}")
        return BinaryVulnerabilityReport.model_validate_json(row["report_json"])

    def get_summary(self) -> dict[str, int]:
        with self._connection() as connection:
            return {
                "samples": connection.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
                "scans": connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0],
                "findings": connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "threads": connection.execute("SELECT COUNT(*) FROM chat_threads").fetchone()[0],
                "tool_events": connection.execute("SELECT COUNT(*) FROM tool_events").fetchone()[0],
                "harness_runs": connection.execute("SELECT COUNT(*) FROM harness_runs").fetchone()[0],
            }

    def create_chat_thread(self, *, sample_id: str | None = None, title: str = "New investigation") -> str:
        thread_id = uuid4().hex
        now = _utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO chat_threads(id, sample_id, title, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (thread_id, sample_id, title, now, now),
            )
        return thread_id

    def list_chat_threads(
        self,
        *,
        sample_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        with self._connection() as connection:
            if sample_id:
                rows = connection.execute(
                    """
                    SELECT id, sample_id, title, created_at, updated_at
                    FROM chat_threads
                    WHERE sample_id = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (sample_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT id, sample_id, title, created_at, updated_at
                    FROM chat_threads
                    ORDER BY updated_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def get_chat_thread(self, thread_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT id, sample_id, title, created_at, updated_at
                FROM chat_threads
                WHERE id = ?
                """,
                (thread_id,),
            ).fetchone()
        return dict(row) if row else None

    def rename_chat_thread(self, thread_id: str, title: str) -> dict[str, Any] | None:
        title = str(title).strip().replace("\n", " ")[:72]
        if not title:
            raise ValueError("Chat title cannot be empty")
        now = _utc_now()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE chat_threads
                SET title = ?, updated_at = ?
                WHERE id = ?
                """,
                (title, now, thread_id),
            )
        return self.get_chat_thread(thread_id) if cursor.rowcount else None

    def delete_chat_thread(self, thread_id: str) -> bool:
        """Delete one conversation and its state while retaining detached run audit records."""
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM chat_threads WHERE id = ?", (thread_id,))
        return bool(cursor.rowcount)

    def save_chat_messages(self, thread_id: str, messages: Sequence[Any]) -> None:
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage, message_to_dict

        if self.get_chat_thread(thread_id) is None:
            raise ValueError(f"Unknown chat thread: {thread_id}")

        pending_tool_calls: dict[str, tuple[str, Any]] = {}
        tool_events: list[tuple[str, str, Any, Any, str]] = []
        title = "New investigation"
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("DELETE FROM chat_messages WHERE thread_id = ?", (thread_id,))
            connection.execute("DELETE FROM tool_events WHERE thread_id = ?", (thread_id,))
            for sequence, message in enumerate(messages):
                message_data = message_to_dict(message)
                connection.execute(
                    """
                    INSERT INTO chat_messages(id, thread_id, sequence, role, message_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid4().hex,
                        thread_id,
                        sequence,
                        message_data["type"],
                        _json_dumps(message_data),
                        now,
                    ),
                )
                if isinstance(message, HumanMessage) and title == "New investigation":
                    title = str(message.content).strip().replace("\n", " ")[:72] or title
                if isinstance(message, AIMessage):
                    for tool_call in message.tool_calls:
                        pending_tool_calls[tool_call["id"]] = (
                            tool_call["name"],
                            tool_call.get("args", {}),
                        )
                if isinstance(message, ToolMessage):
                    call_id = message.tool_call_id
                    name, tool_input = pending_tool_calls.get(
                        call_id,
                        (getattr(message, "name", "") or "unknown", {}),
                    )
                    tool_events.append(
                        (
                            call_id,
                            name,
                            tool_input,
                            message.content,
                            str(getattr(message, "status", "success") or "success"),
                        )
                    )

            connection.execute(
                """
                UPDATE chat_threads
                SET title = CASE
                        WHEN title = 'New investigation' THEN ?
                        ELSE title
                    END,
                    updated_at = ?
                WHERE id = ?
                """,
                (title, now, thread_id),
            )
            for call_id, name, tool_input, output, status in tool_events:
                connection.execute(
                    """
                    INSERT INTO tool_events(
                        id, thread_id, tool_call_id, tool_name,
                        input_json, output_json, status, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid4().hex,
                        thread_id,
                        call_id,
                        name,
                        _json_dumps(tool_input),
                        _json_dumps(output),
                        status,
                        now,
                    ),
                )

    def load_chat_messages(self, thread_id: str) -> list[Any]:
        from langchain_core.messages import messages_from_dict

        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT message_json
                FROM chat_messages
                WHERE thread_id = ?
                ORDER BY sequence ASC
                """,
                (thread_id,),
            ).fetchall()
        return messages_from_dict([json.loads(row["message_json"]) for row in rows])

    def clear_chat_thread(self, thread_id: str) -> None:
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("DELETE FROM chat_messages WHERE thread_id = ?", (thread_id,))
            connection.execute("DELETE FROM tool_events WHERE thread_id = ?", (thread_id,))
            connection.execute("DELETE FROM chat_summaries WHERE thread_id = ?", (thread_id,))
            connection.execute("DELETE FROM investigation_states WHERE thread_id = ?", (thread_id,))
            connection.execute(
                """
                UPDATE chat_threads
                SET title = 'New investigation', updated_at = ?
                WHERE id = ?
                """,
                (now, thread_id),
            )

    def get_chat_summary(self, thread_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT thread_id, summary, summarized_until_sequence, updated_at
                FROM chat_summaries
                WHERE thread_id = ?
                """,
                (thread_id,),
            ).fetchone()
        return dict(row) if row else None

    def save_chat_summary(
        self,
        thread_id: str,
        summary: str,
        *,
        summarized_until_sequence: int,
    ) -> None:
        now = _utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO chat_summaries(
                    thread_id, summary, summarized_until_sequence, updated_at
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(thread_id) DO UPDATE SET
                    summary = excluded.summary,
                    summarized_until_sequence = excluded.summarized_until_sequence,
                    updated_at = excluded.updated_at
                """,
                (thread_id, summary, summarized_until_sequence, now),
            )

    def get_investigation_state(self, thread_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT state_json
                FROM investigation_states
                WHERE thread_id = ?
                """,
                (thread_id,),
            ).fetchone()
        return json.loads(row["state_json"]) if row else None

    def save_investigation_state(self, thread_id: str, state: dict[str, Any]) -> None:
        now = _utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO investigation_states(thread_id, state_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(thread_id) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (thread_id, _json_dumps(state), now),
            )

    def list_tool_events(self, thread_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, thread_id, tool_call_id, tool_name, input_json,
                       output_json, status, created_at
                FROM tool_events
                WHERE thread_id = ?
                ORDER BY created_at ASC
                """,
                (thread_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def persist_harness_run(
        self,
        *,
        run_id: str,
        mode: str,
        status: str,
        thread_id: str = "",
        report_id: str = "",
        answer: str = "",
        error: str = "",
        started_at: str,
        finished_at: str,
        trace_events: Sequence[Any] = (),
        metadata: dict[str, Any] | None = None,
    ) -> str:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO harness_runs(
                    id, mode, status, thread_id, report_id, answer, error,
                    metadata_json, started_at, finished_at
                )
                VALUES (?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    mode = excluded.mode,
                    status = excluded.status,
                    thread_id = excluded.thread_id,
                    report_id = excluded.report_id,
                    answer = excluded.answer,
                    error = excluded.error,
                    metadata_json = excluded.metadata_json,
                    started_at = excluded.started_at,
                    finished_at = excluded.finished_at
                """,
                (
                    run_id,
                    mode,
                    status,
                    thread_id,
                    report_id,
                    answer,
                    error,
                    _json_dumps(metadata or {}),
                    started_at,
                    finished_at,
                ),
            )
            connection.execute("DELETE FROM harness_trace_events WHERE run_id = ?", (run_id,))
            for sequence, event in enumerate(trace_events):
                event_id = getattr(event, "event_id", "") or uuid4().hex
                event_type = getattr(event, "event_type", "")
                message = getattr(event, "message", "")
                data = getattr(event, "data", {})
                created_at = getattr(event, "created_at", _utc_now())
                if hasattr(created_at, "isoformat"):
                    created_at = created_at.isoformat()
                connection.execute(
                    """
                    INSERT INTO harness_trace_events(
                        id, run_id, sequence, event_type, message, data_json, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        run_id,
                        sequence,
                        event_type,
                        message,
                        _json_dumps(data),
                        str(created_at),
                    ),
                )
        return run_id

    def list_harness_runs(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, mode, status, thread_id, report_id, answer, error,
                       metadata_json, started_at, finished_at
                FROM harness_runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_harness_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            run = connection.execute(
                """
                SELECT id, mode, status, thread_id, report_id, answer, error,
                       metadata_json, started_at, finished_at
                FROM harness_runs
                WHERE id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                return None
            events = connection.execute(
                """
                SELECT id, run_id, sequence, event_type, message, data_json, created_at
                FROM harness_trace_events
                WHERE run_id = ?
                ORDER BY sequence ASC
                """,
                (run_id,),
            ).fetchall()
        result = dict(run)
        result["trace_events"] = [dict(row) for row in events]
        return result
