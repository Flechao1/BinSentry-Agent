"""Adapters for streaming scan progress through agent-service-toolkit."""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from langchain_core.messages import ChatMessage
from langgraph.types import StreamWriter

from vulnagent.agent.baseline_scan import ScanProgress


class ToolkitTaskProgressWriter:
    """Emit toolkit-compatible custom task messages for scan stages."""

    def __init__(self, writer: StreamWriter) -> None:
        self.writer = writer
        self.prefix = uuid4().hex
        self.current_stage = ""

    def __call__(self, progress: ScanProgress) -> None:
        if self.current_stage and self.current_stage != progress.stage:
            self._dispatch(self.current_stage, "complete", result="success")
        state: Literal["new", "running"] = (
            "new" if self.current_stage != progress.stage else "running"
        )
        self.current_stage = progress.stage
        self._dispatch(
            progress.stage,
            state,
            data={"message": progress.message, **progress.data},
        )

    def finish(self) -> None:
        if self.current_stage:
            self._dispatch(self.current_stage, "complete", result="success")

    def fail(self, error: str) -> None:
        if self.current_stage:
            self._dispatch(
                self.current_stage,
                "complete",
                result="error",
                data={"error": error},
            )

    def _dispatch(
        self,
        stage: str,
        state: Literal["new", "running", "complete"],
        result: Literal["success", "error"] | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "name": stage,
            "run_id": f"{self.prefix}:{stage}",
            "state": state,
            "data": data or {},
        }
        if result:
            payload["result"] = result
        self.writer(ChatMessage(content=[payload], role="custom"))
