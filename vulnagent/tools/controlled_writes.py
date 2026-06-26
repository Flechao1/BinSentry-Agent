"""Confirmation-gated IDA writes for Agent integrations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.ida.schemas import (
    NopBytesRequest,
    PatchBytesRequest,
    PatchConditionalJumpRequest,
    RenameFunctionRequest,
    SetFunctionCommentRequest,
)


class PendingWriteAction(BaseModel):
    action_id: str = Field(default_factory=lambda: uuid4().hex)
    action: Literal[
        "rename_function",
        "set_function_comment",
        "patch_bytes",
        "nop_bytes",
        "patch_conditional_jump",
        "save_database",
    ]
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def confirmation_prompt(self) -> str:
        if self.action == "rename_function":
            return (
                "Confirm IDB write: rename function "
                f"{self.payload['ea']} to {self.payload['new_name']}? "
                f"Reason: {self.payload.get('reason') or '(none)'}"
            )
        if self.action == "set_function_comment":
            return (
                "Confirm IDB write: set function comment at "
                f"{self.payload['ea']}? Reason: {self.payload.get('reason') or '(none)'}"
            )
        if self.action == "patch_bytes":
            return (
                "Confirm binary patch at "
                f"{self.payload['ea']} with bytes {self.payload['patched_hex']}? "
                f"Reason: {self.payload.get('reason') or '(none)'}"
            )
        if self.action == "nop_bytes":
            return (
                "Confirm binary patch: NOP "
                f"{self.payload['size']} byte(s) at {self.payload['ea']}? "
                f"Reason: {self.payload.get('reason') or '(none)'}"
            )
        if self.action == "patch_conditional_jump":
            return (
                "Confirm binary patch: "
                f"{self.payload['mode']} conditional jump at {self.payload['ea']}? "
                f"Reason: {self.payload.get('reason') or '(none)'}"
            )
        return (
            "Confirm IDB write: save database"
            f" to {self.payload.get('output_path') or '(current database path)'}?"
        )


class AsyncControlledIdaWriter:
    """Create pending writes and execute only explicitly confirmed actions."""

    def __init__(self, client: AsyncIdaClient) -> None:
        self.client = client
        self._pending: dict[str, PendingWriteAction] = {}

    def request_rename_function(
        self,
        ea: int | str,
        new_name: str,
        reason: str = "",
    ) -> PendingWriteAction:
        validated = RenameFunctionRequest(new_name=new_name, reason=reason)
        action = PendingWriteAction(
            action="rename_function",
            payload={"ea": str(ea), **validated.model_dump()},
        )
        self._pending[action.action_id] = action
        return action

    def request_save_database(self, output_path: str = "") -> PendingWriteAction:
        action = PendingWriteAction(
            action="save_database",
            payload={"output_path": output_path},
        )
        self._pending[action.action_id] = action
        return action

    def request_set_function_comment(
        self,
        ea: int | str,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> PendingWriteAction:
        validated = SetFunctionCommentRequest(
            comment=comment,
            repeatable=repeatable,
            reason=reason,
        )
        action = PendingWriteAction(
            action="set_function_comment",
            payload={"ea": str(ea), **validated.model_dump()},
        )
        self._pending[action.action_id] = action
        return action

    def request_patch_bytes(
        self,
        ea: int | str,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PendingWriteAction:
        validated = PatchBytesRequest(
            patched_hex=patched_hex,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        action = PendingWriteAction(
            action="patch_bytes",
            payload={"ea": str(ea), **validated.model_dump()},
        )
        self._pending[action.action_id] = action
        return action

    def request_nop_bytes(
        self,
        ea: int | str,
        size: int,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PendingWriteAction:
        validated = NopBytesRequest(
            size=size,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        action = PendingWriteAction(
            action="nop_bytes",
            payload={"ea": str(ea), **validated.model_dump()},
        )
        self._pending[action.action_id] = action
        return action

    def request_patch_conditional_jump(
        self,
        ea: int | str,
        mode: Literal["invert", "force_taken", "force_not_taken"] = "invert",
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PendingWriteAction:
        validated = PatchConditionalJumpRequest(
            mode=mode,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        action = PendingWriteAction(
            action="patch_conditional_jump",
            payload={"ea": str(ea), **validated.model_dump()},
        )
        self._pending[action.action_id] = action
        return action

    def cancel(self, action_id: str) -> PendingWriteAction:
        return self._pending.pop(action_id)

    async def confirm(self, action_id: str, confirmed: bool) -> Any:
        action = self._pending.pop(action_id)
        if not confirmed:
            return {"ok": False, "message": "write cancelled", "action_id": action_id}
        if action.action == "rename_function":
            return await self.client.rename_function(**action.payload)
        if action.action == "set_function_comment":
            return await self.client.set_function_comment(**action.payload)
        if action.action == "patch_bytes":
            return await self.client.patch_bytes(**action.payload)
        if action.action == "nop_bytes":
            return await self.client.nop_bytes(**action.payload)
        if action.action == "patch_conditional_jump":
            return await self.client.patch_conditional_jump(**action.payload)
        return await self.client.save_database(**action.payload)
