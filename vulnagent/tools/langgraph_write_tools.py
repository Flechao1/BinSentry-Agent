"""LangGraph tools that require an interrupt confirmation before IDB mutation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from vulnagent.clients.async_ida_client import AsyncIdaClient
from vulnagent.ida.schemas import (
    NopBytesRequest,
    PatchBytesRequest,
    PatchConditionalJumpRequest,
    RenameFunctionRequest,
    SetFunctionCommentRequest,
)


AsyncClientFactory = Callable[[], AsyncIdaClient]


def build_confirmed_write_tools(client_factory: AsyncClientFactory) -> list[Any]:
    """Create mutation tools that cannot execute before a human confirms."""
    from langchain_core.tools import tool
    from langgraph.types import interrupt

    @tool
    async def request_rename_function(ea: str, new_name: str, reason: str = "") -> str:
        """Request confirmation, then rename one IDA function if approved."""
        validated = RenameFunctionRequest(new_name=new_name, reason=reason)
        approved = interrupt(
            {
                "action": "rename_function",
                "prompt": (
                    f"Confirm IDB write: rename function {ea} to {validated.new_name}? "
                    f"Reason: {validated.reason or '(none)'}"
                ),
                "ea": ea,
                **validated.model_dump(),
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.rename_function(ea, validated.new_name, validated.reason)
        return result.model_dump_json()

    @tool
    async def request_set_function_comment(
        ea: str,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> str:
        """Request confirmation, then set an IDA function comment if approved."""
        validated = SetFunctionCommentRequest(
            comment=comment,
            repeatable=repeatable,
            reason=reason,
        )
        approved = interrupt(
            {
                "action": "set_function_comment",
                "prompt": (
                    f"Confirm IDB write: set function comment at {ea}? "
                    f"Reason: {validated.reason or '(none)'}"
                ),
                "ea": ea,
                **validated.model_dump(),
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.set_function_comment(
                ea,
                validated.comment,
                validated.repeatable,
                validated.reason,
            )
        return result.model_dump_json()

    @tool
    async def request_patch_bytes(
        ea: str,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> str:
        """Request confirmation, then patch exact database bytes if approved."""
        validated = PatchBytesRequest(
            patched_hex=patched_hex,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        approved = interrupt(
            {
                "action": "patch_bytes",
                "prompt": (
                    f"Confirm binary patch at {ea} with bytes {validated.patched_hex}? "
                    "Use expected_original_hex when possible. "
                    f"Reason: {validated.reason or '(none)'}"
                ),
                "ea": ea,
                **validated.model_dump(),
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.patch_bytes(
                ea,
                validated.patched_hex,
                validated.expected_original_hex,
                validated.reason,
            )
        return result.model_dump_json()

    @tool
    async def request_nop_bytes(
        ea: str,
        size: int,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> str:
        """Request confirmation, then replace bytes with architecture-specific NOPs if approved."""
        validated = NopBytesRequest(
            size=size,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        approved = interrupt(
            {
                "action": "nop_bytes",
                "prompt": (
                    f"Confirm binary patch: NOP {validated.size} byte(s) at {ea}? "
                    "Use expected_original_hex when possible. "
                    f"Reason: {validated.reason or '(none)'}"
                ),
                "ea": ea,
                **validated.model_dump(),
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.nop_bytes(
                ea,
                validated.size,
                validated.expected_original_hex,
                validated.reason,
            )
        return result.model_dump_json()

    @tool
    async def request_patch_conditional_jump(
        ea: str,
        mode: str = "invert",
        expected_original_hex: str = "",
        reason: str = "",
    ) -> str:
        """Request confirmation, then patch a supported conditional jump if approved."""
        validated = PatchConditionalJumpRequest(
            mode=mode,
            expected_original_hex=expected_original_hex,
            reason=reason,
        )
        approved = interrupt(
            {
                "action": "patch_conditional_jump",
                "prompt": (
                    f"Confirm binary patch: {validated.mode} conditional jump at {ea}? "
                    "Supported encodings are limited; unsupported instructions return an error. "
                    f"Reason: {validated.reason or '(none)'}"
                ),
                "ea": ea,
                **validated.model_dump(),
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.patch_conditional_jump(
                ea,
                validated.mode,
                validated.expected_original_hex,
                validated.reason,
            )
        return result.model_dump_json()

    @tool
    async def request_save_database(output_path: str = "") -> str:
        """Request confirmation, then save the active IDA database if approved."""
        approved = interrupt(
            {
                "action": "save_database",
                "prompt": (
                    "Confirm IDB write: save database to "
                    f"{output_path or '(current database path)'}?"
                ),
                "output_path": output_path,
            }
        )
        if not _is_confirmed(approved):
            return "IDB write cancelled by user."
        async with client_factory() as client:
            result = await client.save_database(output_path)
        return result.model_dump_json()

    return [
        request_rename_function,
        request_set_function_comment,
        request_patch_bytes,
        request_nop_bytes,
        request_patch_conditional_jump,
        request_save_database,
    ]


def _is_confirmed(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"confirm", "confirmed", "yes", "y", "ok", "确认"}
    return False
