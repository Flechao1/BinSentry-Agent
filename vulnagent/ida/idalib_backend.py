from __future__ import annotations

import math
import random
import re
import shutil
import struct
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from uuid import uuid4

from vulnagent.ida.core import IdaBackend, format_address, parse_address
from vulnagent.ida.schemas import (
    ArchInfo,
    ArgumentOriginResult,
    BatchDecompileEntry,
    CallChainResult,
    CallRecord,
    CrossHandlerCallee,
    DecompileResponse,
    FunctionContext,
    FunctionEntry,
    ImportEntry,
    IndirectCallCandidate,
    IndirectCallScanResult,
    ExportPatchedBinaryResponse,
    NopBytesRequest,
    OpenSessionRequest,
    OpenSessionResponse,
    PatchBytesResponse,
    PatchConditionalJumpRequest,
    RenameFunctionResponse,
    RouteAnalysisResult,
    RouteRegistration,
    SaveDatabaseResponse,
    SetFunctionCommentResponse,
    SinkScanResult,
    SinkCallResult,
    SourceCandidate,
    SourcePropagateResult,
    SourceScanResult,
    StringRecord,
    TaintNodeResult,
    XrefRecord,
)
from vulnagent.ida.schemas import IDA_PROTOCOL_VERSION


class IdalibBackend(IdaBackend):
    """Headless IDA backend for the Agent-facing HTTP service.

    This class is intentionally the only place that imports IDA modules. The
    rest of the Agent can run in a normal Python environment and communicate
    with this backend over HTTP.
    """

    def __init__(self, idb_path: str = "", writable: bool = True) -> None:
        self.idb_path = str(idb_path or "")
        self.writable = writable
        self._write_capable = writable
        self._opened = False
        self._ida: dict[str, Any] = {}
        self._import_names_by_ea: dict[int, str] = {}
        self._idalib_runtime: Any | None = None

    def open(self) -> None:
        if self._opened:
            return
        if not self.idb_path:
            raise ValueError("idb_path is required for idalib backend")

        idalib_runtime = self._load_idalib_runtime()
        self._idalib_runtime = idalib_runtime
        result = idalib_runtime.open_database(self.idb_path, True)
        if int(result or 0) < 0:
            raise RuntimeError(f"failed to open IDA database: {self.idb_path}")

        import ida_auto  # type: ignore
        import ida_bytes  # type: ignore
        import ida_funcs  # type: ignore
        import ida_hexrays  # type: ignore
        import ida_loader  # type: ignore
        import ida_name  # type: ignore
        import ida_nalt  # type: ignore
        import ida_ua  # type: ignore
        import ida_xref  # type: ignore
        import idautils  # type: ignore
        import idc  # type: ignore

        ida_auto.auto_wait()
        if ida_hexrays.init_hexrays_plugin() is False:
            raise RuntimeError("Hex-Rays decompiler is not available")

        self._ida = {
            "ida_bytes": ida_bytes,
            "ida_funcs": ida_funcs,
            "ida_hexrays": ida_hexrays,
            "ida_loader": ida_loader,
            "ida_name": ida_name,
            "ida_nalt": ida_nalt,
            "ida_ua": ida_ua,
            "ida_xref": ida_xref,
            "idautils": idautils,
            "idc": idc,
        }
        self._import_names_by_ea = self._collect_import_names()
        self._opened = True

    def _load_idalib_runtime(self) -> Any:
        """Load the configured idalib Python package.

        IDA 9 installations are commonly activated either as ``ida`` or
        ``idapro``. This backend supports both and prefers ``ida`` because that
        is what Hex-Rays' ``py-activate-idalib.py`` creates in many local
        installs.
        """

        try:
            import ida  # type: ignore

            return ida
        except ImportError:
            import idapro  # type: ignore

            return idapro

    def health(self) -> dict[str, str]:
        return {
            "status": "ok" if self._opened else "created",
            "backend": "idalib",
            "database": self.idb_path,
            "protocol_version": IDA_PROTOCOL_VERSION,
            "writable": str(self.writable).lower(),
        }

    def open_database(self, request: OpenSessionRequest) -> OpenSessionResponse:
        if self._opened:
            self.close_database(save=False)
        self.idb_path = request.idb_path
        self.writable = bool(request.writable) and self._write_capable
        self._ida = {}
        self._import_names_by_ea = {}
        self.open()
        return OpenSessionResponse(
            session_id=request.session_id or uuid4().hex,
            idb_path=self.idb_path,
            database=self.health().get("database", self.idb_path),
            writable=self.writable,
        )

    def get_function_context(self, ea: int) -> FunctionContext:
        self.open()
        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        end_ea = int(func.end_ea)

        decompiled = self.decompile_function(start_ea)
        xrefs = self.get_function_xrefs(start_ea)
        calls = self.get_function_calls(start_ea)
        string_records = self.get_function_strings(start_ea)
        constants = self.get_function_constants(start_ea)
        imports_used = self.get_function_imports(start_ea)
        callees = self._callee_names(calls)

        return FunctionContext(
            ea=format_address(start_ea),
            start_ea=format_address(start_ea),
            end_ea=format_address(end_ea),
            size=max(0, end_ea - start_ea),
            name=self._func_name(start_ea),
            prototype=self._prototype(start_ea),
            pseudocode=decompiled.pseudocode,
            decompile_ok=decompiled.ok,
            decompile_error=decompiled.error,
            callers=self._caller_addresses(xrefs["to"]),
            callees=callees,
            xrefs_to=[record.frm for record in xrefs["to"]],
            xrefs_from=[record.to for record in xrefs["from"]],
            xref_records_to=xrefs["to"],
            xref_records_from=xrefs["from"],
            call_records=calls,
            strings=[record.value for record in string_records],
            string_records=string_records,
            constants=constants,
            imports_used=imports_used,
            confidence_hints=self._confidence_hints(imports_used, string_records, constants),
        )

    def decompile_function(self, ea: int) -> DecompileResponse:
        self.open()
        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        ida_hexrays = self._ida["ida_hexrays"]

        try:
            pseudocode = str(ida_hexrays.decompile(start_ea))
            return DecompileResponse(
                ea=format_address(start_ea),
                name=self._func_name(start_ea),
                prototype=self._prototype(start_ea),
                pseudocode=pseudocode,
                ok=True,
            )
        except Exception as exc:  # noqa: BLE001 - IDA exceptions vary by version
            return DecompileResponse(
                ea=format_address(start_ea),
                name=self._func_name(start_ea),
                prototype=self._prototype(start_ea),
                pseudocode="",
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    def get_function_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        self.open()
        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        idautils = self._ida["idautils"]

        to_records = [
            self._xref_record(xref)
            for xref in idautils.XrefsTo(start_ea)
            if self._is_interesting_xref(xref)
        ]
        from_records: list[XrefRecord] = []
        seen: set[tuple[str, str, str]] = set()
        for item_ea in idautils.FuncItems(start_ea):
            for xref in idautils.XrefsFrom(item_ea):
                if not self._is_interesting_xref(xref):
                    continue
                record = self._xref_record(xref)
                key = (record.frm, record.to, record.type_name)
                if key not in seen:
                    seen.add(key)
                    from_records.append(record)
        return {"to": to_records, "from": from_records}

    def get_address_xrefs(self, ea: int) -> dict[str, list[XrefRecord]]:
        """Return direct xrefs for a code or data address without requiring a function."""
        self.open()
        idautils = self._ida["idautils"]
        address = parse_address(ea)
        return {
            "to": [
                self._xref_record(xref)
                for xref in idautils.XrefsTo(address)
                if self._is_interesting_xref(xref)
            ],
            "from": [
                self._xref_record(xref)
                for xref in idautils.XrefsFrom(address)
                if self._is_interesting_xref(xref)
            ],
        }

    def get_function_calls(self, ea: int) -> list[CallRecord]:
        self.open()
        func = self._require_func(ea)
        idautils = self._ida["idautils"]
        idc = self._ida["idc"]

        calls: list[CallRecord] = []
        seen: set[tuple[int, int]] = set()
        for item_ea in idautils.FuncItems(int(func.start_ea)):
            mnem = str(idc.print_insn_mnem(item_ea) or "").lower()
            if not self._looks_like_call_mnemonic(mnem):
                continue
            target = int(idc.get_operand_value(item_ea, 0) or 0)
            if target <= 0:
                continue
            key = (int(item_ea), target)
            if key in seen:
                continue
            seen.add(key)
            calls.append(
                CallRecord(
                    call_ea=format_address(int(item_ea)),
                    target_ea=format_address(target),
                    target_name=self._name_at(target),
                    is_import=target in self._import_names_by_ea,
                )
            )
        return calls

    def get_function_strings(self, ea: int) -> list[StringRecord]:
        self.open()
        func = self._require_func(ea)
        idautils = self._ida["idautils"]

        records: list[StringRecord] = []
        seen_values: set[tuple[int, str]] = set()
        for item_ea in idautils.FuncItems(int(func.start_ea)):
            for ref_ea in idautils.DataRefsFrom(item_ea):
                value = self._read_string(int(ref_ea))
                if not value:
                    continue
                key = (int(ref_ea), value)
                if key in seen_values:
                    continue
                seen_values.add(key)
                records.append(
                    StringRecord(
                        ref_ea=format_address(int(item_ea)),
                        string_ea=format_address(int(ref_ea)),
                        value=value,
                    )
                )
        return records

    def get_function_constants(self, ea: int) -> list[int]:
        self.open()
        func = self._require_func(ea)
        idautils = self._ida["idautils"]
        idc = self._ida["idc"]

        values: set[int] = set()
        imm_type = getattr(idc, "o_imm", 5)
        for item_ea in idautils.FuncItems(int(func.start_ea)):
            for operand_index in range(6):
                try:
                    operand_type = int(idc.get_operand_type(item_ea, operand_index))
                except Exception:
                    continue
                if operand_type != imm_type:
                    continue
                value = int(idc.get_operand_value(item_ea, operand_index) or 0)
                if self._is_useful_constant(value):
                    values.add(value)
        return sorted(values)[:200]

    def get_function_imports(self, ea: int) -> list[str]:
        calls = self.get_function_calls(ea)
        imports: list[str] = []
        for call in calls:
            if not call.is_import:
                continue
            name = call.target_name
            if name and name not in imports:
                imports.append(name)
        return imports

    def rename_function(self, ea: int, new_name: str, reason: str = "") -> RenameFunctionResponse:
        self.open()
        if not self.writable:
            return RenameFunctionResponse(
                ea=format_address(parse_address(ea)),
                old_name="",
                new_name=new_name,
                ok=False,
                message="backend is read-only",
            )

        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        ida_name = self._ida["ida_name"]
        idc = self._ida["idc"]

        old_name = self._func_name(start_ea)
        flags = ida_name.SN_CHECK | ida_name.SN_NOWARN
        ok = bool(ida_name.set_name(start_ea, new_name, flags))
        if ok and reason:
            existing = str(idc.get_func_cmt(start_ea, 0) or "")
            suffix = f"VulnAgent rename reason: {reason}"
            comment = f"{existing}\n{suffix}".strip() if existing else suffix
            idc.set_func_cmt(start_ea, comment, 0)
        return RenameFunctionResponse(
            ea=format_address(start_ea),
            old_name=old_name,
            new_name=self._func_name(start_ea),
            ok=ok,
            message="renamed" if ok else "ida_name.set_name returned false",
        )

    def set_function_comment(
        self,
        ea: int,
        comment: str,
        repeatable: bool = False,
        reason: str = "",
    ) -> SetFunctionCommentResponse:
        self.open()
        address = parse_address(ea)
        if not self.writable:
            return SetFunctionCommentResponse(
                ea=format_address(address),
                ok=False,
                old_comment="",
                new_comment=comment,
                message="backend is read-only",
            )

        func = self._require_func(address)
        start_ea = int(func.start_ea)
        idc = self._ida["idc"]
        repeatable_flag = 1 if repeatable else 0
        old_comment = str(idc.get_func_cmt(start_ea, repeatable_flag) or "")
        suffix = f"\nVulnAgent comment reason: {reason}" if reason else ""
        new_comment = f"{comment}{suffix}".strip()
        ok = bool(idc.set_func_cmt(start_ea, new_comment, repeatable_flag))
        return SetFunctionCommentResponse(
            ea=format_address(start_ea),
            ok=ok,
            old_comment=old_comment,
            new_comment=new_comment,
            message="comment updated" if ok else "idc.set_func_cmt returned false",
        )

    def patch_bytes(
        self,
        ea: int,
        patched_hex: str,
        expected_original_hex: str = "",
        reason: str = "",
    ) -> PatchBytesResponse:
        self.open()
        address = parse_address(ea)
        patched = bytes.fromhex(patched_hex)
        if not self.writable:
            return PatchBytesResponse(
                ea=format_address(address),
                size=len(patched),
                patched_hex=patched.hex(),
                ok=False,
                message="backend is read-only",
            )

        original = self._read_bytes(address, len(patched))
        expected = bytes.fromhex(expected_original_hex) if expected_original_hex else b""
        if expected and original != expected:
            return PatchBytesResponse(
                ea=format_address(address),
                size=len(patched),
                original_hex=original.hex(),
                patched_hex=patched.hex(),
                ok=False,
                message="expected_original_hex does not match current bytes",
            )

        ok = self._patch_bytes_raw(address, patched)
        if ok and reason:
            self._set_patch_comment(address, reason)
        return PatchBytesResponse(
            ea=format_address(address),
            size=len(patched),
            original_hex=original.hex(),
            patched_hex=patched.hex(),
            ok=ok,
            message="patched" if ok else "ida_bytes.patch_byte returned false",
        )

    def nop_bytes(self, ea: int, request: NopBytesRequest) -> PatchBytesResponse:
        self.open()
        address = parse_address(ea)
        nop = self._nop_sequence(request.size)
        return self.patch_bytes(
            address,
            nop.hex(),
            expected_original_hex=request.expected_original_hex,
            reason=request.reason,
        )

    def patch_conditional_jump(
        self,
        ea: int,
        request: PatchConditionalJumpRequest,
    ) -> PatchBytesResponse:
        self.open()
        address = parse_address(ea)
        if not self.writable:
            return PatchBytesResponse(
                ea=format_address(address),
                ok=False,
                message="backend is read-only",
            )
        original = self._read_bytes(address, 6)
        patched = self._conditional_jump_patch(address, original, request.mode)
        if patched is None:
            return PatchBytesResponse(
                ea=format_address(address),
                size=0,
                original_hex=original.hex(),
                patched_hex="",
                ok=False,
                message="unsupported conditional jump encoding",
            )
        expected = request.expected_original_hex
        return self.patch_bytes(
            address,
            patched.hex(),
            expected_original_hex=expected,
            reason=request.reason,
        )

    def save_database(self, output_path: str | None = None) -> SaveDatabaseResponse:
        self.open()
        if not self.writable:
            return SaveDatabaseResponse(path="", ok=False, message="backend is read-only")

        ida_loader = self._ida["ida_loader"]
        path = str(output_path or self.idb_path)
        ok = bool(ida_loader.save_database(path, 0))
        return SaveDatabaseResponse(
            path=str(Path(path).resolve()),
            ok=ok,
            message="saved" if ok else "ida_loader.save_database returned false",
        )

    def export_patched_binary(
        self,
        output_path: str | None = None,
        overwrite: bool = False,
        source_path: str | None = None,
    ) -> ExportPatchedBinaryResponse:
        self.open()
        if not self.writable:
            return ExportPatchedBinaryResponse(
                path="",
                ok=False,
                message="backend is read-only",
            )

        source_path = self._input_file_path(source_path)
        if not source_path.exists() or not source_path.is_file():
            return ExportPatchedBinaryResponse(
                path="",
                source_path=str(source_path),
                ok=False,
                message=f"input binary not found: {source_path}",
            )
        if source_path.suffix.lower() in {".idb", ".i64"}:
            return ExportPatchedBinaryResponse(
                path="",
                source_path=str(source_path.resolve()),
                ok=False,
                message=(
                    "refusing to export from an IDA database file; provide source_path "
                    "for the original ELF, for example /path/to/squashfs-root/bin/boa"
                ),
            )

        target_path = Path(output_path).expanduser() if output_path else source_path.with_name(f"{source_path.name}.patched")
        replace_corrupt_elf = False
        if target_path.exists() and not overwrite:
            # A previous implementation could leave a file containing only
            # raw patch bytes.  It is safe to replace that artifact because it
            # is not a valid ELF; valid output still requires overwrite=true.
            try:
                replace_corrupt_elf = (
                    source_path.read_bytes().startswith(b"\x7fELF")
                    and not target_path.read_bytes().startswith(b"\x7fELF")
                )
            except OSError:
                replace_corrupt_elf = False
            if not replace_corrupt_elf:
                return ExportPatchedBinaryResponse(
                    path=str(target_path.resolve()),
                    source_path=str(source_path.resolve()),
                    ok=False,
                    message="output_path already exists; pass overwrite=true to replace it",
                )
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if replace_corrupt_elf:
            self._unlink_export_target(target_path)
        shutil.copy2(source_path, target_path)

        source_data = source_path.read_bytes()
        if source_data.startswith(b"\x7fELF"):
            source_kind = "ELF"
        else:
            source_kind = "binary"

        patches, skipped, mismatched = self._collect_file_backed_patches(source_data)
        if not patches:
            self._unlink_export_target(target_path)
            return ExportPatchedBinaryResponse(
                path=str(target_path.resolve()),
                source_path=str(source_path.resolve()),
                ok=False,
                patched_bytes=0,
                skipped_bytes=skipped,
                mismatched_bytes=mismatched,
                message="no safe file-backed patched bytes found in IDA database",
            )
        if mismatched:
            self._unlink_export_target(target_path)
            return ExportPatchedBinaryResponse(
                path=str(target_path.resolve()),
                source_path=str(source_path.resolve()),
                ok=False,
                patched_bytes=0,
                skipped_bytes=skipped,
                mismatched_bytes=mismatched,
                message=(
                    "patched bytes were not exported because IDA original bytes did not match "
                    "the input file; verify that IDA opened the same original binary"
                ),
            )

        with target_path.open("r+b") as handle:
            for file_offset, value in patches:
                handle.seek(file_offset)
                handle.write(bytes([value & 0xFF]))

        # Never report success for an output that is no longer a valid copy of
        # the input format.  This catches the most damaging failure mode here:
        # treating an IDA virtual address as an ELF file offset.
        output_data = target_path.read_bytes()
        if source_data.startswith(b"\x7fELF") and not output_data.startswith(b"\x7fELF"):
            self._unlink_export_target(target_path)
            return ExportPatchedBinaryResponse(
                path=str(target_path.resolve()),
                source_path=str(source_path.resolve()),
                ok=False,
                patched_bytes=0,
                skipped_bytes=skipped,
                mismatched_bytes=mismatched,
                message="export validation failed: output is not an ELF file",
            )
        if len(output_data) != len(source_data):
            self._unlink_export_target(target_path)
            return ExportPatchedBinaryResponse(
                path=str(target_path.resolve()),
                source_path=str(source_path.resolve()),
                ok=False,
                patched_bytes=0,
                skipped_bytes=skipped,
                mismatched_bytes=mismatched,
                message="export validation failed: output size changed",
            )

        return ExportPatchedBinaryResponse(
            path=str(target_path.resolve()),
            source_path=str(source_path.resolve()),
            ok=True,
            patched_bytes=len(patches),
            skipped_bytes=skipped,
            mismatched_bytes=mismatched,
            message=f"exported patched {source_kind}",
        )

    def close_database(self, save: bool = False) -> None:
        if self._idalib_runtime is not None and self._opened:
            self._idalib_runtime.close_database(bool(save))
        self._opened = False

    # ========================================================================
    # Taint Analysis Tools
    # ========================================================================

    def list_functions(self, pattern: str = "", limit: int = 500) -> list[FunctionEntry]:
        self.open()
        idautils = self._ida["idautils"]
        ida_funcs = self._ida["ida_funcs"]

        results: list[FunctionEntry] = []
        for func_ea in idautils.Functions():
            name = self._func_name(int(func_ea))
            if pattern and not fnmatch(name, pattern):
                continue
            func = ida_funcs.get_func(int(func_ea))
            size = int(func.end_ea - func.start_ea) if func else 0
            results.append(FunctionEntry(
                ea=format_address(int(func_ea)),
                name=name,
                size=size,
            ))
            if len(results) >= limit:
                break
        return results

    def get_imports(self) -> list[ImportEntry]:
        self.open()
        ida_nalt = self._ida["ida_nalt"]
        idc = self._ida["idc"]

        results: list[ImportEntry] = []
        module_names: dict[int, str] = {}

        for index in range(int(ida_nalt.get_import_module_qty())):
            mod_name = ida_nalt.get_import_module_name(index) or ""
            module_names[index] = mod_name

        def callback_factory(mod_idx: int):
            mod_name = module_names.get(mod_idx, "")

            def cb(ea: int, name: str, ordinal: int) -> bool:
                func_name = str(name or f"ord_{ordinal}")
                prototype = str(idc.get_type(int(ea)) or "")
                results.append(ImportEntry(
                    ea=format_address(int(ea)),
                    name=func_name,
                    module=mod_name,
                    prototype=prototype,
                ))
                return True

            return cb

        for index in range(int(ida_nalt.get_import_module_qty())):
            ida_nalt.enum_import_names(index, callback_factory(index))

        return results

    def detect_arch(self) -> ArchInfo:
        self.open()
        try:
            import idaapi as _idaapi  # type: ignore
            inf = _idaapi.get_inf_structure()
        except (AttributeError, ImportError):
            return self._detect_arch_from_idc()

        proc = (inf.procname or "").lower()
        bits = 64 if inf.is_64bit() else (32 if inf.is_32bit() else 16)

        is_be = False
        try:
            if hasattr(inf, "is_be"):
                is_be = bool(inf.is_be())
        except Exception:
            pass

        return self._build_arch_info(proc, bits, is_be)

    def _detect_arch_from_idc(self) -> ArchInfo:
        """Read architecture metadata through the IDA 9 compatible idc API."""
        try:
            idc = self._ida["idc"]
            proc = str(idc.get_inf_attr(idc.INF_PROCNAME) or "").lower()
            lflags = int(idc.get_inf_attr(idc.INF_LFLAGS) or 0)
            model = int(idc.get_inf_attr(idc.INF_MODEL) or 0)
            is_be = bool(lflags & int(idc.LFLG_MSF))
            if lflags & int(idc.LFLG_64BIT):
                bits = 64
            elif model in {ord("2"), 2, 16}:
                bits = 16
            else:
                bits = 32
            return self._build_arch_info(proc, bits, is_be)
        except Exception:
            return ArchInfo(arch="unknown", bits=0, endian="")

    @staticmethod
    def _build_arch_info(proc: str, bits: int, is_be: bool) -> ArchInfo:
        if "arm" in proc:
            arch = "ARM"
        elif "mips" in proc:
            arch = "mipsb" if is_be else "mipsl"
        elif "metapc" in proc or "x86" in proc:
            arch = "x86"
        else:
            arch = proc or "unknown"

        return ArchInfo(
            arch=arch,
            bits=bits,
            endian="big" if is_be else "little",
        )

    def scan_indirect_calls(
        self,
        max_functions: int = 1000,
        max_results: int = 200,
    ) -> IndirectCallScanResult:
        """Scan decompiled functions for function-pointer or table-dispatch calls."""
        self.open()
        idautils = self._ida["idautils"]
        ida_hexrays = self._ida["ida_hexrays"]

        scanned = 0
        failed = 0
        results: list[IndirectCallCandidate] = []
        truncated = False

        for func_ea in idautils.Functions():
            if scanned >= max_functions:
                truncated = True
                break
            scanned += 1
            start_ea = int(func_ea)
            try:
                cfunc = ida_hexrays.decompile(start_ea)
            except Exception:
                failed += 1
                continue
            if not cfunc:
                failed += 1
                continue

            collector = _IndirectCallCollector(
                self._ida,
                start_ea,
                self._func_name(start_ea),
            )
            try:
                collector.apply_to(cfunc.body, None)
            except Exception:
                failed += 1
                continue

            for item in collector.results:
                results.append(IndirectCallCandidate(**item))
                if len(results) >= max_results:
                    truncated = True
                    break
            if truncated:
                break

        return IndirectCallScanResult(
            scanned_functions=scanned,
            failed_decompilations=failed,
            truncated=truncated,
            results=results,
        )

    def find_sink_calls(self, ea: int, sink_specs: dict[str, list]) -> list[SinkCallResult]:
        self.open()
        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        ida_hexrays = self._ida["ida_hexrays"]

        try:
            cfunc = ida_hexrays.decompile(start_ea)
        except Exception:
            return []
        if not cfunc:
            return []

        caller_name = self._func_name(start_ea)
        visitor = _SinkCallVisitor(
            ida=self._ida,
            sink_specs=sink_specs,
            caller_ea=start_ea,
            caller_name=caller_name,
        )
        visitor.apply_to(cfunc.body, None)

        return [
            SinkCallResult(
                loc=r["loc"],
                caller_addr=format_address(start_ea),
                caller_name=caller_name,
                sink_name=r["sink_name"],
                callee_ea=r.get("callee_ea", ""),
                category=r.get("category", "unknown"),
                confidence=r.get("confidence", 0.5),
                args=r["args"],
                score=r["score"],
            )
            for r in visitor.results
        ]

    def scan_sink_calls(
        self,
        sink_specs: dict[str, list],
        roots: list[int] | None = None,
        max_depth: int = 8,
        max_functions: int = 500,
    ) -> SinkScanResult:
        """Scan sink calls from bounded roots, with a bounded global fallback."""
        self.open()
        ida_funcs = self._ida["ida_funcs"]
        idautils = self._ida["idautils"]

        normalized_roots = [parse_address(root) for root in roots or []]
        scope = "provided-roots"
        if not normalized_roots:
            route_analysis = self.find_route_handlers()
            normalized_roots = [parse_address(handler) for handler in route_analysis.handlers]
            scope = "route-handlers"

        queue: deque[tuple[int, int]]
        if normalized_roots:
            queue = deque((root, 0) for root in normalized_roots)
        else:
            scope = "global-fallback"
            queue = deque((int(func_ea), 0) for func_ea in idautils.Functions())

        scanned: set[int] = set()
        queued: set[int] = {ea for ea, _ in queue}
        results: list[SinkCallResult] = []
        seen_results: set[tuple[str, str, str]] = set()
        truncated = False

        while queue:
            if len(scanned) >= max_functions:
                truncated = True
                break

            ea, depth = queue.popleft()
            queued.discard(ea)
            func = ida_funcs.get_func(ea)
            if func is None:
                continue
            func_ea = int(func.start_ea)
            if func_ea in scanned:
                continue
            scanned.add(func_ea)

            for result in self.find_sink_calls(func_ea, sink_specs):
                key = (result.caller_addr, result.loc, result.sink_name)
                if key not in seen_results:
                    seen_results.add(key)
                    results.append(result)

            if scope == "global-fallback" or depth >= max_depth:
                continue
            for call in self.get_function_calls(func_ea):
                if call.is_import or not call.target_ea:
                    continue
                target_ea = parse_address(call.target_ea)
                target_func = ida_funcs.get_func(target_ea)
                if target_func is None:
                    continue
                target_start = int(target_func.start_ea)
                if target_start not in scanned and target_start not in queued:
                    queue.append((target_start, depth + 1))
                    queued.add(target_start)

        return SinkScanResult(
            scope=scope,
            roots=[format_address(root) for root in normalized_roots],
            scanned_functions=len(scanned),
            truncated=truncated,
            results=results,
        )

    def trace_call_chain(
        self,
        ea: int,
        arg_index: int,
        sources: list[str] | None = None,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[CallChainResult]:
        self.open()
        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        sources_set = set(sources) if sources else set()

        engine = _TaintEngine(self._ida, sources_set)
        raw_chains = engine.find_call_chains_bfs(start_ea, arg_index, max_depth, max_chains)

        results: list[CallChainResult] = []
        for chain in raw_chains:
            nodes: list[TaintNodeResult] = []
            taint_verified = False
            has_propagation = False

            for node in chain:
                code = self._decompile_text(node.func_ea)
                nodes.append(TaintNodeResult(
                    func_addr=format_address(node.func_ea),
                    func_name=node.func_name,
                    call_site=format_address(node.call_site) if node.call_site else "",
                    arg_index=node.arg_index,
                    taint_status=node.taint.status.value,
                    taint_reason=node.taint.reason,
                    source_func=node.taint.source_func,
                    source_param=node.taint.source_param,
                    source_expr=node.taint.source_expr,
                    decompiled_code=code,
                ))
                if node.taint.status == _TaintStatus.TAINTED:
                    taint_verified = True
                elif node.taint.status == _TaintStatus.PROPAGATED:
                    has_propagation = True
                elif node.taint.status == _TaintStatus.CLEAN:
                    has_propagation = False

            if not taint_verified and has_propagation:
                taint_verified = True

            chain_str = " -> ".join(n.func_name for n in nodes)
            results.append(CallChainResult(
                chain=nodes,
                taint_verified=taint_verified,
                chain_str=chain_str,
            ))

        return results

    def trace_argument_origin(
        self,
        caller_ea: int,
        call_site: int,
        callee_ea: int,
        target_arg_idx: int,
        sources: list[str] | None = None,
    ) -> ArgumentOriginResult:
        self.open()
        sources_set = set(sources) if sources else set()
        engine = _TaintEngine(self._ida, sources_set)
        taint, next_idx = engine.analyze_arg_propagation(
            caller_ea, call_site, callee_ea, target_arg_idx
        )
        return ArgumentOriginResult(
            taint_status=taint.status.value,
            source_param=taint.source_param,
            source_expr=taint.source_expr,
            source_func=taint.source_func,
            reason=taint.reason,
            next_arg_index=next_idx,
        )

    def batch_decompile(self, addresses: list[int]) -> list[BatchDecompileEntry]:
        self.open()
        results: list[BatchDecompileEntry] = []
        for addr in addresses:
            resp = self.decompile_function(addr)
            results.append(BatchDecompileEntry(
                ea=resp.ea,
                name=resp.name,
                pseudocode=resp.pseudocode,
                ok=resp.ok,
                error=resp.error,
            ))
        return results

    def _decompile_text(self, func_ea: int, max_chars: int = 12000) -> str:
        ida_hexrays = self._ida["ida_hexrays"]
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            text = str(cfunc)
            if max_chars > 0 and len(text) > max_chars:
                return text[:max_chars]
            return text
        except Exception:
            return ""

    # ========================================================================
    # Source Analysis Tools
    # ========================================================================

    def scan_source_candidates(
        self, limit: int = 100, min_score: float = 25.0
    ) -> SourceScanResult:
        """Heuristic scan of all functions to find likely taint sources.

        Uses the xref-density + string-constant-ratio fingerprint that
        distinguishes param-getters (websGetVar, nvram_get, etc.) from
        all other function types.

        Ported from source/get_sources.py universal_source_scan.
        """
        self.open()
        idautils = self._ida["idautils"]
        ida_funcs = self._ida["ida_funcs"]

        total_funcs = 0
        func_entries: list[tuple[int, str, int]] = []

        for func_ea in idautils.Functions():
            total_funcs += 1
            func_obj = ida_funcs.get_func(int(func_ea))
            if not func_obj:
                continue
            size = int(func_obj.end_ea - func_obj.start_ea)
            if size > 0x500 or size < 0x10:
                continue
            name = self._func_name(int(func_ea))
            if _is_source_blacklisted(name):
                continue
            count = sum(1 for _ in idautils.CodeRefsTo(int(func_ea), 0))
            if count < 5:
                continue
            func_entries.append((int(func_ea), name, count))

        func_entries.sort(key=lambda x: x[2], reverse=True)
        top = func_entries[:limit]

        candidates: list[SourceCandidate] = []
        for func_ea, func_name, xref_count in top:
            call_info = self._analyze_call_sites(func_ea, max_sites=30)
            if call_info["total_calls"] < 3:
                continue
            score, reasons = _score_source_candidate(func_ea, func_name, xref_count, call_info)

            best_pos = 1
            best_ratio = 0.0
            for pos in range(3):
                if call_info["total_calls"] > 0:
                    r = call_info["arg_str_hits"][pos] / call_info["total_calls"]
                    if r > best_ratio:
                        best_ratio = r
                        best_pos = pos
            sample_strs = list(call_info["arg_strings"].get(best_pos, []))[:8]

            if score >= min_score:
                try:
                    code = self._decompile_text(func_ea, max_chars=2000)
                except Exception:
                    code = ""
                candidates.append(SourceCandidate(
                    ea=format_address(func_ea),
                    name=func_name,
                    score=round(score, 1),
                    xref_count=xref_count,
                    string_ratio=round(best_ratio, 3),
                    reasons=reasons,
                    sample_strings=sample_strs,
                    decompiled_code=code,
                ))

        candidates.sort(key=lambda c: c.score, reverse=True)
        return SourceScanResult(
            total_functions=total_funcs,
            candidates_scanned=len(top),
            results=candidates,
        )

    @staticmethod
    def _analyze_call_sites(func_ea: int, max_sites: int = 30) -> dict:
        """Sample call sites and count string-constant args per position (ported from get_sources.py)."""
        import idaapi as _idaapi
        import ida_hexrays as _idahx
        import idautils as _idautils
        import ida_funcs as _idafuncs
        import ida_bytes as _idabytes

        info: dict = {
            "total_calls": 0,
            "arg_str_hits": {0: 0, 1: 0, 2: 0},
            "arg_strings": {0: [], 1: [], 2: []},
        }

        xrefs = list(_idautils.CodeRefsTo(func_ea, 0))
        if len(xrefs) > max_sites:
            xrefs = random.sample(xrefs, max_sites) if xrefs else []

        for xref in xrefs:
            caller = _idafuncs.get_func(xref)
            if not caller:
                continue
            try:
                cfunc = _idahx.decompile(caller.start_ea)
            except Exception:
                continue
            if not cfunc:
                continue

            collector = _CallExprCollector()
            try:
                collector.apply_to(cfunc.body, None)
            except Exception:
                continue

            for call_expr in collector.calls:
                callee = call_expr.x
                if callee.op != _idaapi.cot_obj or callee.obj_ea != func_ea:
                    continue
                info["total_calls"] += 1
                for arg_idx in range(min(3, len(call_expr.a))):
                    arg = call_expr.a[arg_idx]
                    str_val = _get_str_constant(arg, _idabytes)
                    if str_val is not None:
                        info["arg_str_hits"][arg_idx] += 1
                        if str_val and len(info["arg_strings"].get(arg_idx, [])) < 32:
                            info["arg_strings"].setdefault(arg_idx, []).append(str_val)

        return info

    def find_route_handlers(self) -> RouteAnalysisResult:
        """Discover route registrations and cross-handler callees in stripped web firmware.

        Finds patterns like websDefineAction("route", handler_func) without
        needing symbols, then identifies functions commonly called across
        those handlers (likely param-getters).

        Ported from source/get_sources.py find_route_registration_functions
        and find_common_param_getters.
        """
        self.open()
        idautils = self._ida["idautils"]
        ida_funcs = self._ida["ida_funcs"]
        ida_hexrays = self._ida["ida_hexrays"]

        callee_regs: dict[int, list[tuple[str, int, int]]] = {}

        for func_ea in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(int(func_ea))
            except Exception:
                continue
            if not cfunc:
                continue

            collector = _CallExprCollector()
            try:
                collector.apply_to(cfunc.body, None)
            except Exception:
                continue

            for call_expr in collector.calls:
                if len(call_expr.a) < 2:
                    continue
                callee_ea = _resolve_callee_ea(call_expr.x)
                if not callee_ea:
                    continue

                for str_pos, ptr_pos in [(0, 1), (1, 2)]:
                    if ptr_pos >= len(call_expr.a):
                        continue
                    route_name = _get_str_constant(call_expr.a[str_pos], self._ida["ida_bytes"])
                    if not route_name:
                        continue
                    handler_arg = call_expr.a[ptr_pos]
                    handler_ea = _resolve_callee_ea(handler_arg)
                    if not handler_ea or ida_funcs.get_func(handler_ea) is None:
                        continue
                    callee_regs.setdefault(callee_ea, []).append(
                        (route_name, handler_ea, int(func_ea))
                    )

        registrations: list[RouteRegistration] = []
        handlers: set[int] = set()

        for callee_ea, regs in callee_regs.items():
            if len(regs) >= 5:
                reg_name = self._func_name(callee_ea)
                for route_name, handler_ea, _caller in regs:
                    handler_name = self._func_name(handler_ea)
                    registrations.append(RouteRegistration(
                        registration_ea=format_address(callee_ea),
                        registration_name=reg_name,
                        route_name=route_name,
                        handler_ea=format_address(handler_ea),
                        handler_name=handler_name,
                    ))
                    handlers.add(handler_ea)

        handler_list = list(handlers)
        cross_callees = self._find_cross_handler_callees(handler_list)

        return RouteAnalysisResult(
            registrations=registrations,
            handlers=[format_address(h) for h in handler_list],
            cross_handler_callees=cross_callees,
        )

    def _find_cross_handler_callees(
        self, handler_eas: list[int], min_ratio: float = 0.3
    ) -> list[CrossHandlerCallee]:
        """Find functions called by multiple handlers — likely param getters.

        Ported from source/get_sources.py find_common_param_getters.
        """
        if not handler_eas:
            return []

        ida_hexrays = self._ida["ida_hexrays"]
        freq: dict[int, int] = {}
        total = 0

        for handler_ea in handler_eas:
            if total >= 20:  # sample at most 20 handlers
                break
            total += 1
            try:
                cfunc = ida_hexrays.decompile(handler_ea)
            except Exception:
                continue
            if not cfunc:
                continue

            collector = _CallExprCollector()
            try:
                collector.apply_to(cfunc.body, None)
            except Exception:
                continue

            seen: set[int] = set()
            for call_expr in collector.calls:
                callee_ea = _resolve_callee_ea(call_expr.x)
                if callee_ea and callee_ea not in seen:
                    seen.add(callee_ea)
                    freq[callee_ea] = freq.get(callee_ea, 0) + 1

        threshold = max(2, total * min_ratio)
        results: list[CrossHandlerCallee] = []
        for ea, count in freq.items():
            if count >= threshold:
                name = self._func_name(ea)
                if _is_source_blacklisted(name):
                    continue
                try:
                    code = self._decompile_text(ea, max_chars=1500)
                except Exception:
                    code = ""
                results.append(CrossHandlerCallee(
                    ea=format_address(ea),
                    name=name,
                    handler_count=count,
                    total_handlers=total,
                    ratio=round(count / max(total, 1), 3),
                    decompiled_code=code,
                ))

        results.sort(key=lambda c: c.handler_count, reverse=True)
        return results

    def propagate_sources(
        self, sources: list[str], max_rounds: int = 5
    ) -> SourcePropagateResult:
        """Propagate source labels through wrapper functions using AST analysis.

        If function f returns the result of calling a known source, mark f as
        a source too. Handles the common pattern where firmware wraps raw input
        functions behind convenience helpers.

        Ported from source/get_sources.py propagate_sources.
        """
        self.open()
        idautils = self._ida["idautils"]
        ida_funcs = self._ida["ida_funcs"]
        ida_hexrays = self._ida["ida_hexrays"]

        source_set = {_normalize_lookup_key(s) for s in sources}
        source_set.update(_normalize_lookup_key(source) for source in COMMON_TAINT_SOURCE_NAMES)
        new_sources: list[str] = []

        for round_num in range(max_rounds):
            round_new = 0
            for func_ea in idautils.Functions():
                name = self._func_name(int(func_ea))
                normed = _normalize_lookup_key(name)
                if normed in source_set or _is_source_blacklisted(name):
                    continue

                try:
                    cfunc = ida_hexrays.decompile(int(func_ea))
                except Exception:
                    continue
                if not cfunc:
                    continue

                # Skip large functions (not wrappers)
                func_obj = ida_funcs.get_func(int(func_ea))
                if func_obj and (int(func_obj.end_ea - func_obj.start_ea)) > 0x500:
                    continue

                call_collector = _CallExprCollector()
                ret_collector = _ReturnExprCollector()
                try:
                    call_collector.apply_to(cfunc.body, None)
                    ret_collector.apply_to(cfunc.body, None)
                except Exception:
                    continue

                out_specs: list[str] = []
                source_callee_count = 0

                for call_expr in call_collector.calls:
                    callee_name = _resolve_callee_name(call_expr.x, self._ida["ida_name"])
                    if not callee_name or _normalize_lookup_key(callee_name) not in source_set:
                        continue
                    source_callee_count += 1

                    if source_callee_count > 3:
                        break  # too many sources → likely handler, not wrapper

                    for ret_expr in ret_collector.returns:
                        if ret_expr is not None and _expr_depends_on(call_expr, ret_expr):
                            out_specs.append("return")
                            break

                if not out_specs or source_callee_count > 3:
                    continue

                out_specs = list(dict.fromkeys(out_specs))
                source_set.add(normed)
                new_sources.append(name)
                round_new += 1

            if round_new == 0:
                break

        return SourcePropagateResult(
            new_sources=new_sources,
            rounds=round_num + 1 if round_new > 0 else round_num,
        )

    def analyze_as_source(self, ea: int) -> SourceCandidate:
        """Analyze a single function to determine if it matches the param-getter pattern.

        Checks argument count, return type, string-constant call-site ratio,
        xref density, and internal callee patterns. Returns a detailed score
        and reasoning suitable for agent review.

        Ported from source/get_sources.py analyze_param_getter_pattern.
        """
        self.open()
        import ida_hexrays as _idahx
        import idautils as _idautils
        import ida_funcs as _idafuncs
        import ida_bytes as _idabytes

        func = self._require_func(ea)
        start_ea = int(func.start_ea)
        func_name = self._func_name(start_ea)

        if _is_source_blacklisted(func_name):
            return SourceCandidate(
                ea=format_address(start_ea),
                name=func_name,
                score=0,
                reasons=["blacklisted — cannot be a source"],
            )

        try:
            cfunc = _idahx.decompile(start_ea)
        except Exception:
            return SourceCandidate(
                ea=format_address(start_ea),
                name=func_name,
                score=0,
                reasons=["decompilation failed"],
            )
        if not cfunc:
            return SourceCandidate(
                ea=format_address(start_ea),
                name=func_name,
                score=0,
                reasons=["decompilation failed"],
            )

        args = cfunc.arguments or []
        arg_count = len(args)
        if arg_count < 2 or arg_count > 4:
            return SourceCandidate(
                ea=format_address(start_ea),
                name=func_name,
                score=0,
                reasons=[f"unlikely arg count ({arg_count}) — param getters have 2-4 args"],
            )

        func_obj = _idafuncs.get_func(start_ea)
        if func_obj and (int(func_obj.end_ea - func_obj.start_ea)) > 0x300:
            return SourceCandidate(
                ea=format_address(start_ea),
                name=func_name,
                score=0,
                reasons=["function too large for a getter"],
            )

        score = 0
        reasons: list[str] = []

        ret_type = cfunc.type.get_rettype()
        if ret_type and ret_type.is_ptr():
            score += 15
            reasons.append("returns pointer type")
        else:
            score -= 10

        # Check if callees include output/sink functions (negative signal)
        calls = self.get_function_calls(start_ea)
        callee_names = [c.target_name.lower() for c in calls if c.target_name]
        sink_keywords = {"printf", "fprintf", "sprintf", "puts", "fputs",
                         "write", "send", "syslog", "webswrite"}
        sink_hits = sum(1 for name in callee_names if any(s in name for s in sink_keywords))
        if sink_hits > 0:
            score -= 15 * sink_hits
            reasons.append(f"calls {sink_hits} output/sink functions (negative)")

        # Call-site string-constant analysis
        string_const_calls = 0
        param_names: list[str] = []
        total_call_sites = 0

        xrefs = list(_idautils.CodeRefsTo(start_ea, 0))
        for xref in xrefs[:30]:
            caller_func = _idafuncs.get_func(xref)
            if not caller_func:
                continue
            try:
                caller_cfunc = _idahx.decompile(caller_func.start_ea)
            except Exception:
                continue
            if not caller_cfunc:
                continue

            call_collector = _CallExprCollector()
            try:
                call_collector.apply_to(caller_cfunc.body, None)
            except Exception:
                continue

            for call_expr in call_collector.calls:
                callee_ea = _resolve_callee_ea(call_expr.x)
                if callee_ea != start_ea:
                    continue
                total_call_sites += 1
                if len(call_expr.a) > 1:
                    str_val = _get_str_constant(call_expr.a[1], _idabytes)
                    if str_val is not None:
                        string_const_calls += 1
                        param_names.append(str_val)

        if total_call_sites > 0:
            ratio = string_const_calls / total_call_sites
            if ratio > 0.7:
                score += 30
                reasons.append(f"called with string constants {string_const_calls}/{total_call_sites}")
            elif ratio > 0.3:
                score += 15
                reasons.append("sometimes called with string constants")

        # HTTP param keyword detection
        http_kws = {"user", "pass", "name", "id", "cmd", "action", "ip", "mac", "ssid",
                     "proto", "port", "host", "url", "path", "key", "value", "data",
                     "addr", "mask", "dns", "gateway", "mode", "flag", "type", "enable"}
        bad_indicators = {"%", "error", "fail", "warn", "log", "debug", "\\n", ":", "/"}
        cleaned = [p for p in param_names if not any(b in p for b in bad_indicators) and len(p) <= 32 and " " not in p]
        http_hits = sum(1 for p in cleaned if any(kw in p.lower() for kw in http_kws))
        if http_hits > 2:
            score += 25
            reasons.append(f"param names look like HTTP params: {cleaned[:5]}")
        elif http_hits > 0:
            score += 10

        xref_count = len(xrefs)
        if xref_count > 20:
            score += 15
            reasons.append(f"high xref count ({xref_count})")
        elif xref_count > 5:
            score += 8

        string_ops = {"strcmp", "strstr", "strchr", "strlen"}
        if any(op in name for name in callee_names for op in string_ops):
            score += 5
            reasons.append("contains string operations")

        is_source = score >= 60
        reasons.insert(0, f"{'SOURCE' if is_source else 'NOT source'} (score={score}/100)")

        try:
            code = self._decompile_text(start_ea, max_chars=2000)
        except Exception:
            code = ""

        return SourceCandidate(
            ea=format_address(start_ea),
            name=func_name,
            score=round(float(score), 1),
            xref_count=xref_count,
            string_ratio=round(string_const_calls / max(total_call_sites, 1), 3),
            reasons=reasons,
            sample_strings=list(dict.fromkeys(cleaned))[:8],
            decompiled_code=code,
        )

    def _require_func(self, ea: int) -> Any:
        address = parse_address(ea)
        ida_funcs = self._ida["ida_funcs"]
        func = ida_funcs.get_func(address)
        if func is None:
            raise ValueError(f"no function contains {format_address(address)}")
        return func

    def _func_name(self, ea: int) -> str:
        idc = self._ida["idc"]
        return str(idc.get_func_name(ea) or f"sub_{ea:x}")

    def _prototype(self, ea: int) -> str:
        idc = self._ida["idc"]
        return str(idc.get_type(ea) or "")

    def _read_bytes(self, ea: int, size: int) -> bytes:
        ida_bytes = self._ida["ida_bytes"]
        values: list[int] = []
        for offset in range(max(0, size)):
            value = int(ida_bytes.get_byte(ea + offset))
            if value < 0:
                raise ValueError(f"failed to read byte at {format_address(ea + offset)}")
            values.append(value & 0xFF)
        return bytes(values)

    def _patch_bytes_raw(self, ea: int, data: bytes) -> bool:
        ida_bytes = self._ida["ida_bytes"]
        ok = True
        for offset, value in enumerate(data):
            ok = bool(ida_bytes.patch_byte(ea + offset, value)) and ok
        return ok

    def _input_file_path(self, explicit_source_path: str | None = None) -> Path:
        ida_nalt = self._ida.get("ida_nalt")
        idc = self._ida.get("idc")
        candidates: list[str] = []

        if explicit_source_path:
            candidates.append(explicit_source_path)

        for owner in (ida_nalt, idc):
            getter = getattr(owner, "get_input_file_path", None)
            if getter is None:
                continue
            try:
                value = str(getter() or "").strip()
            except Exception:
                continue
            if value:
                candidates.append(value)

        candidates.append(self.idb_path)
        for candidate in list(candidates):
            path = Path(candidate).expanduser()
            if path.suffix.lower() in {".idb", ".i64"}:
                stem_path = path.with_suffix("")
                candidates.extend([
                    str(stem_path),
                    str(path.with_name(stem_path.name)),
                ])

        for candidate in candidates:
            path = Path(candidate).expanduser()
            if path.exists() and path.is_file() and path.suffix.lower() not in {".idb", ".i64"}:
                return path
        for candidate in candidates:
            path = Path(candidate).expanduser()
            if path.exists() and path.is_file():
                return path
        return Path(candidates[0]).expanduser() if candidates else Path(self.idb_path).expanduser()

    def _collect_file_backed_patches(self, source_data: bytes) -> tuple[list[tuple[int, int]], int, int]:
        ida_bytes = self._ida["ida_bytes"]
        idautils = self._ida["idautils"]
        idc = self._ida["idc"]
        ida_loader = self._ida.get("ida_loader")
        elf_segments = self._elf_load_segments(source_data)

        patches: list[tuple[int, int]] = []
        seen_offsets: set[int] = set()
        skipped = 0
        mismatched = 0

        def visit(ea: int, fpos: int, original: int, patched: int) -> int:
            nonlocal skipped, mismatched
            original_byte = int(original) & 0xFF
            candidate_offsets: list[int] = []

            # For ELF, derive the offset from PT_LOAD first.  It remains
            # correct for stripped binaries with no section header, and avoids
            # versions of IDALib that report an invalid fpos for MIPS inputs.
            for offset in self._elf_file_offsets_for_ea(int(ea), elf_segments):
                candidate_offsets.append(offset)
            if int(fpos) >= 0:
                candidate_offsets.append(int(fpos))
            if ida_loader is not None:
                try:
                    loader_offset = int(ida_loader.get_fileregion_offset(int(ea)))
                except Exception:
                    loader_offset = -1
                if loader_offset >= 0:
                    candidate_offsets.append(loader_offset)

            file_offset = next(
                (
                    offset
                    for offset in candidate_offsets
                    if 0 <= offset < len(source_data)
                    and offset not in seen_offsets
                    and source_data[offset] == original_byte
                ),
                -1,
            )
            if file_offset < 0:
                skipped += 1
                if any(0 <= offset < len(source_data) for offset in candidate_offsets):
                    mismatched += 1
                return 0
            if file_offset < 4 and source_data.startswith(b"\x7fELF"):
                skipped += 1
                return 0
            seen_offsets.add(file_offset)
            patches.append((file_offset, int(patched) & 0xFF))
            return 0

        for seg_ea in idautils.Segments():
            start = int(seg_ea)
            end = int(idc.get_segm_end(start) or start)
            if end <= start:
                continue
            ida_bytes.visit_patched_bytes(start, end, visit)

        patches.sort(key=lambda item: item[0])
        return patches, skipped, mismatched

    @staticmethod
    def _elf_load_segments(data: bytes) -> list[tuple[int, int, int, int]]:
        """Return (vaddr, memsz, file_offset, file_size) for PT_LOAD segments."""
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return []
        elf_class = data[4]
        endian = ">" if data[5] == 2 else "<" if data[5] == 1 else ""
        if not endian:
            return []
        try:
            if elf_class == 1:
                phoff = struct.unpack_from(f"{endian}I", data, 28)[0]
                phentsize = struct.unpack_from(f"{endian}H", data, 42)[0]
                phnum = struct.unpack_from(f"{endian}H", data, 44)[0]
                fields = ("I", 4, 8, 16, 20)
            elif elf_class == 2 and len(data) >= 64:
                phoff = struct.unpack_from(f"{endian}Q", data, 32)[0]
                phentsize = struct.unpack_from(f"{endian}H", data, 54)[0]
                phnum = struct.unpack_from(f"{endian}H", data, 56)[0]
                fields = ("Q", 8, 16, 32, 40)
            else:
                return []
        except struct.error:
            return []

        segments: list[tuple[int, int, int, int]] = []
        for index in range(int(phnum)):
            offset = int(phoff) + index * int(phentsize)
            if offset < 0 or offset + int(phentsize) > len(data):
                continue
            try:
                p_type = struct.unpack_from(f"{endian}I", data, offset)[0]
                if p_type != 1:
                    continue
                word, offset_pos, vaddr_pos, filesz_pos, memsz_pos = fields
                p_offset = struct.unpack_from(f"{endian}{word}", data, offset + offset_pos)[0]
                p_vaddr = struct.unpack_from(f"{endian}{word}", data, offset + vaddr_pos)[0]
                p_filesz = struct.unpack_from(f"{endian}{word}", data, offset + filesz_pos)[0]
                p_memsz = struct.unpack_from(f"{endian}{word}", data, offset + memsz_pos)[0]
            except struct.error:
                continue
            if p_filesz and p_offset < len(data):
                segments.append((int(p_vaddr), int(p_memsz), int(p_offset), int(p_filesz)))
        return segments

    @staticmethod
    def _elf_file_offsets_for_ea(
        ea: int,
        segments: list[tuple[int, int, int, int]],
    ) -> list[int]:
        offsets: list[int] = []
        for vaddr, _memsz, file_offset, file_size in segments:
            if vaddr <= ea < vaddr + file_size:
                offsets.append(file_offset + (ea - vaddr))
        return offsets

    def _unlink_export_target(self, target_path: Path) -> None:
        try:
            target_path.unlink(missing_ok=True)
        except Exception:
            return

    def _set_patch_comment(self, ea: int, reason: str) -> None:
        idc = self._ida.get("idc")
        if idc is None:
            return
        try:
            existing = str(idc.get_cmt(ea, 0) or "")
            suffix = f"VulnAgent patch reason: {reason}"
            comment = f"{existing}\n{suffix}".strip() if existing else suffix
            idc.set_cmt(ea, comment, 0)
        except Exception:
            return

    def _nop_sequence(self, size: int) -> bytes:
        arch = self.detect_arch()
        proc = arch.arch.lower()
        if "mips" in proc:
            return b"\x00" * size
        return b"\x90" * size

    def _conditional_jump_patch(self, ea: int, original: bytes, mode: str) -> bytes | None:
        arch = self.detect_arch()
        proc = arch.arch.lower()
        if "mips" in proc:
            return self._mips_conditional_jump_patch(original[:4], arch.endian, mode)
        return self._x86_conditional_jump_patch(original, mode)

    def _x86_conditional_jump_patch(self, original: bytes, mode: str) -> bytes | None:
        if len(original) < 2:
            return None

        first = original[0]
        if 0x70 <= first <= 0x7F:
            if mode == "invert":
                return bytes([first ^ 0x01, original[1]])
            if mode == "force_taken":
                return bytes([0xEB, original[1]])
            if mode == "force_not_taken":
                return b"\x90\x90"
            return None

        if len(original) >= 6 and first == 0x0F and 0x80 <= original[1] <= 0x8F:
            if mode == "invert":
                return bytes([0x0F, original[1] ^ 0x01]) + original[2:6]
            if mode == "force_not_taken":
                return b"\x90" * 6
            return None

        return None

    def _mips_conditional_jump_patch(
        self,
        original: bytes,
        endian: str,
        mode: str,
    ) -> bytes | None:
        if len(original) < 4:
            return None
        byteorder = "big" if endian == "big" else "little"
        word = int.from_bytes(original[:4], byteorder=byteorder)
        opcode = (word >> 26) & 0x3F
        immediate = word & 0xFFFF

        if opcode not in {0x04, 0x05}:  # beq / bne
            return None
        if mode == "invert":
            patched_opcode = 0x05 if opcode == 0x04 else 0x04
            patched = (word & 0x03FFFFFF) | (patched_opcode << 26)
        elif mode == "force_taken":
            patched = (0x04 << 26) | immediate
        elif mode == "force_not_taken":
            patched = 0
        else:
            return None
        return int(patched).to_bytes(4, byteorder=byteorder)

    def _name_at(self, ea: int) -> str:
        idc = self._ida["idc"]
        return str(
            self._import_names_by_ea.get(ea)
            or idc.get_func_name(ea)
            or idc.get_name(ea)
            or ""
        )

    def _xref_record(self, xref: Any) -> XrefRecord:
        return XrefRecord(
            frm=format_address(int(xref.frm)),
            to=format_address(int(xref.to)),
            type_name=self._xref_type_name(int(xref.type)),
            is_code=bool(getattr(xref, "iscode", False)),
        )

    def _xref_type_name(self, xref_type: int) -> str:
        ida_xref = self._ida["ida_xref"]
        mapping = {
            getattr(ida_xref, "fl_CF", -1): "call_far",
            getattr(ida_xref, "fl_CN", -2): "call_near",
            getattr(ida_xref, "fl_JF", -3): "jump_far",
            getattr(ida_xref, "fl_JN", -4): "jump_near",
            getattr(ida_xref, "dr_R", -5): "data_read",
            getattr(ida_xref, "dr_W", -6): "data_write",
            getattr(ida_xref, "dr_O", -7): "data_offset",
        }
        return mapping.get(xref_type, str(xref_type))

    def _is_interesting_xref(self, xref: Any) -> bool:
        ida_xref = self._ida["ida_xref"]
        flow_type = getattr(ida_xref, "fl_F", None)
        if flow_type is not None and int(xref.type) == int(flow_type):
            return False
        return True

    def _collect_import_names(self) -> dict[int, str]:
        ida_nalt = self._ida["ida_nalt"]
        imports: dict[int, str] = {}

        def callback(ea: int, name: str, ordinal: int) -> bool:
            imports[int(ea)] = str(name or f"ord_{ordinal}")
            return True

        for index in range(int(ida_nalt.get_import_module_qty())):
            ida_nalt.enum_import_names(index, callback)
        return imports

    def _looks_like_call_mnemonic(self, mnemonic: str) -> bool:
        if not mnemonic:
            return False
        prefixes = ("call", "bl", "jal", "bal", "bsr")
        return mnemonic.startswith(prefixes)

    def _read_string(self, ea: int) -> str:
        idc = self._ida["idc"]
        try:
            raw = idc.get_strlit_contents(ea)
        except Exception:
            raw = None
        if raw is None:
            return ""
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    def _is_useful_constant(self, value: int) -> bool:
        if value in {0, 1, 2, 4, 8}:
            return False
        if value < 0:
            return False
        return value <= 0xFFFFFFFFFFFFFFFF

    def _callee_names(self, calls: list[CallRecord]) -> list[str]:
        names: list[str] = []
        for call in calls:
            value = call.target_name or call.target_ea
            if value and value not in names:
                names.append(value)
        return names

    def _caller_addresses(self, xrefs_to: list[XrefRecord]) -> list[str]:
        callers: list[str] = []
        for record in xrefs_to:
            if record.type_name not in {"call_far", "call_near"}:
                continue
            if record.frm not in callers:
                callers.append(record.frm)
        return callers

    def _confidence_hints(
        self,
        imports_used: list[str],
        strings: list[StringRecord],
        constants: list[int],
    ) -> list[str]:
        hints: list[str] = []
        if imports_used:
            hints.append(f"uses imports: {', '.join(imports_used[:12])}")
        command_words = ("cmd", "system", "exec", "sh", "telnet", "passwd", "error")
        interesting_strings = [
            record.value for record in strings if any(word in record.value.lower() for word in command_words)
        ]
        if interesting_strings:
            hints.append(f"interesting strings: {', '.join(interesting_strings[:8])}")
        if constants:
            hints.append(f"notable constants: {', '.join(hex(value) for value in constants[:12])}")
        return hints


# ============================================================================
# Internal Taint Analysis Engine (ported from source/get_ccs.py & get_vds.py)
# ============================================================================

_NORMALIZE_RE = re.compile(r"^j_|^__imp_")
_EA_FUZZY_RANGE = 0x20
_MAX_TRACE_DEPTH = 8


def _normalize_func_name(name: str) -> str:
    name = name.strip()
    if name.startswith("j_"):
        name = name[2:]
    if name.startswith("__imp_"):
        name = name[6:]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def _normalize_lookup_key(name: str) -> str:
    return _normalize_func_name(name).lower()


COMMON_TAINT_SOURCE_NAMES = {
    "websGetVar",
    "websGetVarString",
    "websGetVarInt",
    "websGetVarLong",
    "cgiGetValue",
    "cgiGetVariable",
    "cgiGetVal",
    "cgiFormString",
    "cgiFormStringNoNewlines",
    "cgiFormInteger",
    "get_cgi",
    "getCgi",
    "getcgiparam",
    "getenv",
    "nvram_get",
    "nvram_safe_get",
    "acosNvramConfig_get",
    "getQueryString",
    "getRequestParam",
    "getRequestHeader",
    "recv",
    "recvfrom",
    "read",
}


class _TaintStatus(Enum):
    TAINTED = "tainted"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    PROPAGATED = "propagated"


@dataclass
class _TaintInfo:
    status: _TaintStatus
    source_param: int | None = None
    source_expr: str = ""
    source_func: str = ""
    reason: str = ""


@dataclass
class _CallChainNode:
    func_ea: int
    func_name: str
    call_site: int = 0
    arg_index: int = 0
    taint: _TaintInfo = field(default_factory=lambda: _TaintInfo(_TaintStatus.UNKNOWN))


class _SinkCallVisitor:
    """Ctree visitor that finds calls to sink functions (ported from get_vds.py)."""

    def __init__(
        self,
        ida: dict[str, Any],
        sink_specs: dict[str, list],
        caller_ea: int,
        caller_name: str,
    ) -> None:
        self._ida = ida
        self.sink_specs = {
            _normalize_lookup_key(name): specs
            for name, specs in sink_specs.items()
        }
        self.caller_ea = caller_ea
        self.caller_name = caller_name
        self.results: list[dict] = []

    def apply_to(self, body: Any, parent: Any) -> None:
        ida_hexrays = self._ida["ida_hexrays"]
        visitor = _SinkCallCtreeVisitor(
            ida_hexrays, self._ida, self.sink_specs, self.caller_ea, self.caller_name
        )
        visitor.apply_to(body, parent)
        self.results = visitor.results


class _SinkCallCtreeVisitor:
    """Actual ctree_visitor_t subclass (created at runtime to avoid import-time IDA dependency)."""

    def __init__(
        self,
        ida_hexrays: Any,
        ida: dict[str, Any],
        sink_specs: dict[str, list],
        caller_ea: int,
        caller_name: str,
    ) -> None:
        self._ida = ida
        self.sink_specs = sink_specs
        self.caller_ea = caller_ea
        self.caller_name = caller_name
        self.results: list[dict] = []
        self._seen: set[tuple] = set()

        class Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(inner_self):
                super().__init__(ida_hexrays.CV_FAST)
                inner_self.outer = self

            def visit_expr(inner_self, expr):
                return inner_self.outer._visit_expr(expr)

        self._visitor = Visitor()

    def apply_to(self, body: Any, parent: Any) -> None:
        self._visitor.apply_to(body, parent)

    def _visit_expr(self, expr: Any) -> int:
        import idaapi as _idaapi  # type: ignore

        if expr.op != _idaapi.cot_call:
            return 0

        callee = self._resolve_callee(expr.x)
        if callee is None:
            return 0
        callee_name, callee_ea = callee

        specs = self.sink_specs.get(_normalize_lookup_key(callee_name))
        if not specs:
            return 0

        arglist = list(expr.a)
        argcount = len(arglist)
        indices = self._specs_to_indices(specs, argcount)
        if not indices:
            return 0

        args = []
        for idx in indices:
            arg_expr = arglist[idx - 1]
            arg_type = self._classify_arg(arg_expr)
            if arg_type == "constant":
                continue
            weight = {"pointer": 1.0, "variable": 0.6}.get(arg_type, 0.0)
            args.append({
                "index": idx,
                "expr": self._expr_text(arg_expr),
                "arg_type": arg_type,
                "weight": weight,
            })

        if not args:
            return 0

        call_ea = expr.ea
        loc = format_address(int(call_ea)) if call_ea != _idaapi.BADADDR else ""
        key = (call_ea, callee_name, self.caller_ea)
        if key in self._seen:
            return 0
        self._seen.add(key)

        max_weight = max(a["weight"] for a in args)
        self.results.append({
            "loc": loc,
            "sink_name": callee_name,
            "callee_ea": callee_ea,
            "category": "unknown",
            "confidence": 0.5,
            "args": args,
            "score": round(0.5 * max_weight, 4),
        })
        return 0

    def _resolve_callee(self, callee_expr: Any) -> tuple[str, str] | None:
        import idaapi as _idaapi  # type: ignore

        inner = callee_expr
        while inner.op in {_idaapi.cot_cast, _idaapi.cot_ptr, _idaapi.cot_ref}:
            inner = inner.x

        ida_name = self._ida["ida_name"]
        if inner.op == _idaapi.cot_obj:
            name = ida_name.get_name(inner.obj_ea)
            callee_ea = format_address(int(inner.obj_ea))
        elif inner.op == _idaapi.cot_helper:
            name = inner.helper
            callee_ea = ""
        else:
            return None

        if not name:
            return None
        return _normalize_func_name(name), callee_ea

    def _classify_arg(self, expr: Any) -> str:
        import idaapi as _idaapi  # type: ignore

        if expr.op in {_idaapi.cot_num, _idaapi.cot_fnum, _idaapi.cot_str}:
            return "constant"

        inner = expr
        while inner.op == _idaapi.cot_cast:
            inner = inner.x

        if inner.op in {_idaapi.cot_ptr, _idaapi.cot_memptr, _idaapi.cot_ref}:
            return "pointer"

        try:
            tif = inner.type
            if tif and not tif.is_unknown() and tif.is_ptr():
                return "pointer"
        except Exception:
            pass

        return "variable"

    def _expr_text(self, expr: Any) -> str:
        try:
            import ida_lines as _ida_lines  # type: ignore
            return _ida_lines.tag_remove(expr.print1(None)).strip()
        except Exception:
            try:
                return expr.dstr()
            except Exception:
                return "?"

    def _specs_to_indices(self, specs: list, argcount: int) -> list[int]:
        indices: set[int] = set()
        if argcount <= 0:
            return []
        for spec in specs:
            if not isinstance(spec, (list, tuple)):
                continue
            kind = spec[0]
            if kind == "index":
                v = spec[1]
                if 1 <= v <= argcount:
                    indices.add(v)
            elif kind == "range":
                for v in range(max(1, spec[1]), min(spec[2], argcount) + 1):
                    indices.add(v)
            elif kind in {">", ">=", "<", "<="}:
                v = spec[1]
                if kind == ">":
                    start, end = v + 1, argcount
                elif kind == ">=":
                    start, end = v, argcount
                elif kind == "<":
                    start, end = 1, v - 1
                else:
                    start, end = 1, v
                for idx in range(max(1, start), min(end, argcount) + 1):
                    indices.add(idx)
        return sorted(indices)


class _TaintEngine:
    """Core taint analysis engine (ported from source/get_ccs.py).

    Performs BFS backward call-chain tracing with Hex-Rays ctree-based
    data flow analysis. All state is instance-local (no globals).
    """

    def __init__(self, ida: dict[str, Any], sources: set[str]) -> None:
        self._ida = ida
        self._sources = {_normalize_lookup_key(source) for source in sources}
        self._sources.update(_normalize_lookup_key(source) for source in COMMON_TAINT_SOURCE_NAMES)
        self._decompile_cache: dict[int, Any] = {}

    def _decompile_cached(self, func_ea: int) -> Any:
        if func_ea in self._decompile_cache:
            return self._decompile_cache[func_ea]
        try:
            import idaapi as _idaapi  # type: ignore
            result = _idaapi.decompile(func_ea)
        except Exception:
            result = None
        self._decompile_cache[func_ea] = result
        return result

    def _get_func_name(self, ea: int) -> str:
        ida_name = self._ida["ida_name"]
        name = ida_name.get_name(ea)
        if not name:
            return f"sub_{ea:X}"
        return _normalize_func_name(name)

    def _is_source(self, func_name: str) -> bool:
        return _normalize_lookup_key(func_name) in self._sources

    def _get_callers(self, func_ea: int) -> list[tuple[int, int]]:
        idautils = self._ida["idautils"]
        ida_funcs = self._ida["ida_funcs"]
        ida_xref = self._ida["ida_xref"]

        callers = []
        for xref in idautils.XrefsTo(func_ea, 0):
            if xref.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
                continue
            caller_func = ida_funcs.get_func(xref.frm)
            if not caller_func:
                continue
            callers.append((int(caller_func.start_ea), int(xref.frm)))
        return callers

    def find_call_chains_bfs(
        self,
        target_func_ea: int,
        target_arg_idx: int,
        max_depth: int = 20,
        max_chains: int = 5,
    ) -> list[list[_CallChainNode]]:
        target_name = self._get_func_name(target_func_ea)

        queue: deque[tuple[int, int, list[_CallChainNode]]] = deque()
        start_node = _CallChainNode(
            func_ea=target_func_ea,
            func_name=target_name,
            arg_index=target_arg_idx,
        )
        queue.append((target_func_ea, target_arg_idx, [start_node]))

        visited = {target_func_ea}
        chains: list[list[_CallChainNode]] = []

        while queue and len(chains) < max_chains:
            curr_ea, curr_arg_idx, path = queue.popleft()

            if len(path) >= max_depth:
                chains.append(list(reversed(path)))
                continue

            curr_name = self._get_func_name(curr_ea)

            if len(path) > 1 and self._is_source(curr_name):
                path[-1].taint = _TaintInfo(
                    _TaintStatus.TAINTED,
                    source_func=curr_name,
                    reason=f"reached SOURCE: {curr_name}",
                )
                chains.append(list(reversed(path)))
                continue

            callers = self._get_callers(curr_ea)
            if not callers:
                chains.append(list(reversed(path)))
                continue

            if len(callers) > 50:
                callers = callers[:50]

            for caller_ea, call_site in callers:
                if caller_ea in visited:
                    continue

                caller_name = self._get_func_name(caller_ea)
                visited.add(caller_ea)

                taint_info, new_arg_idx = self.analyze_arg_propagation(
                    caller_ea, call_site, curr_ea, curr_arg_idx
                )

                node = _CallChainNode(
                    func_ea=caller_ea,
                    func_name=caller_name,
                    call_site=call_site,
                    arg_index=new_arg_idx,
                    taint=taint_info,
                )

                new_path = path + [node]

                if taint_info.status == _TaintStatus.TAINTED:
                    chains.append(list(reversed(new_path)))
                    continue

                if taint_info.status == _TaintStatus.CLEAN:
                    chains.append(list(reversed(new_path)))
                    continue

                queue.append((caller_ea, new_arg_idx, new_path))

        return chains

    def analyze_arg_propagation(
        self,
        caller_ea: int,
        call_site: int,
        callee_ea: int,
        target_arg_idx: int,
    ) -> tuple[_TaintInfo, int]:
        cfunc = self._decompile_cached(caller_ea)
        if not cfunc:
            return _TaintInfo(_TaintStatus.UNKNOWN, reason="decompilation failed"), target_arg_idx

        arg_node, arg_text = self._extract_call_arg(cfunc, call_site, callee_ea, target_arg_idx)

        if arg_node is not None:
            taint = self._trace_expr_origin(arg_node, cfunc)
            if taint.status == _TaintStatus.TAINTED:
                return taint, 0
            if taint.status == _TaintStatus.CLEAN:
                return taint, 0
            if taint.status == _TaintStatus.PROPAGATED:
                next_idx = taint.source_param if taint.source_param else target_arg_idx
                return taint, next_idx
            if taint.reason:
                return taint, target_arg_idx

        if arg_text:
            if self._is_constant_text(arg_text):
                return _TaintInfo(_TaintStatus.CLEAN, source_expr=arg_text, reason=f"constant: {arg_text}"), 0
            arg_idx = self._extract_arg_index_text(arg_text)
            if arg_idx:
                return _TaintInfo(
                    _TaintStatus.PROPAGATED, source_param=arg_idx,
                    source_expr=arg_text, reason=f"propagated from arg {arg_idx}"
                ), arg_idx

        return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=arg_text or "", reason="complex expression"), target_arg_idx

    def _extract_call_arg(
        self, cfunc: Any, call_site: int, callee_ea: int, target_arg_idx: int
    ) -> tuple[Any | None, str]:
        """Find the AST node and text of a specific argument at a call site.

        Uses CallArgExtractor (ctree visitor) for exact match first, then fuzzy
        EA matching within _EA_FUZZY_RANGE bytes.
        """
        extractor = _CallArgExtractor(self._ida, call_site, callee_ea, target_arg_idx)
        extractor.apply_to(cfunc.body, None)

        if not extractor.found:
            extractor.try_fuzzy(_EA_FUZZY_RANGE)

        if extractor.found:
            return extractor.result_node, extractor.result_text
        return None, ""

    def _trace_expr_origin(self, expr_node: Any, cfunc: Any, depth: int = 0) -> _TaintInfo:
        """Recursively trace the data origin of an expression node (ported from get_ccs.py trace_expr_origin)."""
        import idaapi as _idaapi  # type: ignore

        if depth > _MAX_TRACE_DEPTH:
            text = self._safe_expr_text(expr_node)
            return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=text, reason="trace depth exceeded")

        op = expr_node.op

        # Constants
        if op == _idaapi.cot_num:
            return _TaintInfo(_TaintStatus.CLEAN, source_expr=self._safe_expr_text(expr_node), reason="numeric constant")
        if op == _idaapi.cot_str:
            return _TaintInfo(_TaintStatus.CLEAN, source_expr=self._safe_expr_text(expr_node), reason="string constant")
        if op == _idaapi.cot_fnum:
            return _TaintInfo(_TaintStatus.CLEAN, source_expr=self._safe_expr_text(expr_node), reason="float constant")

        # Global object
        if op == _idaapi.cot_obj:
            name = self._get_func_name(expr_node.obj_ea)
            if name in self._sources:
                return _TaintInfo(_TaintStatus.TAINTED, source_expr=name, reason=f"source object: {name}")
            return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=name, reason=f"global: {name}")

        # Local variable — the most critical path
        if op == _idaapi.cot_var:
            return self._trace_var_origin(expr_node, cfunc, depth)

        # Function call return value
        if op == _idaapi.cot_call:
            return self._trace_call_return(expr_node, cfunc, depth)

        # Cast → pass through
        if op == _idaapi.cot_cast:
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Address-of → pass through
        if op == _idaapi.cot_ref:
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Dereference → trace pointer
        if op == _idaapi.cot_ptr:
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Struct member → trace base
        if op in (_idaapi.cot_memref, _idaapi.cot_memptr):
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Array index → trace base
        if op == _idaapi.cot_idx:
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Arithmetic / bitwise → either operand tainted => propagate
        if op in (
            _idaapi.cot_add, _idaapi.cot_sub, _idaapi.cot_bor,
            _idaapi.cot_band, _idaapi.cot_xor,
            _idaapi.cot_mul, _idaapi.cot_sdiv, _idaapi.cot_udiv,
        ):
            left = self._trace_expr_origin(expr_node.x, cfunc, depth + 1)
            if left.status in (_TaintStatus.TAINTED, _TaintStatus.PROPAGATED):
                return left
            right = self._trace_expr_origin(expr_node.y, cfunc, depth + 1)
            if right.status in (_TaintStatus.TAINTED, _TaintStatus.PROPAGATED):
                return right
            if left.status == _TaintStatus.CLEAN and right.status == _TaintStatus.CLEAN:
                return _TaintInfo(_TaintStatus.CLEAN, source_expr=self._safe_expr_text(expr_node), reason="both operands clean")
            return left

        # Ternary a ? b : c
        if op == _idaapi.cot_tern:
            then_r = self._trace_expr_origin(expr_node.y, cfunc, depth + 1)
            if then_r.status == _TaintStatus.TAINTED:
                return then_r
            else_r = self._trace_expr_origin(expr_node.z, cfunc, depth + 1)
            if else_r.status == _TaintStatus.TAINTED:
                return else_r
            if then_r.status == _TaintStatus.PROPAGATED:
                return then_r
            if else_r.status == _TaintStatus.PROPAGATED:
                return else_r
            return then_r

        # Logical NOT, bitwise NOT, negation → pass through
        if op in (_idaapi.cot_lnot, _idaapi.cot_bnot, _idaapi.cot_neg):
            return self._trace_expr_origin(expr_node.x, cfunc, depth + 1)

        # Comma operator (a, b) → result is last expression
        if op == _idaapi.cot_comma:
            return self._trace_expr_origin(expr_node.y, cfunc, depth + 1)

        # Assignment (x = y) → trace RHS
        if op == _idaapi.cot_asg:
            return self._trace_expr_origin(expr_node.y, cfunc, depth + 1)

        return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=self._safe_expr_text(expr_node),
                          reason=f"unhandled op {op}")

    def _trace_var_origin(self, expr_node: Any, cfunc: Any, depth: int) -> _TaintInfo:
        """Trace origin of a local variable."""

        var_idx = expr_node.v.idx
        lvars = cfunc.get_lvars()
        if var_idx >= len(lvars):
            return _TaintInfo(_TaintStatus.UNKNOWN, reason=f"invalid var idx {var_idx}")
        lvar = lvars[var_idx]

        # Function parameter → PROPAGATED
        if lvar.is_arg_var:
            arg_num = self._get_param_index_for_lvar(var_idx, cfunc)
            return _TaintInfo(
                _TaintStatus.PROPAGATED,
                source_param=arg_num,
                source_expr=lvar.name,
                reason=f"from caller param {lvar.name}",
            )

        # Local variable → find assignments, trace RHS
        finder = _VarAssignFinder(self._ida, var_idx)
        finder.apply_to(cfunc.body, None)

        if not finder.assignments:
            return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=lvar.name,
                              reason=f"var {lvar.name}: no def found")

        if len(finder.assignments) == 1:
            _, rhs = finder.assignments[0]
            return self._trace_expr_origin(rhs, cfunc, depth + 1)

        # Multiple assignments — if any RHS is tainted, propagate
        best = _TaintInfo(_TaintStatus.UNKNOWN, reason="multi-assign: all unknown")
        for _, rhs in finder.assignments:
            r = self._trace_expr_origin(rhs, cfunc, depth + 1)
            if r.status == _TaintStatus.TAINTED:
                return r
            if r.status == _TaintStatus.PROPAGATED and best.status != _TaintStatus.TAINTED:
                best = r
            if r.status == _TaintStatus.UNKNOWN and best.status == _TaintStatus.UNKNOWN:
                best = r
        return best

    def _trace_call_return(self, expr_node: Any, cfunc: Any, depth: int) -> _TaintInfo:
        """Trace the return value of a function call."""
        import idaapi as _idaapi  # type: ignore

        callee = expr_node.x
        if callee.op == _idaapi.cot_obj:
            callee_name = _normalize_func_name(self._get_func_name(callee.obj_ea))

            if self._is_source(callee_name):
                return _TaintInfo(
                    _TaintStatus.TAINTED,
                    source_expr=self._safe_expr_text(expr_node),
                    source_func=callee_name,
                    reason=f"return from SOURCE: {callee_name}",
                )

            # Shallow trace: check if any arg to the callee is tainted
            arglist = list(expr_node.a)
            propagated_args: list[_TaintInfo] = []
            for i, arg in enumerate(arglist):
                arg_result = self._trace_expr_origin(arg, cfunc, depth + 1)
                if arg_result.status == _TaintStatus.TAINTED:
                    return _TaintInfo(
                        _TaintStatus.TAINTED,
                        source_expr=self._safe_expr_text(expr_node),
                        source_func=arg_result.source_func,
                        reason=f"arg {i + 1} of {callee_name}() is tainted: {arg_result.reason}",
                    )
                if arg_result.status == _TaintStatus.PROPAGATED:
                    propagated_args.append(arg_result)

            if len(propagated_args) == 1:
                return _TaintInfo(
                    _TaintStatus.PROPAGATED,
                    source_param=propagated_args[0].source_param,
                    source_expr=self._safe_expr_text(expr_node),
                    reason=f"sole propagated arg of {callee_name}(): {propagated_args[0].reason}",
                )

        callee_name = self._safe_expr_text(callee)
        return _TaintInfo(_TaintStatus.UNKNOWN, source_expr=self._safe_expr_text(expr_node),
                          reason=f"return from {callee_name}")

    def _get_param_index_for_lvar(self, var_idx: int, cfunc: Any) -> int | None:
        """Map a local variable index back to its 1-based parameter number."""
        lvars = cfunc.get_lvars()
        if var_idx >= len(lvars):
            return None
        target_lvar = lvars[var_idx]
        if not target_lvar.is_arg_var:
            return None
        m = re.match(r"^a(\d+)$", target_lvar.name)
        if m:
            return int(m.group(1))
        arg_count = 0
        for i in range(len(lvars)):
            if lvars[i].is_arg_var:
                arg_count += 1
                if i == var_idx:
                    return arg_count
        return None

    @staticmethod
    def _safe_expr_text(expr_node: Any) -> str:
        try:
            import ida_lines as _ida_lines  # type: ignore
            return _ida_lines.tag_remove(expr_node.print1(None)).strip()
        except Exception:
            try:
                return expr_node.dstr()
            except Exception:
                return "?"

    @staticmethod
    def _is_constant_text(expr: str) -> bool:
        expr = expr.strip()
        if not expr:
            return False
        if expr in {"0", "NULL", "nullptr", "0LL", "0i64"}:
            return True
        if re.match(r'^".*"$', expr):
            return True
        if re.match(r'^\d+$', expr):
            return True
        if re.match(r'^0x[0-9a-fA-F]+$', expr):
            return True
        return False

    @staticmethod
    def _extract_arg_index_text(expr: str) -> int | None:
        expr = expr.strip()
        m = re.match(r"^a(\d+)$", expr)
        if m:
            return int(m.group(1))
        m = re.match(r"^(?:\([^)]+\)\s*)*[&*]*a(\d+)$", expr)
        if m:
            return int(m.group(1))
        return None


class _CallArgExtractor:
    """Ctree visitor that extracts a specific argument from a call expression.

    Uses exact EA matching first, then falls back to fuzzy matching.
    """

    def __init__(self, ida: dict[str, Any], call_site: int, callee_ea: int, target_arg_idx: int) -> None:
        self._ida = ida
        self.call_site = call_site
        self.callee_ea = callee_ea
        self.target_arg_idx = target_arg_idx
        self.result_node: Any = None
        self.result_text: str = ""
        self.found = False
        self._fallback_calls: list[Any] = []

        ida_hexrays = ida["ida_hexrays"]

        class _Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(vis_self):
                super().__init__(ida_hexrays.CV_FAST)
                vis_self.outer = self

            def visit_expr(vis_self, expr):
                return vis_self.outer._visit_expr(expr)

        self._visitor = _Visitor()

    def apply_to(self, body: Any, parent: Any) -> None:
        self._visitor.apply_to(body, parent)

    def try_fuzzy(self, max_range: int) -> None:
        if self.found or not self._fallback_calls:
            return
        closest = min(self._fallback_calls, key=lambda e: abs(e.ea - self.call_site))
        if abs(closest.ea - self.call_site) <= max_range:
            self._extract(closest)

    def _visit_expr(self, expr: Any) -> int:
        import idaapi as _idaapi  # type: ignore

        if self.found:
            return 0
        if expr.op != _idaapi.cot_call:
            return 0

        callee = expr.x
        if callee.op == _idaapi.cot_obj:
            if callee.obj_ea != self.callee_ea:
                return 0
        else:
            self._fallback_calls.append(expr)
            return 0

        if expr.ea == self.call_site:
            self._extract(expr)
            return 0

        self._fallback_calls.append(expr)
        return 0

    def _extract(self, call_expr: Any) -> None:
        if self.target_arg_idx < 1:
            return
        arglist = list(call_expr.a)
        if self.target_arg_idx > len(arglist):
            return
        arg = arglist[self.target_arg_idx - 1]
        self.result_node = arg
        try:
            import ida_lines as _ida_lines  # type: ignore
            self.result_text = _ida_lines.tag_remove(arg.print1(None)).strip()
        except Exception:
            self.result_text = arg.dstr()
        self.found = True


class _VarAssignFinder:
    """Ctree visitor that finds all assignments to a specific local variable."""

    def __init__(self, ida: dict[str, Any], var_idx: int) -> None:
        self._ida = ida
        self.var_idx = var_idx
        self.assignments: list[tuple[int, Any]] = []

        ida_hexrays = ida["ida_hexrays"]

        class _Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(vis_self):
                super().__init__(ida_hexrays.CV_FAST)
                vis_self.outer = self

            def visit_expr(vis_self, expr):
                return vis_self.outer._visit_expr(expr)

        self._visitor = _Visitor()

    def apply_to(self, body: Any, parent: Any) -> None:
        self._visitor.apply_to(body, parent)

    def _visit_expr(self, expr: Any) -> int:
        import idaapi as _idaapi  # type: ignore

        if expr.op != _idaapi.cot_asg:
            return 0
        lhs = expr.x
        if lhs.op != _idaapi.cot_var:
            return 0
        if lhs.v.idx != self.var_idx:
            return 0
        self.assignments.append((expr.ea, expr.y))
        return 0


# ============================================================================
# Source Analysis Helpers (ported from source/get_sources.py)
# ============================================================================

_NOT_SOURCE_BLACKLIST: set[str] = {
    "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "wcscmp",
    "strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "memset",
    "bcopy", "bzero", "wmemcpy", "wcscpy", "wcscat",
    "strstr", "strchr", "strrchr", "strpbrk", "strtok", "strsep",
    "strtok_r", "index", "rindex",
    "strlen", "strnlen", "wcslen",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "puts", "fputs", "putchar", "fputc",
    "syslog", "perror", "dprintf",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll",
    "strtoull", "strtod", "strtof", "strtold",
    "htonl", "htons", "ntohl", "ntohs", "inet_addr", "inet_ntoa",
    "inet_pton", "inet_ntop",
    "malloc", "calloc", "realloc", "free", "mmap", "munmap", "brk", "sbrk",
    "alloca", "posix_memalign", "memalign", "valloc",
    "write", "send", "sendto", "sendmsg", "fwrite",
    "websWrite", "websResponse", "websDone", "websRedirect",
    "websError", "websHeader", "websFooter",
    "open", "close", "fclose", "fflush", "fseek", "ftell", "rewind",
    "stat", "fstat", "lstat", "access", "unlink", "rename", "mkdir", "rmdir",
    "chmod", "chown", "chdir",
    "system", "popen", "exec", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "fork", "vfork", "exit", "_exit",
    "kill", "signal", "raise", "abort", "doSystem",
    "assert", "__assert_fail", "openlog", "closelog",
    "abs", "labs", "pow", "sqrt", "log", "exp", "ceil", "floor",
    "sin", "cos", "tan", "rand", "srand",
    "time", "gettimeofday", "clock", "sleep", "usleep", "nanosleep",
    "socket", "bind", "listen", "connect", "shutdown",
    "setsockopt", "getsockopt",
    "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "sem_wait", "sem_post",
    "websSetVar", "websFormHandler", "websCgiGatherOutput",
    "websEncode64", "websDecode64", "websGetDateString",
    "websAccept", "websTimeout", "websUrlParse", "websValidateUrl",
    "websReadEvent",
    "nvram_bufset", "nvram_set", "nvram_commit", "nvram_close",
    "ejArgs", "ejSetResult", "ejLexGetToken",
    "killProcByName", "checkSemicolon",
}

_NOT_SOURCE_PREFIXES = (
    "print", "log", "debug", "err", "warn", "die", "assert",
    "pthread_", "sem_", "mutex_",
)


def _is_source_blacklisted(name: str) -> bool:
    normed = _normalize_func_name(name)
    if normed in _NOT_SOURCE_BLACKLIST:
        return True
    lower = normed.lower()
    if lower.startswith(_NOT_SOURCE_PREFIXES):
        return True
    return False


class _CallExprCollector:
    """Ctree visitor that collects all call expressions in a function body."""

    def __init__(self) -> None:
        self.calls: list[Any] = []
        self._imports_done = False

    def apply_to(self, body: Any, parent: Any) -> None:
        self._ensure_imports()
        self._visitor.apply_to(body, parent)

    def _ensure_imports(self) -> None:
        if self._imports_done:
            return
        import ida_hexrays as _idahx  # type: ignore
        import idaapi as _idaapi  # type: ignore

        class _Visitor(_idahx.ctree_visitor_t):
            def __init__(vis_self):
                super().__init__(_idahx.CV_FAST)
                vis_self.outer = self

            def visit_expr(vis_self, expr):
                if expr.op == _idaapi.cot_call:
                    vis_self.outer.calls.append(expr)
                return 0

        self._visitor = _Visitor()
        self._imports_done = True


class _IndirectCallCollector:
    """Ctree visitor that records indirect call expressions in one function."""

    def __init__(self, ida: dict[str, Any], caller_ea: int, caller_name: str) -> None:
        self._ida = ida
        self.caller_ea = caller_ea
        self.caller_name = caller_name
        self.results: list[dict[str, Any]] = []
        self._seen: set[tuple[str, str]] = set()
        self._imports_done = False

    def apply_to(self, body: Any, parent: Any) -> None:
        self._ensure_imports()
        self._visitor.apply_to(body, parent)

    def _ensure_imports(self) -> None:
        if self._imports_done:
            return
        import ida_hexrays as _idahx  # type: ignore
        import idaapi as _idaapi  # type: ignore

        class _Visitor(_idahx.ctree_visitor_t):
            def __init__(vis_self):
                super().__init__(_idahx.CV_FAST)
                vis_self.outer = self

            def visit_expr(vis_self, expr):
                if expr.op == _idaapi.cot_call:
                    vis_self.outer._visit_call(expr)
                return 0

        self._visitor = _Visitor()
        self._imports_done = True

    def _visit_call(self, expr: Any) -> None:
        import idaapi as _idaapi  # type: ignore

        target = _strip_call_target_wrappers(expr.x)
        if target.op in {_idaapi.cot_obj, _idaapi.cot_helper}:
            return
        if _resolve_callee_ea(expr.x) is not None:
            return

        call_ea = "" if expr.ea == _idaapi.BADADDR else format_address(int(expr.ea))
        target_expr = _safe_ctree_expr_text(expr.x)
        call_expr = _safe_ctree_expr_text(expr)
        key = (call_ea, target_expr)
        if key in self._seen:
            return
        self._seen.add(key)

        kind, confidence, evidence = _classify_indirect_call_target(target)
        self.results.append(
            {
                "caller_ea": format_address(self.caller_ea),
                "caller_name": self.caller_name,
                "call_ea": call_ea,
                "expr": call_expr,
                "target_expr": target_expr,
                "kind": kind,
                "confidence": confidence,
                "evidence": evidence,
            }
        )


class _ReturnExprCollector:
    """Ctree visitor that collects return expressions in a function body."""

    def __init__(self) -> None:
        self.returns: list[Any] = []
        self._imports_done = False

    def apply_to(self, body: Any, parent: Any) -> None:
        self._ensure_imports()
        self._visitor.apply_to(body, parent)

    def _ensure_imports(self) -> None:
        if self._imports_done:
            return
        import ida_hexrays as _idahx  # type: ignore
        import idaapi as _idaapi  # type: ignore

        class _Visitor(_idahx.ctree_visitor_t):
            def __init__(vis_self):
                super().__init__(_idahx.CV_FAST)
                vis_self.outer = self

            def visit_expr(vis_self, expr):
                if expr.op == _idaapi.cot_return:
                    vis_self.outer.returns.append(expr)
                return 0

        self._visitor = _Visitor()
        self._imports_done = True


def _get_str_constant(expr: Any, ida_bytes: Any) -> str | None:
    """Return the string value if expr is a string literal, else None."""
    import idaapi as _idaapi  # type: ignore

    if expr.op == _idaapi.cot_str:
        try:
            return str(expr.string)
        except Exception:
            try:
                raw = ida_bytes.get_strlit_contents(expr.obj_ea, -1, 3)
                if raw:
                    if isinstance(raw, bytes):
                        return raw.decode("utf-8", errors="replace")
                    return str(raw)
            except Exception:
                pass
            return None

    if expr.op == _idaapi.cot_obj:
        try:
            flags = ida_bytes.get_full_flags(expr.obj_ea)
            if ida_bytes.is_strlit(flags):
                raw = ida_bytes.get_strlit_contents(expr.obj_ea, -1, 3)
                if raw:
                    if isinstance(raw, bytes):
                        return raw.decode("utf-8", errors="replace")
                    return str(raw)
        except Exception:
            pass

    return None


def _resolve_callee_ea(expr: Any) -> int | None:
    """Resolve the effective address of a callee expression."""
    import idaapi as _idaapi  # type: ignore

    inner = _strip_call_target_wrappers(expr)
    if inner.op == _idaapi.cot_obj:
        return int(inner.obj_ea)
    return None


def _strip_call_target_wrappers(expr: Any) -> Any:
    """Remove non-semantic wrappers around a call target expression."""
    import idaapi as _idaapi  # type: ignore

    inner = expr
    while inner.op in {_idaapi.cot_cast, _idaapi.cot_ptr, _idaapi.cot_ref}:
        inner = inner.x
    return inner


def _safe_ctree_expr_text(expr_node: Any) -> str:
    try:
        import ida_lines as _ida_lines  # type: ignore
        return _ida_lines.tag_remove(expr_node.print1(None)).strip()
    except Exception:
        try:
            return expr_node.dstr()
        except Exception:
            return "?"


def _classify_indirect_call_target(expr: Any) -> tuple[str, float, list[str]]:
    import idaapi as _idaapi  # type: ignore

    op = expr.op
    if op == _idaapi.cot_var:
        return "function_pointer_call", 0.75, [
            "call target is a local variable or function pointer",
            "direct callee address is unavailable",
        ]
    if op in {_idaapi.cot_memptr, _idaapi.cot_memref}:
        return "callback_field_call", 0.85, [
            "call target is loaded from a structure field",
            "direct callee address is unavailable",
        ]
    if op == _idaapi.cot_idx:
        return "callback_table_call", 0.85, [
            "call target is loaded from an indexed table expression",
            "direct callee address is unavailable",
        ]
    if op == _idaapi.cot_ptr:
        return "function_pointer_deref_call", 0.8, [
            "call target is dereferenced before the call",
            "direct callee address is unavailable",
        ]
    return "indirect_call", 0.6, [
        f"call target expression op={int(op)} is not a direct function object",
        "direct callee address is unavailable",
    ]


def _resolve_callee_name(expr: Any, ida_name: Any) -> str | None:
    """Resolve the name of a callee expression."""
    import idaapi as _idaapi  # type: ignore

    inner = expr
    while inner.op in {_idaapi.cot_cast, _idaapi.cot_ptr, _idaapi.cot_ref}:
        inner = inner.x
    if inner.op == _idaapi.cot_obj:
        name = ida_name.get_name(inner.obj_ea)
    elif inner.op == _idaapi.cot_helper:
        name = inner.helper
    else:
        return None
    if not name:
        return None
    return _normalize_func_name(name)


def _expr_depends_on(call_expr: Any, ret_expr: Any) -> bool:
    """Check if ret_expr's text contains call_expr's text (simple string match)."""
    try:
        call_str = call_expr.dstr() or ""
        ret_str = ret_expr.dstr() or ""
    except Exception:
        return False
    return bool(call_str and ret_str and call_str in ret_str)


def _score_source_candidate(
    func_ea: int,
    func_name: str,
    xref_count: int,
    call_info: dict,
) -> tuple[float, list[str]]:
    """Composite scoring for source candidates (ported from get_sources.py _score_candidate)."""
    reasons: list[str] = []
    total = call_info["total_calls"]

    if total <= 0:
        return 0.0, ["no call sites"]

    # Best string-constant ratio across arg positions
    best_ratio = 0.0
    best_pos = 1
    for pos in range(3):
        r = call_info["arg_str_hits"][pos] / total
        if r > best_ratio:
            best_ratio = r
            best_pos = pos

    if best_ratio < 0.2:
        return 0.0, [f"low string ratio ({best_ratio:.2f})"]

    raw = math.log2(xref_count + 1) * (best_ratio ** 2) * 10

    # Bonuses
    bonuses = 0.0
    if best_ratio > 0.7:
        bonuses += 8
        reasons.append("very high string consistency")
    if best_pos == 1:
        bonuses += 5
    if xref_count > 30:
        bonuses += 5
        reasons.append("very high call frequency")

    # Sample string diversity
    sample = call_info["arg_strings"].get(best_pos, [])
    unique = len(set(sample))
    if unique >= 5:
        bonuses += 5
        reasons.append(f"high string diversity ({unique} unique)")

    score = raw + bonuses

    # Penalties
    penalties = 0.0
    if best_ratio < 0.4:
        penalties += 5
        reasons.append("moderate string consistency (penalty)")
    if best_pos != 1:
        penalties += 3

        # Too many call sites may indicate utility, not source
    if total > 80:
        penalties += 3
        reasons.append("very high call site count (penalty)")

    final = max(0.0, score - penalties)
    reasons.insert(0, f"xref={xref_count} ratio={best_ratio:.2f}")
    return round(final, 1), reasons
