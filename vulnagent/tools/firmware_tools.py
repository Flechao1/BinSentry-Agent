from __future__ import annotations

import json
from typing import Any

from vulnagent.firmware.scanner import (
    FirmwareFilesystemScanner,
    attach_ida_backend_commands,
)
from vulnagent.tools.recon_tools import _json_result


class FirmwareFilesystemTools:
    """Agent-facing wrappers for extracted firmware filesystem analysis."""

    def scan_firmware_filesystem(
        self,
        root: str,
        limit: int = 20,
        ida_host: str = "127.0.0.1",
        ida_port: int = 8765,
    ) -> str:
        """Scan an extracted firmware filesystem and rank binaries for IDA analysis."""
        report = FirmwareFilesystemScanner(root).scan(limit=limit)
        attach_ida_backend_commands(report, host=ida_host, port=ida_port, read_only=True)
        lines = [
            f"Firmware filesystem: {report.root}",
            (
                f"Files={report.total_files}, ELF={report.elf_files}, "
                f"web_endpoints={len(report.web_endpoints)}, "
                f"sensitive_files={len(report.sensitive_files)}"
            ),
            "",
            "Top binary candidates:",
        ]
        for candidate in report.candidates[:limit]:
            reason_text = "; ".join(candidate.reasons[:5])
            marker_text = ", ".join(
                (candidate.route_markers + candidate.source_markers + candidate.sink_markers)[:8]
            )
            lines.append(
                f"{candidate.rank}. {candidate.relative_path} "
                f"(score={candidate.score}, arch={candidate.machine}/{candidate.elf_class}/{candidate.endian})"
            )
            if reason_text:
                lines.append(f"   reasons: {reason_text}")
            if marker_text:
                lines.append(f"   markers: {marker_text}")
            if candidate.web_endpoints:
                lines.append(f"   endpoints: {', '.join(candidate.web_endpoints[:5])}")
            if candidate.startup_references:
                lines.append(f"   startup refs: {', '.join(candidate.startup_references[:3])}")
            if candidate.ida_backend_command:
                lines.append(f"   next: {candidate.ida_backend_command}")

        if report.web_endpoints:
            lines.extend(["", "Web endpoint samples:"])
            for endpoint in report.web_endpoints[:15]:
                target = f" -> {endpoint.candidate}" if endpoint.candidate else ""
                lines.append(f"- {endpoint.endpoint} ({endpoint.source_file}){target}")

        if report.sensitive_files:
            lines.extend(["", "Sensitive file samples:"])
            for path in report.sensitive_files[:10]:
                lines.append(f"- {path}")

        return _json_result(
            "\n".join(lines),
            firmware_filesystem={
                "root": report.root,
                "total_files": report.total_files,
                "elf_files": report.elf_files,
                "text_files_scanned": report.text_files_scanned,
                "web_endpoints": [endpoint.__dict__ for endpoint in report.web_endpoints[:100]],
                "sensitive_files": report.sensitive_files[:100],
            },
            binary_candidates=[
                {
                    "rank": candidate.rank,
                    "path": candidate.path,
                    "relative_path": candidate.relative_path,
                    "score": candidate.score,
                    "size": candidate.size,
                    "machine": candidate.machine,
                    "elf_class": candidate.elf_class,
                    "endian": candidate.endian,
                    "elf_type": candidate.elf_type,
                    "reasons": candidate.reasons,
                    "route_markers": candidate.route_markers,
                    "source_markers": candidate.source_markers,
                    "sink_markers": candidate.sink_markers,
                    "referenced_by": candidate.referenced_by,
                    "web_references": candidate.web_references,
                    "startup_references": candidate.startup_references,
                    "config_references": candidate.config_references,
                    "web_endpoints": candidate.web_endpoints,
                    "ida_backend_command": candidate.ida_backend_command,
                }
                for candidate in report.candidates[:limit]
            ],
        )


def parse_tool_json(value: str) -> dict[str, Any]:
    return json.loads(value)
