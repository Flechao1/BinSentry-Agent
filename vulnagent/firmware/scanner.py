from __future__ import annotations

import argparse
import json
import os
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


DEFAULT_MAX_STRING_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 512 * 1024

WEB_DIR_PARTS = {
    "www",
    "web",
    "htdocs",
    "html",
    "cgi-bin",
    "cgi",
}

EXEC_DIR_SUFFIXES = {
    "bin",
    "sbin",
    "usr/bin",
    "usr/sbin",
}

WEB_SERVER_NAMES = (
    "lighttpd",
    "mini_httpd",
    "boa",
    "goahead",
    "httpd",
    "thttpd",
    "uhttpd",
    "webs",
)

WEB_HANDLER_NAMES = {
    "cgi",
    "cgibin",
    "hnap",
    "soap",
    "tr069",
    "ubus",
    "web",
    "wps",
}

CONFIG_HANDLER_NAMES = {
    "apply",
    "cfg",
    "config",
    "firmware",
    "login",
    "network",
    "nvram",
    "ping",
    "reboot",
    "restore",
    "upload",
    "upgrade",
}

WEB_CONFIG_PARTS = {
    "boa",
    "cgi",
    "conf.d",
    "goahead",
    "lighttpd",
    "uhttpd",
    "web",
}

STARTUP_PARTS = {
    "init.d",
    "rc.d",
}

SENSITIVE_NAME_PATTERNS = (
    "passwd",
    "shadow",
    "private",
    "password",
    "credential",
    "secret",
    "key",
    "cert",
)

WEB_ENDPOINT_RE = re.compile(
    rb"(?P<endpoint>/[A-Za-z0-9_./%+-]*(?:cgi-bin/)?[A-Za-z0-9_.%+-]+(?:\.cgi|\.asp|\.php|\.xml|\.htm|\.html))"
)

EXEC_PATH_RE = re.compile(
    rb"(?P<path>/(?:usr/)?(?:s?bin|lib|www|web|htdocs|cgi-bin)/[A-Za-z0-9_./%+-]+)"
)

ROUTE_MARKERS = [
    b"/cgi-bin/",
    b"/goform/",
    b".cgi",
    b"Content-Type",
    b"HTTP/1.",
    b"REQUEST_METHOD",
    b"QUERY_STRING",
    b"REMOTE_ADDR",
    b"SCRIPT_NAME",
]

SOURCE_MARKERS = [
    b"getenv",
    b"recv",
    b"recvfrom",
    b"fgets",
    b"fread",
    b"scanf",
    b"websGetVar",
    b"cgiFormString",
    b"query",
    b"REQUEST_METHOD",
    b"QUERY_STRING",
]

SINK_MARKERS = [
    b"system",
    b"popen",
    b"execl",
    b"execv",
    b"sprintf",
    b"snprintf",
    b"strcpy",
    b"strcat",
    b"memcpy",
    b"strncpy",
]

ELF_TYPE_NAMES = {
    1: "relocatable",
    2: "executable",
    3: "shared",
    4: "core",
}

ELF_MACHINE_NAMES = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


@dataclass(frozen=True)
class ElfInfo:
    elf_class: str
    endian: str
    machine: str
    elf_type: str


@dataclass
class FirmwareBinaryCandidate:
    path: str
    relative_path: str
    size: int
    elf_class: str
    endian: str
    machine: str
    elf_type: str
    score: int = 0
    rank: int = 0
    reasons: list[str] = field(default_factory=list)
    route_markers: list[str] = field(default_factory=list)
    source_markers: list[str] = field(default_factory=list)
    sink_markers: list[str] = field(default_factory=list)
    referenced_by: list[str] = field(default_factory=list)
    web_references: list[str] = field(default_factory=list)
    startup_references: list[str] = field(default_factory=list)
    config_references: list[str] = field(default_factory=list)
    web_endpoints: list[str] = field(default_factory=list)
    ida_backend_command: str = ""


@dataclass
class FirmwareEndpoint:
    endpoint: str
    source_file: str
    candidate: str = ""


@dataclass
class FirmwareFilesystemScanReport:
    root: str
    total_files: int
    elf_files: int
    text_files_scanned: int
    web_endpoints: list[FirmwareEndpoint]
    sensitive_files: list[str]
    candidates: list[FirmwareBinaryCandidate]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class FirmwareFilesystemScanner:
    """Rank ELF binaries that are likely useful vulnerability-analysis entry points."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_string_bytes: int = DEFAULT_MAX_STRING_BYTES,
        max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES,
    ) -> None:
        self.root = Path(root).resolve()
        self.max_string_bytes = max_string_bytes
        self.max_text_bytes = max_text_bytes

    def scan(self, *, limit: int = 30) -> FirmwareFilesystemScanReport:
        if not self.root.exists():
            raise FileNotFoundError(f"firmware root does not exist: {self.root}")
        if not self.root.is_dir():
            raise NotADirectoryError(f"firmware root is not a directory: {self.root}")

        candidates: list[FirmwareBinaryCandidate] = []
        total_files = 0
        text_files: list[Path] = []
        sensitive_files: list[str] = []

        for path in self._iter_files():
            total_files += 1
            rel = _relative_posix(path, self.root)
            if _is_sensitive_file(rel):
                sensitive_files.append(rel)
            if self._is_small_text_candidate(path):
                text_files.append(path)
            elf_info = _read_elf_info(path)
            if elf_info is None:
                continue
            candidates.append(self._score_elf(path, elf_info))

        text_files_scanned, web_endpoints = self._add_reference_scores(candidates, text_files)
        candidates.sort(key=lambda item: (-item.score, item.relative_path.lower()))

        for index, candidate in enumerate(candidates, start=1):
            candidate.rank = index

        return FirmwareFilesystemScanReport(
            root=str(self.root),
            total_files=total_files,
            elf_files=len(candidates),
            text_files_scanned=text_files_scanned,
            web_endpoints=web_endpoints[:200],
            sensitive_files=sensitive_files[:200],
            candidates=candidates[:limit],
        )

    def _iter_files(self) -> Iterable[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                name for name in dirnames if name not in {".git", "__pycache__"}
            ]
            for filename in filenames:
                path = Path(dirpath) / filename
                if path.is_file():
                    yield path

    def _score_elf(self, path: Path, elf_info: ElfInfo) -> FirmwareBinaryCandidate:
        rel = _relative_posix(path, self.root)
        lower_rel = rel.lower()
        parent_parts = set(Path(lower_rel).parent.as_posix().split("/"))
        name = path.name.lower()
        stem = path.stem.lower()
        size = path.stat().st_size

        candidate = FirmwareBinaryCandidate(
            path=str(path),
            relative_path=rel,
            size=size,
            elf_class=elf_info.elf_class,
            endian=elf_info.endian,
            machine=elf_info.machine,
            elf_type=elf_info.elf_type,
        )

        if elf_info.elf_type == "executable":
            _add_score(candidate, 20, "ELF executable")
        elif elf_info.elf_type == "shared":
            _add_score(candidate, 8, "ELF shared object")

        if parent_parts & WEB_DIR_PARTS:
            _add_score(candidate, 35, "Web-facing path")
        if _path_ends_with_exec_dir(lower_rel):
            _add_score(candidate, 10, "System executable directory")

        if name.endswith(".cgi") or ".cgi" in name:
            _add_score(candidate, 35, "CGI-style filename")

        for keyword in WEB_SERVER_NAMES:
            if keyword in stem:
                _add_score(candidate, 45, f"Web server name: {keyword}")
                break

        for keyword in WEB_HANDLER_NAMES:
            if keyword in stem:
                _add_score(candidate, 20, f"Web handler keyword: {keyword}")
                break

        for keyword in CONFIG_HANDLER_NAMES:
            if keyword in stem:
                _add_score(candidate, 12, f"Admin/config keyword: {keyword}")
                break

        self._score_binary_strings(path, candidate)
        return candidate

    def _score_binary_strings(
        self,
        path: Path,
        candidate: FirmwareBinaryCandidate,
    ) -> None:
        data = _read_limited(path, self.max_string_bytes)
        route_markers = _find_markers(data, ROUTE_MARKERS)
        source_markers = _find_markers(data, SOURCE_MARKERS)
        sink_markers = _find_markers(data, SINK_MARKERS)

        candidate.route_markers = route_markers
        candidate.source_markers = source_markers
        candidate.sink_markers = sink_markers

        if route_markers:
            _add_score(candidate, min(30, 8 * len(route_markers)), "Contains Web/CGI route markers")
        if source_markers:
            _add_score(candidate, min(25, 5 * len(source_markers)), "Contains user-input/source markers")
        if sink_markers:
            _add_score(candidate, min(25, 4 * len(sink_markers)), "Contains dangerous sink markers")

    def _add_reference_scores(
        self,
        candidates: list[FirmwareBinaryCandidate],
        text_files: list[Path],
    ) -> tuple[int, list[FirmwareEndpoint]]:
        if not candidates:
            return 0, []

        by_name: dict[str, list[FirmwareBinaryCandidate]] = {}
        by_rel: dict[str, FirmwareBinaryCandidate] = {}
        for candidate in candidates:
            path = Path(candidate.relative_path)
            names = {path.name.lower(), path.stem.lower()}
            by_rel["/" + candidate.relative_path.lower()] = candidate
            by_rel[candidate.relative_path.lower()] = candidate
            for name in names:
                if len(name) >= 3:
                    by_name.setdefault(name, []).append(candidate)

        scanned = 0
        web_endpoints: list[FirmwareEndpoint] = []
        for text_file in text_files:
            data = _read_limited(text_file, self.max_text_bytes).lower()
            if not data:
                continue
            scanned += 1
            rel = _relative_posix(text_file, self.root)
            rel_parts = set(rel.lower().split("/"))
            reference_kind = _classify_reference_file(rel)
            endpoints = _extract_web_endpoints(data)
            for endpoint in endpoints:
                linked = _resolve_endpoint_candidate(endpoint, by_rel, by_name)
                web_endpoints.append(
                    FirmwareEndpoint(
                        endpoint=endpoint,
                        source_file=rel,
                        candidate=linked.relative_path if linked else "",
                    )
                )
                if linked is not None and endpoint not in linked.web_endpoints:
                    linked.web_endpoints.append(endpoint)
            for name, linked_candidates in by_name.items():
                if name.encode("utf-8", errors="ignore") not in data:
                    continue
                for candidate in linked_candidates:
                    if rel == candidate.relative_path:
                        continue
                    if rel not in candidate.referenced_by:
                        candidate.referenced_by.append(rel)
                    if reference_kind == "web" and rel not in candidate.web_references:
                        candidate.web_references.append(rel)
                    elif reference_kind == "startup" and rel not in candidate.startup_references:
                        candidate.startup_references.append(rel)
                    elif reference_kind == "config" and rel not in candidate.config_references:
                        candidate.config_references.append(rel)

            for exec_path in _extract_exec_paths(data):
                linked = by_rel.get(exec_path.lower().lstrip("/")) or by_rel.get(exec_path.lower())
                if linked is None or rel == linked.relative_path:
                    continue
                if rel not in linked.referenced_by:
                    linked.referenced_by.append(rel)
                if reference_kind == "web" and rel not in linked.web_references:
                    linked.web_references.append(rel)
                elif reference_kind == "startup" and rel not in linked.startup_references:
                    linked.startup_references.append(rel)
                elif reference_kind == "config" and rel not in linked.config_references:
                    linked.config_references.append(rel)

        for candidate in candidates:
            if candidate.referenced_by:
                candidate.referenced_by = candidate.referenced_by[:8]
                _add_score(
                    candidate,
                    min(30, 6 * len(candidate.referenced_by)),
                    "Referenced by scripts/config files",
                )
            if candidate.web_references:
                candidate.web_references = candidate.web_references[:8]
                _add_score(candidate, min(35, 10 * len(candidate.web_references)), "Referenced from Web assets/config")
            if candidate.startup_references:
                candidate.startup_references = candidate.startup_references[:8]
                _add_score(candidate, min(25, 8 * len(candidate.startup_references)), "Started or referenced by init scripts")
            if candidate.config_references:
                candidate.config_references = candidate.config_references[:8]
            if candidate.web_endpoints:
                candidate.web_endpoints = candidate.web_endpoints[:12]
                _add_score(candidate, min(30, 6 * len(candidate.web_endpoints)), "Mapped to Web endpoints")
        return scanned, _dedupe_endpoints(web_endpoints)

    def _is_small_text_candidate(self, path: Path) -> bool:
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size <= 0 or size > self.max_text_bytes:
            return False
        suffix = path.suffix.lower()
        if suffix in {
            ".conf",
            ".config",
            ".cgi",
            ".htm",
            ".html",
            ".ini",
            ".js",
            ".json",
            ".lua",
            ".php",
            ".sh",
            ".txt",
            ".xml",
        }:
            return True
        parts = set(_relative_posix(path, self.root).lower().split("/"))
        return bool(parts & {"etc", "init.d", "rc.d", "www", "htdocs", "web"})


def _read_elf_info(path: Path) -> ElfInfo | None:
    try:
        with path.open("rb") as fh:
            header = fh.read(20)
    except OSError:
        return None
    if len(header) < 20 or not header.startswith(b"\x7fELF"):
        return None

    elf_class = "32-bit" if header[4] == 1 else "64-bit" if header[4] == 2 else "unknown"
    endian = "little" if header[5] == 1 else "big" if header[5] == 2 else "unknown"
    fmt = "<HH" if endian == "little" else ">HH"
    try:
        elf_type_id, machine_id = struct.unpack(fmt, header[16:20])
    except struct.error:
        return None

    return ElfInfo(
        elf_class=elf_class,
        endian=endian,
        machine=ELF_MACHINE_NAMES.get(machine_id, f"machine-{machine_id}"),
        elf_type=ELF_TYPE_NAMES.get(elf_type_id, f"type-{elf_type_id}"),
    )


def _read_limited(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _find_markers(data: bytes, markers: list[bytes]) -> list[str]:
    lower = data.lower()
    found: list[str] = []
    for marker in markers:
        if marker.lower() in lower:
            found.append(marker.decode("ascii", errors="replace"))
    return found


def _extract_web_endpoints(data: bytes) -> list[str]:
    endpoints: list[str] = []
    for match in WEB_ENDPOINT_RE.finditer(data):
        value = match.group("endpoint").decode("utf-8", errors="ignore")
        if len(value) < 4 or value.startswith("//") or value in endpoints:
            continue
        endpoints.append(value)
        if len(endpoints) >= 200:
            break
    return endpoints


def _extract_exec_paths(data: bytes) -> list[str]:
    paths: list[str] = []
    for match in EXEC_PATH_RE.finditer(data):
        value = match.group("path").decode("utf-8", errors="ignore").rstrip(".,;:'\")")
        if len(value) < 4 or value in paths:
            continue
        paths.append(value)
        if len(paths) >= 200:
            break
    return paths


def _resolve_endpoint_candidate(
    endpoint: str,
    by_rel: dict[str, FirmwareBinaryCandidate],
    by_name: dict[str, list[FirmwareBinaryCandidate]],
) -> FirmwareBinaryCandidate | None:
    normalized = endpoint.lower().lstrip("/")
    direct = by_rel.get(normalized) or by_rel.get("/" + normalized)
    if direct is not None:
        return direct

    for relative_path, candidate in by_rel.items():
        if relative_path.endswith("/" + normalized):
            return candidate

    endpoint_name = Path(normalized).name
    candidates = by_name.get(endpoint_name) or by_name.get(Path(endpoint_name).stem)
    if candidates:
        return candidates[0]
    return None


def _dedupe_endpoints(endpoints: list[FirmwareEndpoint]) -> list[FirmwareEndpoint]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[FirmwareEndpoint] = []
    for endpoint in endpoints:
        key = (endpoint.endpoint, endpoint.source_file, endpoint.candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(endpoint)
    return unique


def _classify_reference_file(relative_path: str) -> str:
    lower = relative_path.lower()
    parts = set(lower.split("/"))
    if parts & STARTUP_PARTS or lower.endswith("/rcs") or lower.endswith("/inittab"):
        return "startup"
    if parts & WEB_DIR_PARTS or parts & WEB_CONFIG_PARTS:
        return "web"
    if "etc/" in lower or lower.startswith("etc/") or lower.endswith(".conf"):
        return "config"
    return "other"


def _is_sensitive_file(relative_path: str) -> bool:
    name = Path(relative_path.lower()).name
    if name in {"passwd", "shadow", "group"}:
        return True
    return any(pattern in name for pattern in SENSITIVE_NAME_PATTERNS)


def _relative_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _path_ends_with_exec_dir(relative_path: str) -> bool:
    parent = str(Path(relative_path).parent).replace("\\", "/").strip("/")
    return parent in EXEC_DIR_SUFFIXES or any(parent.endswith(f"/{part}") for part in EXEC_DIR_SUFFIXES)


def _add_score(candidate: FirmwareBinaryCandidate, points: int, reason: str) -> None:
    candidate.score += points
    if reason not in candidate.reasons:
        candidate.reasons.append(reason)


def build_ida_backend_command(
    binary_path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    read_only: bool = True,
) -> str:
    command = f'python -m vulnagent --idb "{binary_path}" --host {host} --port {port}'
    if read_only:
        command += " --read-only"
    return command


def attach_ida_backend_commands(
    report: FirmwareFilesystemScanReport,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    read_only: bool = True,
) -> FirmwareFilesystemScanReport:
    for candidate in report.candidates:
        candidate.ida_backend_command = build_ida_backend_command(
            candidate.path,
            host=host,
            port=port,
            read_only=read_only,
        )
    return report


def _format_table(
    report: FirmwareFilesystemScanReport,
    *,
    show_ida_commands: bool = False,
) -> str:
    lines = [
        f"Firmware root: {report.root}",
        (
            f"Files: {report.total_files}  ELF: {report.elf_files}  "
            f"Text refs scanned: {report.text_files_scanned}  "
            f"Web endpoints: {len(report.web_endpoints)}  "
            f"Sensitive files: {len(report.sensitive_files)}"
        ),
        "",
        "Rank  Score  Arch              Type        Path",
        "----  -----  ----------------  ----------  ----",
    ]
    for candidate in report.candidates:
        arch = f"{candidate.machine}/{candidate.elf_class}/{candidate.endian}"
        lines.append(
            f"{candidate.rank:>4}  {candidate.score:>5}  {arch:<16}  "
            f"{candidate.elf_type:<10}  {candidate.relative_path}"
        )
        if candidate.reasons:
            lines.append(f"      reasons: {', '.join(candidate.reasons[:5])}")
        markers = candidate.route_markers + candidate.source_markers + candidate.sink_markers
        if markers:
            lines.append(f"      markers: {', '.join(markers[:10])}")
        if candidate.referenced_by:
            lines.append(f"      refs: {', '.join(candidate.referenced_by[:4])}")
        if candidate.web_endpoints:
            lines.append(f"      endpoints: {', '.join(candidate.web_endpoints[:6])}")
        if candidate.startup_references:
            lines.append(f"      startup: {', '.join(candidate.startup_references[:3])}")
        if show_ida_commands and candidate.ida_backend_command:
            lines.append(f"      start IDA backend: {candidate.ida_backend_command}")
    if report.web_endpoints:
        lines.extend(["", "Web endpoint samples:"])
        for endpoint in report.web_endpoints[:10]:
            target = f" -> {endpoint.candidate}" if endpoint.candidate else ""
            lines.append(f"  {endpoint.endpoint} ({endpoint.source_file}){target}")
    if report.sensitive_files:
        lines.extend(["", "Sensitive file samples:"])
        for path in report.sensitive_files[:10]:
            lines.append(f"  {path}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scan an extracted firmware filesystem and rank binaries for vulnerability analysis.",
    )
    parser.add_argument("root", help="Extracted firmware filesystem directory, e.g. squashfs-root")
    parser.add_argument("--limit", type=int, default=30, help="Maximum candidates to print")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--show-ida-commands",
        action="store_true",
        help="Include suggested IDA backend startup commands for ranked candidates",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host for suggested IDA backend commands")
    parser.add_argument("--port", type=int, default=8765, help="Port for suggested IDA backend commands")
    parser.add_argument(
        "--writable",
        action="store_true",
        help="Generate writable IDA backend commands instead of read-only commands",
    )
    parser.add_argument(
        "--max-string-bytes",
        type=int,
        default=DEFAULT_MAX_STRING_BYTES,
        help="Maximum bytes read from each ELF for marker scoring",
    )
    args = parser.parse_args(argv)

    report = FirmwareFilesystemScanner(
        args.root,
        max_string_bytes=args.max_string_bytes,
    ).scan(limit=args.limit)
    attach_ida_backend_commands(
        report,
        host=args.host,
        port=args.port,
        read_only=not args.writable,
    )

    if args.json:
        print(report.to_json())
    else:
        print(_format_table(report, show_ida_commands=args.show_ida_commands))


if __name__ == "__main__":
    main()
