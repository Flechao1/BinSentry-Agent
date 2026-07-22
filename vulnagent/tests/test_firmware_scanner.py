from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vulnagent.firmware.scanner import FirmwareFilesystemScanner
from vulnagent.tools.firmware_tools import FirmwareFilesystemTools, parse_tool_json


def _write_mips_elf(path: Path, payload: bytes = b"") -> None:
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1  # 32-bit
    header[5] = 2  # big endian
    struct.pack_into(">HH", header, 16, 2, 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header) + payload)


class FirmwareFilesystemScannerTests(unittest.TestCase):
    def test_ranks_web_facing_binary_above_generic_binary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            web = root / "www" / "cgi-bin" / "apply.cgi"
            generic = root / "bin" / "busybox"
            _write_mips_elf(
                web,
                b"REQUEST_METHOD\x00QUERY_STRING\x00system\x00strcpy\x00",
            )
            _write_mips_elf(generic, b"")
            (root / "etc" / "rc.d").mkdir(parents=True)
            (root / "etc" / "rc.d" / "rcS").write_text(
                "/www/cgi-bin/apply.cgi\n",
                encoding="utf-8",
            )

            report = FirmwareFilesystemScanner(root).scan(limit=10)

        self.assertEqual(report.elf_files, 2)
        self.assertEqual(report.candidates[0].relative_path, "www/cgi-bin/apply.cgi")
        self.assertGreater(report.candidates[0].score, report.candidates[1].score)
        self.assertIn("Web-facing path", report.candidates[0].reasons)
        self.assertIn("Referenced by scripts/config files", report.candidates[0].reasons)
        self.assertIn("REQUEST_METHOD", report.candidates[0].route_markers)
        self.assertIn("system", report.candidates[0].sink_markers)

    def test_extracts_web_endpoints_and_startup_references(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            httpd = root / "sbin" / "httpd"
            handler = root / "www" / "apply.cgi"
            _write_mips_elf(httpd, b"HTTP/1.1\x00Content-Type\x00")
            _write_mips_elf(handler, b"REQUEST_METHOD\x00QUERY_STRING\x00system\x00")
            (root / "www").mkdir(parents=True, exist_ok=True)
            (root / "www" / "index.htm").write_text(
                '<form action="/apply.cgi"></form>',
                encoding="utf-8",
            )
            (root / "etc" / "rc.d").mkdir(parents=True, exist_ok=True)
            (root / "etc" / "rc.d" / "rcS").write_text(
                "/sbin/httpd -f /etc/lighttpd.conf\n",
                encoding="utf-8",
            )

            report = FirmwareFilesystemScanner(root).scan(limit=10)

        by_path = {candidate.relative_path: candidate for candidate in report.candidates}
        self.assertTrue(any(endpoint.endpoint == "/apply.cgi" for endpoint in report.web_endpoints))
        self.assertIn("/apply.cgi", by_path["www/apply.cgi"].web_endpoints)
        self.assertIn("Mapped to Web endpoints", by_path["www/apply.cgi"].reasons)
        self.assertIn("etc/rc.d/rcS", by_path["sbin/httpd"].startup_references)
        self.assertIn("Started or referenced by init scripts", by_path["sbin/httpd"].reasons)

    def test_agent_tool_returns_structured_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_mips_elf(
                root / "www" / "apply.cgi",
                b"REQUEST_METHOD\x00QUERY_STRING\x00system\x00",
            )

            payload = parse_tool_json(
                FirmwareFilesystemTools().scan_firmware_filesystem(str(root), limit=5)
            )

        self.assertEqual(payload["format"], "vulnagent.tool_result.v1")
        self.assertIn("binary_candidates", payload)
        self.assertEqual(payload["binary_candidates"][0]["relative_path"], "www/apply.cgi")
        self.assertIn("python -m vulnagent --idb", payload["binary_candidates"][0]["ida_backend_command"])
        self.assertIn("firmware_filesystem", payload)


if __name__ == "__main__":
    unittest.main()
