"""Filesystem-backed JSON report storage."""

from __future__ import annotations

import json
import re
from pathlib import Path

from vulnagent.reports.models import BinaryVulnerabilityReport

_REPORT_ID_RE = re.compile(r"^[0-9a-fA-F]{8,128}$")


def _is_valid_report_id(report_id: str) -> bool:
    return bool(_REPORT_ID_RE.match(report_id))


class FileReportStore:
    """Persist :class:`BinaryVulnerabilityReport` objects as JSON files."""

    def __init__(self, report_dir: str | Path) -> None:
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, report_id: str) -> Path:
        if not _is_valid_report_id(report_id):
            raise ValueError(f"invalid report_id: {report_id!r}")
        return self.report_dir / f"{report_id}.json"

    def save(self, report: BinaryVulnerabilityReport) -> Path:
        path = self._path_for(report.report_id)
        path.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return path

    def load(self, report_id: str) -> BinaryVulnerabilityReport:
        path = self._path_for(report_id)
        if not path.is_file():
            raise FileNotFoundError(f"Unknown report: {report_id}")
        return BinaryVulnerabilityReport.model_validate_json(path.read_text(encoding="utf-8"))

    def exists(self, report_id: str) -> bool:
        try:
            return self._path_for(report_id).is_file()
        except ValueError:
            return False

    def list_reports(self) -> list[Path]:
        return sorted(self.report_dir.glob("*.json"))
