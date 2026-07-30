"""FastAPI router exposing saved vulnerability reports."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from vulnagent.reports.store import FileReportStore


def build_report_router(store: FileReportStore) -> APIRouter:
    """Return a router serving report JSON files from ``store.report_dir``."""
    router = APIRouter()

    @router.get("/reports")
    def list_reports() -> list[dict]:
        reports = []
        for path in store.list_reports():
            report_id = path.stem
            try:
                report = store.load(report_id)
            except Exception:
                continue
            reports.append(
                {
                    "report_id": report.report_id,
                    "created_at": report.created_at.isoformat(),
                    "scope": report.scope,
                    "summary": report.summary,
                }
            )
        return reports

    @router.get("/reports/{report_id}")
    def get_report(report_id: str) -> FileResponse:
        try:
            path = store._path_for(report_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not path.is_file():
            raise HTTPException(status_code=404, detail="unknown report")
        return FileResponse(path, media_type="application/json", filename=path.name)

    return router
