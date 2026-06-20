# (●°u°●)​ 」 Results & Reports Router

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from ..models.database import Target, Scan, Finding, get_db

router = APIRouter(prefix="/results", tags=["results"])


@router.get("/", response_class=HTMLResponse)
async def results_page(request: Request):
    """Results dashboard"""
    return request.app.state.templates.TemplateResponse(request, "results.html")


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_results(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """View results for a specific scan"""
    scan = await db.get(Scan, scan_id, options=[joinedload(Scan.target)])
    if not scan:
        return HTMLResponse("<div class='p-4'>T^T Scan not found...</div>")

    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(
            Finding.severity.desc(), Finding.found_at.desc()
        )
    )
    findings = result.scalars().all()

    return request.app.state.templates.TemplateResponse(
        request, "components/scan_results.html",
        {"scan": scan, "target": scan.target, "findings": findings,
         "severity_counts": _count_severities(findings)}
    )


@router.get("/report/{scan_id}", response_class=HTMLResponse)
async def scan_report(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Generate HTML report for a scan"""
    scan = await db.get(Scan, scan_id, options=[joinedload(Scan.target)])
    if not scan:
        return HTMLResponse("<h2>T^T Scan not found</h2>")

    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity.desc())
    )
    findings = result.scalars().all()

    return request.app.state.templates.TemplateResponse(
        request, "report.html",
        {"scan": scan, "target": scan.target, "findings": findings,
         "severity_counts": _count_severities(findings),
         "verified_count": sum(1 for f in findings if f.verified)}
    )


def _count_severities(findings: list[Finding]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
