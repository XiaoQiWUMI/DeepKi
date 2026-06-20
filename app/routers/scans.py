# (●°u°●)​ 」 Scan Management Router

import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, Form, WebSocket
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.database import Target, Scan, Finding, ScanModule, ScanStatus, get_db
from ..scanners.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """Scan configuration page"""
    return request.app.state.templates.TemplateResponse(request, "scan.html")


@router.post("/start")
async def start_scan(
    request: Request,
    target_id: int = Form(...),
    mode: str = Form("full"),
    modules: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    """Start a new scan"""
    target = await db.get(Target, target_id)
    if not target:
        return request.app.state.templates.TemplateResponse(
            request, "components/toast.html",
            {"type": "error", "message": "T^T Target not found!"}
        )

    # Parse enabled modules
    enabled = [m.strip() for m in modules.split(",") if m.strip()] if modules else None

    # Create scan record
    scan = Scan(
        target_id=target.id,
        mode=mode,
        status=ScanStatus.RUNNING.value,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Update target stats
    target.last_scan_at = datetime.now(timezone.utc)
    target.scan_count = (target.scan_count or 0) + 1
    await db.commit()

    # Store progress in app state for WebSocket
    request.app.state.active_scans[scan.id] = {
        "target_url": target.url,
        "mode": mode,
        "progress": None,
        "findings": [],
        "status": "running",
    }

    # Launch scan in background
    asyncio.create_task(_run_scan(request, scan.id, target.url, mode, enabled, db))

    return request.app.state.templates.TemplateResponse(
        request, "components/scan_started.html",
        {"scan_id": scan.id, "target_url": target.url}
    )


@router.get("/{scan_id}/progress")
async def scan_progress(
    request: Request,
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """HTMX partial: scan progress bar"""
    state = request.app.state.active_scans.get(scan_id, {})
    progress = state.get("progress")
    findings = state.get("findings", [])
    status = state.get("status", "running")

    return request.app.state.templates.TemplateResponse(
        request, "components/progress.html",
        {"scan_id": scan_id, "progress": progress, "findings": findings, "status": status}
    )


@router.get("/list")
async def list_scans(request: Request, db: AsyncSession = Depends(get_db)):
    """HTMX partial: list recent scans"""
    result = await db.execute(
        select(Scan).order_by(Scan.started_at.desc()).limit(20)
    )
    scans = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        request, "components/scan_list.html", {"scans": scans}
    )


async def _run_scan(
    request: Request, scan_id: int, target_url: str,
    mode: str, modules: list[str], db_session,
):
    """Background scan execution"""
    from ..models.database import async_session

    # Progress callback
    async def on_progress(progress):
        state = request.app.state.active_scans.get(scan_id, {})
        state["progress"] = progress
        state["findings"] = progress.findings
        state["status"] = progress.status
        # Emit terminal output
        terminal = ScanOrchestrator.format_terminal(progress)
        if hasattr(request.app.state, 'ws_manager'):
            await request.app.state.ws_manager.send(scan_id, {
                "type": "progress",
                "terminal": terminal,
                "percent": progress.overall_percent,
                "phase": progress.phase,
                "findings": [
                    {"title": f.title, "severity": f.severity, "url": f.url, "verified": f.verified}
                    for f in progress.findings[-10:]
                ],
                "counts": progress.severity_counts,
            })

    # Finding callback
    async def on_finding(finding):
        if hasattr(request.app.state, 'ws_manager'):
            await request.app.state.ws_manager.send(scan_id, {
                "type": "finding",
                "title": finding.title,
                "severity": finding.severity,
                "module": finding.module,
                "url": finding.url,
                "evidence": finding.evidence[:200],
            })

    try:
        orchestrator = ScanOrchestrator(
            target_url=target_url,
            mode=mode,
            modules=modules,
            progress_callback=on_progress,
            finding_callback=on_finding,
        )
        result = await orchestrator.run()

        # Save to database
        async with async_session() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED.value
                scan.finished_at = datetime.now(timezone.utc)
                scan.total_requests = sum(
                    mp.extra.get("reqs", 0) for mp in result.modules.values()
                )
                for f in result.findings:
                    finding = Finding(
                        scan_id=scan_id,
                        module=f.module,
                        severity=f.severity,
                        title=f.title,
                        url=f.url,
                        description=f.description,
                        evidence=f.evidence,
                        remediation=f.remediation,
                        cve_id=f.cve_id,
                        verified=f.verified,
                    )
                    db.add(finding)
                await db.commit()

        # Notify completion
        if hasattr(request.app.state, 'ws_manager'):
            await request.app.state.ws_manager.send(scan_id, {
                "type": "complete",
                "findings_count": len(result.findings),
                "counts": result.severity_counts,
                "terminal": ScanOrchestrator.format_terminal(result),
            })

        del request.app.state.active_scans[scan_id]

    except Exception as e:
        async with async_session() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED.value
                await db.commit()

        if hasattr(request.app.state, 'ws_manager'):
            await request.app.state.ws_manager.send(scan_id, {
                "type": "error",
                "message": f"T^T Scan failed: {str(e)}",
            })
