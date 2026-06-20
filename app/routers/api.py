# (●°u°●)​ 」 REST API Router
# For external integrations & programmatic access

from fastapi import APIRouter, Request, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ..models.database import Target, Scan, Finding, get_db

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/stats")
async def api_stats(request: Request, db: AsyncSession = Depends(get_db)):
    """Get overall stats ~_^"""
    # Count targets
    target_count = await db.scalar(select(func.count(Target.id)))
    # Count scans
    scan_count = await db.scalar(select(func.count(Scan.id)))
    # Count findings by severity
    total_findings = await db.scalar(select(func.count(Finding.id)))
    high_count = await db.scalar(
        select(func.count(Finding.id)).where(Finding.severity.in_(("critical", "high")))
    )
    # Recent scans
    recent = await db.execute(
        select(Scan).order_by(Scan.started_at.desc()).limit(5)
    )
    recent_scans = recent.scalars().all()

    return {
        "targets": target_count,
        "scans": scan_count,
        "findings": total_findings,
        "high_severity": high_count,
        "recent_scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in recent_scans
        ],
        "mascot": "Xiao Qi (●°u°●)​ 」",
    }


@router.get("/targets")
async def api_targets(request: Request, db: AsyncSession = Depends(get_db)):
    """List all targets"""
    result = await db.execute(select(Target).order_by(Target.added_at.desc()))
    targets = result.scalars().all()
    return [
        {
            "id": t.id, "url": t.url, "label": t.label,
            "scan_count": t.scan_count,
            "last_scan_at": t.last_scan_at.isoformat() if t.last_scan_at else None,
        }
        for t in targets
    ]


@router.get("/findings/{scan_id}")
async def api_findings(
    request: Request,
    scan_id: int,
    severity: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a scan, optionally filtered by severity"""
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    query = query.order_by(Finding.severity.desc())

    result = await db.execute(query)
    findings = result.scalars().all()
    return [
        {
            "id": f.id, "module": f.module, "severity": f.severity,
            "title": f.title, "url": f.url, "description": f.description,
            "evidence": f.evidence, "verified": f.verified,
            "cve_id": f.cve_id, "found_at": f.found_at.isoformat() if f.found_at else None,
        }
        for f in findings
    ]
