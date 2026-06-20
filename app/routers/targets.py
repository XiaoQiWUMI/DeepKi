# (●°u°●)​ 」 Target Management Router

from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.database import Target, Scan, get_db

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/", response_class=HTMLResponse)
async def targets_page(request: Request):
    """Target management page"""
    return request.app.state.templates.TemplateResponse(request, "targets.html")


@router.get("/list")
async def list_targets(request: Request, db: AsyncSession = Depends(get_db)):
    """HTMX partial: list all targets"""
    result = await db.execute(select(Target).order_by(Target.added_at.desc()))
    targets = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        request, "components/target_list.html", {"targets": targets}
    )


@router.post("/add")
async def add_target(
    request: Request,
    url: str = Form(...),
    label: str = Form(""),
    description: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    """Add a new scan target"""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Check duplicate
    existing = await db.execute(select(Target).where(Target.url == url))
    if existing.scalar_one_or_none():
        return request.app.state.templates.TemplateResponse(
            request, "components/toast.html",
            {"type": "warning", "message": f"T^T Target already exists: {url}"}
        )

    target = Target(url=url, label=label, description=description)
    db.add(target)
    await db.commit()

    # Return updated list
    await db.refresh(target)
    result = await db.execute(select(Target).order_by(Target.added_at.desc()))
    targets = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        request, "components/target_list.html", {"targets": targets}
    )


@router.get("/options")
async def target_options(request: Request, db: AsyncSession = Depends(get_db)):
    """HTMX partial: return <option> tags for select"""
    result = await db.execute(select(Target).order_by(Target.added_at.desc()))
    targets = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        request, "components/target_options.html", {"targets": targets}
    )


@router.delete("/{target_id}")
async def delete_target(
    request: Request,
    target_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete a target and all its scans"""
    target = await db.get(Target, target_id)
    if target:
        await db.delete(target)
        await db.commit()

    result = await db.execute(select(Target).order_by(Target.added_at.desc()))
    targets = result.scalars().all()
    return request.app.state.templates.TemplateResponse(
        request, "components/target_list.html", {"targets": targets}
    )
