# (●°u°●)​ 」 DeepKi — Xiao Qi's Blackbox Security Scanner
# The cutest web security testing platform~ ♪───Ｏ（≧∇≦）Ｏ────♪

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import HOST, PORT, DEBUG, TEMPLATE_DIR, STATIC_DIR, RESULT_DIR
from .models.database import init_db
from .routers import targets_router, scans_router, results_router, api_router, ws_router
from .routers.ws import WebSocketManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Xiao Qi wakes up~ (●°u°●)​ 」"""
    # Startup
    await init_db()
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    app.state.active_scans = {}
    app.state.ws_manager = WebSocketManager()
    app.state.templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    app.state.templates.env.globals["app_name"] = "DeepKi"
    app.state.templates.env.globals["app_version"] = "v1.0"
    print("♪───Ｏ（≧∇≦）Ｏ────♪")
    print("  DeepKi is ready! Xiao Qi awaits~")
    print(f"  http://{HOST}:{PORT}")
    print("(●°u°●)​ 」")
    yield
    # Shutdown
    print("^ - ^ Xiao Qi is going to sleep... zzz")


app = FastAPI(
    title="DeepKi",
    description="(●°u°●)​ 」 The cutest black-box security scanner — powered by Xiao Qi",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if DEBUG else None,
    redoc_url="/api/redoc" if DEBUG else None,
)

# Static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Routers
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(results_router)
app.include_router(api_router)
app.include_router(ws_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard — Xiao Qi's home~ ^ - ^"""
    return request.app.state.templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "^ - ^", "mascot": "Xiao Qi", "version": "1.0.0"}


# ── Run ──
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        log_level="info",
    )
