"""
ETHIO-AI Defender - FastAPI Main Application Entry Point.
"""

from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings, BASE_DIR
from app.core.logger import logger
from app.api.files import router as files_router
from app.api.dashboard import router as dashboard_router
from app.api.auth import router as auth_router
from app.api.audit import router as audit_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_FULL_NAME,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for web dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Applies standard defensive HTTP security headers to all responses.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Include API Routers
app.include_router(files_router)
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(audit_router)

# Mount Static Files (CSS, JS)
static_dir = BASE_DIR / "frontend" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

frontend_index = BASE_DIR / "frontend" / "index.html"


@app.get("/", tags=["Dashboard & Health"])
async def root(request: Request):
    """
    Serves the modern SOC Dashboard for browser clients,
    or returns system status JSON for programmatic health checks.
    """
    accept_header = request.headers.get("accept", "").lower()
    
    # If requested by a web browser, serve the Module 02 Dashboard UI
    if "text/html" in accept_header and frontend_index.exists():
        return FileResponse(frontend_index)

    # Otherwise, return the standard system health JSON
    return {
        "platform": settings.PROJECT_NAME,
        "full_name": settings.PROJECT_FULL_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "description": "Defensive static malware analysis & reverse-engineering platform",
        "supported_formats": list(settings.ALLOWED_EXTENSIONS),
    }


@app.get("/dashboard", tags=["Dashboard"])
async def dashboard():
    """Direct route to the Module 02 File Hash Analysis Dashboard."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting ETHIO-AI Defender development server...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
