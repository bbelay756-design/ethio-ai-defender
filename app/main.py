"""
ETHIO-AI Defender - FastAPI Main Application Entry Point.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings, BASE_DIR
from app.core.logger import logger
from app.api.files import router as files_router
from app.api.dashboard import router as dashboard_router
from app.api.analyses import router as analyses_router
from app.api.auth import router as auth_router
from app.api.audit import router as audit_router
from app.api.learning import router as learning_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup/shutdown hooks.

    SEC-02: refuse to start if the token-signing secret is missing or weak
    (fail closed). The error message never contains the secret value.
    """
    settings.validate_security()
    logger.info("Security configuration validated: signing secret present and strong.")
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_FULL_NAME,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
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
app.include_router(analyses_router)
app.include_router(files_router)
app.include_router(dashboard_router)
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(learning_router)

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


@app.get("/login", tags=["Public Routes"])
@app.get("/about", tags=["Public Routes"])
async def public_pages():
    """Public portal landing routes."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


@app.get("/dashboard", tags=["Dashboard"])
@app.get("/history", tags=["Protected Analysis Routes"])
@app.get("/analysis", tags=["Protected Analysis Routes"])
@app.get("/pe-analysis", tags=["Protected Analysis Routes"])
@app.get("/imports", tags=["Protected Analysis Routes"])
@app.get("/strings", tags=["Protected Analysis Routes"])
@app.get("/indicators", tags=["Protected Analysis Routes"])
@app.get("/ai-analysis", tags=["Protected Analysis Routes"])
@app.get("/reports", tags=["Protected Analysis Routes"])
@app.get("/settings", tags=["Protected Analysis Routes"])
async def protected_analysis_routes():
    """Protected static malware analysis and SOC reporting routes."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


@app.get("/admin/dashboard", tags=["Role Dashboards"])
@app.get("/admin/users", tags=["Role Dashboards"])
@app.get("/admin/audit", tags=["Role Dashboards"])
async def admin_dashboard_routes():
    """Dedicated Administrator Control Center Dashboard routes."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


@app.get("/analyst/dashboard", tags=["Role Dashboards"])
@app.get("/analyst/new-analysis", tags=["Role Dashboards"])
@app.get("/analyst/history", tags=["Role Dashboards"])
async def analyst_dashboard_routes():
    """Dedicated SOC / Malware Analyst Triage Dashboard routes."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


@app.get("/student/dashboard", tags=["Role Dashboards"])
@app.get("/student/learning", tags=["Role Dashboards"])
@app.get("/student/safe-samples", tags=["Role Dashboards"])
async def student_dashboard_routes():
    """Dedicated Cybersecurity Student Learning Lab Dashboard routes."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=404, content={"detail": "Frontend index.html not found."})


@app.get("/unauthorized", tags=["Dashboard"])
async def unauthorized_page():
    """Safe unauthorized access / 403 route."""
    if frontend_index.exists():
        return FileResponse(frontend_index)
    return JSONResponse(status_code=403, content={"detail": "Access forbidden: Unauthorized role or missing credentials."})


if __name__ == "__main__":
    import uvicorn
    settings.validate_security()
    logger.info("Starting ETHIO-AI Defender development server...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
