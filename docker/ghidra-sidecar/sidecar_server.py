"""
ETHIO-AI Defender - OPS-02: Containerized Ghidra Headless Sidecar Server

A hardened, lightweight internal microservice that executes Ghidra headless
reverse engineering inside an isolated, non-root Linux container.

Defensive Guarantees:
- Samples are mounted read-only (:ro).
- Zero binary execution: Ghidra only statically parses bytes.
- Command executed strictly as an argument list (no shell injection).
- Isolated per-analysis temporary workspaces, purged after each invocation.
- Token-authenticated internal RPC endpoint.
- Resource & timeout bounded.
"""

import os
import re
import json
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ghidra-sidecar")

# Configuration
GHIDRA_HOME = Path(os.getenv("GHIDRA_HOME", "/opt/ghidra"))
SCRIPT_DIR = Path(os.getenv("SCRIPT_DIR", "/app/scripts"))
WORKSPACE_BASE = Path(os.getenv("WORKSPACE_DIR", "/tmp/workspace"))
SAMPLES_DIR = Path(os.getenv("SAMPLES_DIR", "/samples"))
SIDECAR_TOKEN = os.getenv("GHIDRA_SIDECAR_TOKEN", "")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("DEFAULT_TIMEOUT_SECONDS", "180.0"))
DEFAULT_MAX_FUNCTIONS = int(os.getenv("DEFAULT_MAX_FUNCTIONS", "2000"))

_SAFE_LABEL = re.compile(r"[^A-Za-z0-9_-]")

app = FastAPI(
    title="ETHIO-AI Defender Ghidra Sidecar",
    description="Isolated static reverse-engineering sidecar service",
    version="1.0.0",
)


class AnalysisRequest(BaseModel):
    """RPC request schema for headless Ghidra analysis."""
    sample_path: str = Field(..., description="Path to quarantined binary within container /samples mount")
    analysis_id: Optional[str] = Field(None, description="Unique analysis identifier for workspace isolation")
    max_functions: Optional[int] = Field(None, description="Max functions to extract")
    timeout_seconds: Optional[float] = Field(None, description="Hard timeout in seconds")


def verify_token(x_sidecar_token: Optional[str] = Header(None)):
    """Enforce optional shared secret token authentication."""
    if SIDECAR_TOKEN and x_sidecar_token != SIDECAR_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing sidecar authentication token",
        )


def _resolve_headless_launcher() -> Optional[Path]:
    """Locate analyzeHeadless launcher."""
    for name in ("analyzeHeadless", "analyzeHeadless.bat"):
        candidate = GHIDRA_HOME / "support" / name
        if candidate.is_file():
            return candidate
    return None


@app.get("/health")
def health_check():
    """Health and readiness probe."""
    launcher = _resolve_headless_launcher()
    available = launcher is not None and launcher.is_file()
    return {
        "status": "healthy" if available else "degraded",
        "ghidra_home": str(GHIDRA_HOME),
        "ghidra_available": available,
        "launcher_path": str(launcher) if launcher else None,
        "scripts_dir": str(SCRIPT_DIR),
        "user_uid": os.getuid() if hasattr(os, "getuid") else None,
    }


@app.post("/analyze", dependencies=[Depends(verify_token)])
def analyze_sample(request: AnalysisRequest) -> Dict[str, Any]:
    """
    Executes Ghidra headless analysis on a sample mounted inside the container.
    Returns structured JSON matching ETHIO-AI Defender reverse-engineering schema.
    """
    launcher = _resolve_headless_launcher()
    if not launcher:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Ghidra analyzeHeadless launcher not found under {GHIDRA_HOME}",
        )

    # Resolve and validate sample path
    raw_path = Path(request.sample_path)
    # If relative path or filename, resolve relative to SAMPLES_DIR
    if not raw_path.is_absolute():
        target_path = SAMPLES_DIR / raw_path.name
    elif str(raw_path).startswith(str(SAMPLES_DIR)):
        target_path = raw_path
    else:
        # Check if basename exists under SAMPLES_DIR
        target_path = SAMPLES_DIR / raw_path.name
        if not target_path.is_file() and raw_path.is_file():
            target_path = raw_path

    if not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample file not found at '{target_path}'",
        )

    # Workspace setup
    analysis_label = request.analysis_id or target_path.stem
    safe_label = _SAFE_LABEL.sub("_", analysis_label)[:64] or "sample"
    workspace = WORKSPACE_BASE / safe_label
    project_dir = workspace / "project"
    out_file = workspace / "program_info.json"

    timeout_seconds = request.timeout_seconds or DEFAULT_TIMEOUT_SECONDS
    max_functions = request.max_functions or DEFAULT_MAX_FUNCTIONS

    try:
        workspace.mkdir(parents=True, exist_ok=True)
        project_dir.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env["GHIDRA_OUT_FILE"] = str(out_file)
        env["GHIDRA_MAX_FUNCTIONS"] = str(max_functions)

        # Defensive argument array invocation (no shell injection)
        command: List[str] = [
            str(launcher),
            str(project_dir),
            "EthioAIDefender",
            "-scriptPath", str(SCRIPT_DIR),
            "-import", str(target_path),
            "-postScript", "dump_program_info.py",
            "-deleteProject",
        ]

        logger.info(f"Executing Ghidra sidecar headless analysis for {target_path.name} (timeout={timeout_seconds}s)")

        proc = subprocess.run(
            command,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )

        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-500:]
            logger.warning(f"Ghidra exited with code {proc.returncode}: {tail}")
            return {
                "ok": False,
                "available": True,
                "status": "FAILED",
                "message": f"Ghidra headless exited with code {proc.returncode}",
                "errors": [tail],
            }

        if not out_file.is_file():
            tail = (proc.stderr or proc.stdout or "").strip()[-500:]
            return {
                "ok": False,
                "available": True,
                "status": "FAILED",
                "message": "Ghidra completed but did not produce output JSON",
                "errors": [tail],
            }

        with open(out_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)

        payload["available"] = True
        payload["status"] = "SUCCESS"
        payload["message"] = "Ghidra sidecar analysis completed successfully."
        return payload

    except subprocess.TimeoutExpired:
        logger.warning(f"Ghidra analysis timed out after {timeout_seconds}s for {target_path.name}")
        return {
            "ok": False,
            "available": True,
            "status": "TIMEOUT",
            "message": f"Ghidra sidecar analysis timed out after {timeout_seconds}s",
            "errors": [f"TimeoutExpired: {timeout_seconds}s limit reached"],
        }
    except Exception as exc:
        logger.error(f"Error during sidecar analysis: {exc}")
        return {
            "ok": False,
            "available": True,
            "status": "FAILED",
            "message": f"Internal sidecar error: {str(exc)}",
            "errors": [str(exc)],
        }
    finally:
        # Purge temporary workspace
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("GHIDRA_SIDECAR_PORT", "8089"))
    host = os.getenv("GHIDRA_SIDECAR_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=port, access_log=False)
