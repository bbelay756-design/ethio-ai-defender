"""
Module 20: Ghidra Headless Static Reverse-Engineering Analyzer

Responsibility:
Runs Ghidra's supported headless workflow against a quarantined sample and
extracts structured reverse-engineering artifacts (program identity,
architecture, entry point, functions, call-graph relationships, imports,
exports, strings).

Defensive guarantees:
- The sample is NEVER executed, spawned, or emulated. Ghidra only parses bytes.
- Ghidra is invoked through its official analyzeHeadless launcher using a
  subprocess ARGUMENT ARRAY (no shell string concatenation).
- The command list contains no user-controlled values; the only inputs are the
  quarantined file path and an isolated per-analysis workspace.
- A hard timeout is applied to every external process.
- Structured results are stored independently from raw Ghidra project files,
  and the temporary workspace is cleaned up according to configuration.
- When Ghidra is not installed/configured, the service degrades gracefully and
  reports its status instead of failing the pipeline.

This module does NOT automatically send decompiled output to an AI model.
"""

import os
import re
import json
import shutil
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from app.core.config import settings, BASE_DIR
from app.core.logger import logger

# Maximum number of strings returned to in-memory consumers (evidence/AI).
# The raw count discovered by the Ghidra script is preserved separately.
_MAX_RETURNED_STRINGS = 200

# Maximum number of call-graph relationships retained (raw count preserved).
_MAX_RETURNED_RELATIONSHIPS = 1000

# Allowed characters for an isolated workspace directory name.
_SAFE_LABEL = re.compile(r"[^A-Za-z0-9_-]")


@dataclass
class GhidraFunctionItem:
    """A single function recovered from the Ghidra program database."""
    name: str
    address: str
    size: int = 0
    is_thunk: bool = False
    calling_convention: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "is_thunk": self.is_thunk,
            "calling_convention": self.calling_convention,
        }


@dataclass
class GhidraRelationshipItem:
    """A call-graph edge showing one function invoking another."""
    from_address: str
    from_name: str
    to_address: str
    to_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_address": self.from_address,
            "from_name": self.from_name,
            "to_address": self.to_address,
            "to_name": self.to_name,
        }


@dataclass
class GhidraScanResult:
    """
    Structured outcome of a Ghidra headless analysis.

    status values:
        SUCCESS     - structured results were produced.
        UNAVAILABLE - Ghidra is not installed/configured.
        DISABLED    - Ghidra integration was disabled by configuration.
        FAILED      - Ghidra ran but did not produce usable output.
        TIMEOUT     - Ghidra exceeded the configured timeout.
    """
    available: bool = True
    status: str = "SUCCESS"
    message: str = "Ghidra analysis completed."
    program_name: Optional[str] = None
    language_id: Optional[str] = None
    processor: Optional[str] = None
    compiler: Optional[str] = None
    image_base: Optional[str] = None
    entry_point: Optional[str] = None
    function_count: int = 0
    functions: List[GhidraFunctionItem] = field(default_factory=list)
    imports: List[Dict[str, str]] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    string_count: int = 0
    strings: List[str] = field(default_factory=list)
    relationship_count: int = 0
    relationships: List[GhidraRelationshipItem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "status": self.status,
            "message": self.message,
            "program_name": self.program_name,
            "language_id": self.language_id,
            "processor": self.processor,
            "compiler": self.compiler,
            "image_base": self.image_base,
            "entry_point": self.entry_point,
            "function_count": self.function_count,
            "import_count": len(self.imports),
            "export_count": len(self.exports),
            "string_count": self.string_count,
            "relationship_count": self.relationship_count,
            "functions": [f.to_dict() for f in self.functions],
            "imports": list(self.imports),
            "exports": list(self.exports),
            "strings": list(self.strings),
            "relationships": [r.to_dict() for r in self.relationships],
            "errors": list(self.errors),
        }


class GhidraAnalyzerService:
    """
    Service that drives Ghidra's headless analyzer over quarantined binaries.
    """

    def __init__(
        self,
        ghidra_home: Optional[Path] = None,
        workspace_dir: Optional[Path] = None,
        script_dir: Optional[Path] = None,
    ):
        if ghidra_home is not None:
            self.ghidra_home: Optional[Path] = Path(ghidra_home)
        elif settings.GHIDRA_HOME:
            self.ghidra_home = Path(settings.GHIDRA_HOME)
        else:
            self.ghidra_home = None

        self.workspace_dir = workspace_dir or settings.GHIDRA_WORKSPACE_DIR
        self.script_dir = script_dir or (BASE_DIR / "ghidra_scripts")

    # ------------------------------------------------------------------ #
    # Availability
    # ------------------------------------------------------------------ #
    def _resolve_headless(self) -> Optional[Path]:
        """Locates the analyzeHeadless launcher under GHIDRA_HOME/support."""
        if not self.ghidra_home or not self.ghidra_home.is_dir():
            return None
        for launcher_name in ("analyzeHeadless.bat", "analyzeHeadless"):
            candidate = self.ghidra_home / "support" / launcher_name
            if candidate.is_file():
                return candidate
        return None

    def _check_sidecar_health(self) -> tuple[bool, str]:
        """Probes the sidecar /health endpoint with a 3-second timeout."""
        import urllib.request
        import urllib.error

        url = f"{settings.GHIDRA_SIDECAR_URL.rstrip('/')}/health"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.getcode() == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    if payload.get("status") == "healthy" or payload.get("ghidra_available"):
                        return True, "Sidecar is healthy and Ghidra is available."
                    return False, f"Sidecar reported degraded state: {payload}"
                return False, f"Sidecar /health returned HTTP {resp.getcode()}"
        except Exception as exc:
            return False, f"Sidecar connection failed: {exc}"

    def is_available(self) -> Any:
        """Returns (available: bool, reason: str) without invoking Ghidra."""
        if not getattr(settings, "GHIDRA_ENABLED", True):
            return False, "Ghidra integration is disabled (GHIDRA_ENABLED=false)."

        if getattr(settings, "GHIDRA_SIDECAR_ENABLED", False):
            healthy, reason = self._check_sidecar_health()
            if healthy:
                return True, "Ghidra containerized sidecar is healthy and available."
            return False, f"Ghidra sidecar unavailable: {reason}"

        if not self.ghidra_home or not self.ghidra_home.is_dir():
            return False, (
                "Ghidra is not configured. Set GHIDRA_HOME to your extracted Ghidra "
                "installation directory to enable headless reverse engineering."
            )
        if self._resolve_headless() is None:
            return False, (
                "Ghidra headless launcher (support/analyzeHeadless) was not found "
                "under GHIDRA_HOME."
            )
        return True, "Ghidra headless analyzer is available."

    # ------------------------------------------------------------------ #
    # Workspace helpers
    # ------------------------------------------------------------------ #
    def _safe_workspace(self, label: str) -> Path:
        """Builds an isolated workspace path with a sanitized label."""
        safe_label = _SAFE_LABEL.sub("_", str(label or "sample"))[:64] or "sample"
        return self.workspace_dir / safe_label

    # ------------------------------------------------------------------ #
    # Analysis
    # ------------------------------------------------------------------ #
    def analyze_file(
        self,
        file_path: Optional[Path],
        analysis_id: Optional[str] = None,
    ) -> GhidraScanResult:
        """
        Executes Ghidra headless analysis over a quarantined sample file.

        Args:
            file_path: Path to the quarantined sample (never executed).
            analysis_id: Optional analysis identifier used for workspace isolation.

        Returns:
            GhidraScanResult describing the outcome.
        """
        available, reason = self.is_available()
        if not available:
            # Distinguish deliberate disablement from a missing installation.
            disabled = "disabled" in reason.lower()
            return GhidraScanResult(
                available=False,
                status="DISABLED" if disabled else "UNAVAILABLE",
                message=reason,
            )

        if not file_path:
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message="No quarantined sample path was provided for Ghidra analysis.",
            )

        source = Path(file_path)
        if not source.is_file():
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message="Quarantined sample file could not be found for Ghidra analysis.",
            )

        # OPS-02: Route to containerized sidecar service if enabled
        if getattr(settings, "GHIDRA_SIDECAR_ENABLED", False):
            return self._call_sidecar(source, analysis_id)

        headless = self._resolve_headless()
        workspace = self._safe_workspace(analysis_id or source.stem)
        project_dir = workspace / "project"
        out_file = workspace / "program_info.json"
        stdout_text = ""
        stderr_text = ""

        try:
            workspace.mkdir(parents=True, exist_ok=True)
            project_dir.mkdir(parents=True, exist_ok=True)

            env = os.environ.copy()
            env["GHIDRA_OUT_FILE"] = str(out_file)
            env["GHIDRA_MAX_FUNCTIONS"] = str(settings.GHIDRA_MAX_FUNCTIONS)

            # Argument array only - no shell string concatenation.
            command: List[str] = [
                str(headless),
                str(project_dir),
                "EthioAIDefender",
                "-scriptPath", str(self.script_dir),
                "-import", str(source),
                "-postScript", "dump_program_info.py",
                "-deleteProject",
            ]

            logger.info(
                f"Launching Ghidra headless analysis for '{source.name}' "
                f"(workspace isolated, timeout={settings.GHIDRA_TIMEOUT_SECONDS}s)."
            )

            completed = subprocess.run(
                command,
                env=env,
                capture_output=True,
                text=True,
                timeout=settings.GHIDRA_TIMEOUT_SECONDS,
                shell=False,
            )
            stdout_text = completed.stdout or ""
            stderr_text = completed.stderr or ""

            if completed.returncode != 0:
                logger.warning(
                    f"Ghidra headless exited with code {completed.returncode} for '{source.name}'."
                )
                return GhidraScanResult(
                    available=True,
                    status="FAILED",
                    message=(
                        f"Ghidra headless analyzer exited with code {completed.returncode}."
                    ),
                    errors=[self._tail(stderr_text) or self._tail(stdout_text)],
                )

            if not out_file.is_file():
                return GhidraScanResult(
                    available=True,
                    status="FAILED",
                    message="Ghidra completed but produced no structured output.",
                    errors=[self._tail(stderr_text) or self._tail(stdout_text)],
                )

            with open(out_file, "r", encoding="utf-8") as fh:
                payload = json.load(fh)

            return self._build_result(payload)

        except subprocess.TimeoutExpired:
            logger.warning(
                f"Ghidra analysis timed out after {settings.GHIDRA_TIMEOUT_SECONDS}s for '{source.name}'."
            )
            return GhidraScanResult(
                available=True,
                status="TIMEOUT",
                message=(
                    f"Ghidra analysis exceeded the {settings.GHIDRA_TIMEOUT_SECONDS}s "
                    "timeout limit."
                ),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"Ghidra analysis failed for '{source.name}': {exc}")
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message=f"Ghidra analysis error: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - defensive: never crash the pipeline
            logger.warning(f"Unexpected Ghidra analysis error for '{source.name}': {exc}")
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message=f"Unexpected Ghidra analysis error: {exc}",
            )
        finally:
            if not settings.GHIDRA_KEEP_WORKSPACE:
                shutil.rmtree(workspace, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _call_sidecar(
        self,
        source: Path,
        analysis_id: Optional[str] = None,
    ) -> GhidraScanResult:
        """
        Invokes containerized Ghidra sidecar service over internal HTTP RPC.
        Defensively handles timeouts, network failures, and malformed responses.
        """
        import urllib.request
        import urllib.error

        url = f"{settings.GHIDRA_SIDECAR_URL.rstrip('/')}/analyze"
        headers = {"Content-Type": "application/json"}
        if getattr(settings, "GHIDRA_SIDECAR_TOKEN", None):
            headers["X-Sidecar-Token"] = settings.GHIDRA_SIDECAR_TOKEN

        payload_req = {
            "sample_path": source.name,
            "analysis_id": analysis_id or source.stem,
            "max_functions": settings.GHIDRA_MAX_FUNCTIONS,
            "timeout_seconds": settings.GHIDRA_SIDECAR_TIMEOUT_SECONDS,
        }

        data_bytes = json.dumps(payload_req).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=settings.GHIDRA_SIDECAR_TIMEOUT_SECONDS) as resp:
                resp_bytes = resp.read()
                resp_payload = json.loads(resp_bytes.decode("utf-8"))

                if resp_payload.get("status") == "TIMEOUT":
                    return GhidraScanResult(
                        available=True,
                        status="TIMEOUT",
                        message=resp_payload.get("message", "Ghidra sidecar analysis timed out."),
                        errors=resp_payload.get("errors", []),
                    )
                if resp_payload.get("status") == "FAILED" or not resp_payload.get("ok", True):
                    return GhidraScanResult(
                        available=True,
                        status="FAILED",
                        message=resp_payload.get("message", "Ghidra sidecar analysis failed."),
                        errors=resp_payload.get("errors", []),
                    )

                return self._build_result(resp_payload)

        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8")
            except Exception:
                pass
            logger.warning(f"Ghidra sidecar HTTP error {exc.code} for '{source.name}': {err_body}")
            if exc.code == 408:
                return GhidraScanResult(
                    available=True,
                    status="TIMEOUT",
                    message="Ghidra sidecar request timed out.",
                    errors=[f"HTTP 408: {err_body}"],
                )
            if exc.code in (502, 503, 504):
                return GhidraScanResult(
                    available=False,
                    status="UNAVAILABLE",
                    message=f"Ghidra sidecar service unavailable (HTTP {exc.code}).",
                    errors=[err_body],
                )
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message=f"Ghidra sidecar returned HTTP {exc.code}.",
                errors=[err_body],
            )
        except (urllib.error.URLError, ConnectionRefusedError, OSError) as exc:
            logger.warning(f"Ghidra sidecar connection failed for '{source.name}': {exc}")
            return GhidraScanResult(
                available=False,
                status="UNAVAILABLE",
                message=f"Ghidra sidecar service unreachable: {exc}",
                errors=[str(exc)],
            )
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(f"Ghidra sidecar returned malformed response for '{source.name}': {exc}")
            return GhidraScanResult(
                available=True,
                status="FAILED",
                message=f"Ghidra sidecar returned invalid response format: {exc}",
                errors=[str(exc)],
            )
        except Exception as exc:
            logger.warning(f"Unexpected error communicating with Ghidra sidecar for '{source.name}': {exc}")
            return GhidraScanResult(
                available=False,
                status="UNAVAILABLE",
                message=f"Ghidra sidecar error: {exc}",
                errors=[str(exc)],
            )
    @staticmethod
    def _tail(text: str, limit: int = 500) -> str:
        """Returns a trimmed tail of captured process output for diagnostics."""
        if not text:
            return ""
        cleaned = text.strip()
        return cleaned[-limit:] if len(cleaned) > limit else cleaned

    def _build_result(self, payload: Dict[str, Any]) -> GhidraScanResult:
        """Converts the raw Ghidra script JSON into a structured result."""
        raw_functions = payload.get("functions") or []
        functions = [
            GhidraFunctionItem(
                name=str(fn.get("name", "FUN_unknown")),
                address=str(fn.get("address", "")),
                size=int(fn.get("size", 0) or 0),
                is_thunk=bool(fn.get("is_thunk", False)),
                calling_convention=fn.get("calling_convention"),
            )
            for fn in raw_functions
            if isinstance(fn, dict)
        ]

        raw_imports = payload.get("imports") or []
        imports = [
            {"name": str(imp.get("name", "")), "library": str(imp.get("library", "EXTERNAL"))}
            for imp in raw_imports
            if isinstance(imp, dict)
        ]

        raw_exports = payload.get("exports") or []
        exports = [str(exp) for exp in raw_exports]

        raw_strings = payload.get("strings") or []
        string_values: List[str] = []
        for item in raw_strings:
            if isinstance(item, dict):
                value = item.get("value")
                if value:
                    string_values.append(str(value))

        string_count = int(payload.get("string_count", len(string_values)) or len(string_values))

        raw_rels = payload.get("relationships") or []
        relationships = [
            GhidraRelationshipItem(
                from_address=str(rel.get("from_address", "")),
                from_name=str(rel.get("from_name", "")),
                to_address=str(rel.get("to_address", "")),
                to_name=str(rel.get("to_name", "")),
            )
            for rel in raw_rels
            if isinstance(rel, dict)
        ]
        relationship_count = int(
            payload.get("relationship_count", len(relationships)) or len(relationships)
        )

        return GhidraScanResult(
            available=True,
            status="SUCCESS",
            message=(
                f"Ghidra recovered {int(payload.get('function_count', len(functions)) or len(functions))} "
                f"function(s), {len(imports)} import(s), and {string_count} string(s)."
            ),
            program_name=payload.get("program_name"),
            language_id=payload.get("language_id"),
            processor=payload.get("processor"),
            compiler=payload.get("compiler"),
            image_base=payload.get("image_base"),
            entry_point=payload.get("entry_point"),
            function_count=int(payload.get("function_count", len(functions)) or len(functions)),
            functions=functions,
            imports=imports,
            exports=exports,
            string_count=string_count,
            strings=string_values[:_MAX_RETURNED_STRINGS],
            relationship_count=relationship_count,
            relationships=relationships[:_MAX_RETURNED_RELATIONSHIPS],
            errors=[str(e) for e in (payload.get("errors") or [])],
        )


# Global singleton instance
ghidra_analyzer_service = GhidraAnalyzerService()
