"""
Application Configuration and Environment Settings for ETHIO-AI Defender.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set

from dotenv import load_dotenv

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load environment variables from the project-level .env file if present.
load_dotenv(BASE_DIR / ".env")
load_dotenv()

# Minimum acceptable length for the token-signing secret.
MIN_SECRET_KEY_LENGTH = 32
# Historical insecure default; explicitly rejected so it can never be reused.
LEGACY_INSECURE_SECRET = "ethio-ai-defender-secure-platform-master-key-2026"


@dataclass
class Settings:
    """System configuration settings for ETHIO-AI Defender."""
    PROJECT_NAME: str = "ETHIO-AI Defender"
    PROJECT_FULL_NAME: str = "AI-Powered Defensive Malware Analysis and Reverse Engineering Platform for Ethiopia"
    VERSION: str = "0.1.0"
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

    # Security & Storage Configuration
    # Max file size: 50MB (52,428,800 bytes) by default
    MAX_FILE_SIZE_BYTES: int = int(os.getenv("MAX_FILE_SIZE_BYTES", str(50 * 1024 * 1024)))

    # Upper bound for the entire multipart request body on upload endpoints.
    # Slightly larger than MAX_FILE_SIZE_BYTES to accommodate multipart
    # form-field/framing overhead. Enforced by the ASGI body-size middleware
    # BEFORE multipart parsing; see app/middleware/body_size_limit.py.
    MAX_UPLOAD_BODY_BYTES: int = int(os.getenv("MAX_UPLOAD_BODY_BYTES", str(51 * 1024 * 1024)))
    # Chunk size used when streaming an uploaded file through read_upload_bounded.
    UPLOAD_CHUNK_SIZE: int = int(os.getenv("UPLOAD_CHUNK_SIZE", str(1024 * 1024)))
    
    # Strictly supported static analysis file extensions
    ALLOWED_EXTENSIONS: Set[str] = field(default_factory=lambda: {".exe", ".dll"})

    # Storage Paths (Outside any web root)
    STORAGE_BASE_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage")
    UPLOAD_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "uploads")
    QUARANTINE_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "quarantine")
    LOG_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs")
    LOG_FILE: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs" / "defender.log")
    GHIDRA_WORKSPACE_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "ghidra")
    AUDIT_LOG_FILE: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs" / "audit.jsonl")
    AUDIT_LOG_MAX_BYTES: int = int(os.getenv("AUDIT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
    AUDIT_LOG_BACKUP_COUNT: int = int(os.getenv("AUDIT_LOG_BACKUP_COUNT", "10"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # AI Security Analyst Configuration
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "mock")
    AI_MODEL_NAME: str = os.getenv("AI_MODEL_NAME", "gemini-1.5-flash")
    AI_TIMEOUT_SECONDS: int = int(os.getenv("AI_TIMEOUT_SECONDS", "15"))

    # Threat Intelligence Providers Configuration
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
    THREAT_INTEL_TIMEOUT_SECONDS: int = int(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "10"))

    # Ghidra Headless Reverse-Engineering Configuration
    # GHIDRA_HOME points to the extracted Ghidra installation directory (empty = disabled/unavailable).
    GHIDRA_HOME: str = os.getenv("GHIDRA_HOME", "")
    GHIDRA_ENABLED: bool = os.getenv("GHIDRA_ENABLED", "true").lower() in ("true", "1", "yes")
    GHIDRA_TIMEOUT_SECONDS: int = int(os.getenv("GHIDRA_TIMEOUT_SECONDS", "300"))
    GHIDRA_MAX_FUNCTIONS: int = int(os.getenv("GHIDRA_MAX_FUNCTIONS", "2000"))
    # Retain the isolated Ghidra workspace after analysis for troubleshooting (default: cleaned up).
    GHIDRA_KEEP_WORKSPACE: bool = os.getenv("GHIDRA_KEEP_WORKSPACE", "false").lower() in ("true", "1", "yes")

    # Machine Learning Static Analysis Configuration (Milestone ML-04 Shadow Mode)
    # Defaults to disabled (False) or safe shadow mode (True); does not alter blocking decisions.
    ML_ENABLED: bool = os.getenv("ML_ENABLED", "false").lower() in ("true", "1", "yes")
    ML_SHADOW_MODE: bool = os.getenv("ML_SHADOW_MODE", "true").lower() in ("true", "1", "yes")
    ML_TIMEOUT_SECONDS: int = int(os.getenv("ML_TIMEOUT_SECONDS", "10"))

    # Database Configuration (SQLite default)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'storage' / 'defender.db'}")

    # Authentication & Security Configuration
    # No default is provided: the signing secret MUST be supplied via the
    # SECRET_KEY environment variable and is validated at startup (fail closed).
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    MAX_FAILED_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES: int = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
    RATE_LIMIT_LOGIN_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_LOGIN_PER_MINUTE", "10"))

    # Roles that unauthenticated clients are permitted to self-register as.
    # ADMIN is intentionally never permitted here; privileged roles are assigned
    # only through the ADMIN-guarded user provisioning endpoints.
    SELF_REGISTRATION_ROLES: Set[str] = field(
        default_factory=lambda: {
            role.strip().upper()
            for role in os.getenv("SELF_REGISTRATION_ROLES", "VIEWER").split(",")
            if role.strip()
        }
    )

    # Cross-Origin Resource Sharing (CORS).
    # Explicit allowlist of trusted front-end origins. Empty (the default)
    # disables cross-origin access entirely, which is the correct behaviour for
    # the same-origin, single-host deployment the platform ships with. Wildcards
    # are explicitly rejected by validate_cors(). Populate via the comma
    # separated CORS_ORIGINS environment variable only for a real, known
    # front-end origin.
    CORS_ORIGINS: Set[str] = field(
        default_factory=lambda: {
            origin.strip()
            for origin in os.getenv("CORS_ORIGINS", "").split(",")
            if origin.strip()
        }
    )
    CORS_ALLOW_CREDENTIALS: bool = os.getenv(
        "CORS_ALLOW_CREDENTIALS", "false"
    ).lower() in ("true", "1", "yes")

    def validate_cors(self) -> None:
        """
        Fail closed if CORS is configured unsafely.

        Rejects the wildcard origin and any wildcard pattern, which is critical
        when credentials are allowed (a wildcard + credentials combination lets
        any site read authenticated responses).
        """
        for origin in self.CORS_ORIGINS:
            if "*" in origin:
                raise RuntimeError(
                    "SECURITY CONFIGURATION ERROR: CORS_ORIGINS must list explicit "
                    "origins; wildcards ('*') are not permitted. Configure the exact "
                    "front-end origin(s) via the CORS_ORIGINS environment variable."
                )
        if self.CORS_ALLOW_CREDENTIALS and not self.CORS_ORIGINS:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: CORS_ALLOW_CREDENTIALS is enabled but "
                "CORS_ORIGINS is empty. Configure an explicit origin allowlist."
            )

    def validate_security(self) -> None:
        """
        Fail closed if the application is configured with an unsafe signing key.

        Raises RuntimeError (never leaking the secret value) when SECRET_KEY is
        missing, empty, the historical insecure default, or too short.
        """
        key = (self.SECRET_KEY or "").strip()
        if not key:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: SECRET_KEY is not set. Set a strong, "
                "unique SECRET_KEY environment variable before starting the platform."
            )
        if key == LEGACY_INSECURE_SECRET:
            raise RuntimeError(
                "SECURITY CONFIGURATION ERROR: SECRET_KEY uses the insecure legacy default. "
                "Generate a new secret and set it via the SECRET_KEY environment variable."
            )
        if len(key) < MIN_SECRET_KEY_LENGTH:
            raise RuntimeError(
                f"SECURITY CONFIGURATION ERROR: SECRET_KEY must be at least "
                f"{MIN_SECRET_KEY_LENGTH} characters long."
            )

    def ensure_directories(self) -> None:
        """Ensure all required storage and isolation directories exist securely."""
        for directory in [self.STORAGE_BASE_DIR, self.UPLOAD_DIR, self.QUARANTINE_DIR, self.LOG_DIR, self.GHIDRA_WORKSPACE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
