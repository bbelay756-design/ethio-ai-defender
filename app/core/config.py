"""
Application Configuration and Environment Settings for ETHIO-AI Defender.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent


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
    
    # Strictly supported static analysis file extensions
    ALLOWED_EXTENSIONS: Set[str] = field(default_factory=lambda: {".exe", ".dll"})

    # Storage Paths (Outside any web root)
    STORAGE_BASE_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage")
    UPLOAD_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "uploads")
    QUARANTINE_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "quarantine")
    LOG_DIR: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs")
    LOG_FILE: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs" / "defender.log")
    AUDIT_LOG_FILE: Path = field(default_factory=lambda: BASE_DIR / "storage" / "logs" / "audit.jsonl")
    AUDIT_LOG_MAX_BYTES: int = int(os.getenv("AUDIT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
    AUDIT_LOG_BACKUP_COUNT: int = int(os.getenv("AUDIT_LOG_BACKUP_COUNT", "10"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # AI Security Analyst Configuration
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "mock")
    AI_MODEL_NAME: str = os.getenv("AI_MODEL_NAME", "gemini-1.5-flash")
    AI_TIMEOUT_SECONDS: int = int(os.getenv("AI_TIMEOUT_SECONDS", "15"))

    # Database Configuration (SQLite default)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'storage' / 'defender.db'}")

    # Authentication & Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "ethio-ai-defender-secure-platform-master-key-2026")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    MAX_FAILED_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES: int = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
    RATE_LIMIT_LOGIN_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_LOGIN_PER_MINUTE", "10"))

    def ensure_directories(self) -> None:
        """Ensure all required storage and isolation directories exist securely."""
        for directory in [self.STORAGE_BASE_DIR, self.UPLOAD_DIR, self.QUARANTINE_DIR, self.LOG_DIR]:
            directory.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()
