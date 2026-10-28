"""
Pytest configuration for ETHIO-AI Defender test suite.

Ensures strict operational database isolation. All pytest executions
use an isolated temporary SQLite database, protecting storage/defender.db.
"""

import os
import tempfile
from pathlib import Path
import pytest

_isolated_db_dir = tempfile.mkdtemp(prefix="defender_pytest_")
_isolated_db_path = os.path.join(_isolated_db_dir, "pytest_defender.db")

# Point all database settings to this isolated test database before any models or app modules are loaded
os.environ["DATABASE_URL"] = f"sqlite:///{_isolated_db_path}"
os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{_isolated_db_path}"

from app.db.session import init_db, SessionLocal
init_db()


@pytest.fixture(autouse=True)
def ensure_db_isolation():
    """Safety check verifying that operational database is never bound during tests."""
    from app.core.config import settings
    assert "pytest_defender.db" in settings.DATABASE_URL or "test" in settings.DATABASE_URL.lower() or ":memory:" in settings.DATABASE_URL
    yield
