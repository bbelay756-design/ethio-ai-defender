"""
Test helper utilities for security tests.
Provides common utilities for resetting database state between tests.
"""

from app.db.session import SessionLocal
from app.auth.rate_limiter_db import get_db_rate_limiter


def reset_rate_limiter():
    """Reset the database-backed rate limiter for test isolation."""
    db = SessionLocal()
    try:
        rate_limiter = get_db_rate_limiter(db)
        rate_limiter.reset_all()
    finally:
        db.close()


def reset_failed_login_attempts():
    """Reset all failed login attempt records for test isolation."""
    db = SessionLocal()
    try:
        from app.db.models import FailedLoginAttemptModel
        db.query(FailedLoginAttemptModel).delete()
        db.commit()
    finally:
        db.close()


def get_fresh_test_client():
    """Create a fresh TestClient with no cookie persistence."""
    from app.main import app
    from fastapi.testclient import TestClient
    return TestClient(app)