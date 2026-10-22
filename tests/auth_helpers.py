"""
Shared authentication helpers for the test suite (P1 / SEC-05).

Upload endpoints now require authentication and the UPLOAD_FILES permission
(ADMIN / ANALYST). These helpers mint throwaway users and their Bearer-token
headers so individual test modules do not duplicate the setup logic.
"""

import uuid

from app.auth.service import AuthService
from app.auth.roles import UserRole

DEFAULT_TEST_PASSWORD = "PasswordTest2026!"


def _create_user_with_headers(db, role: UserRole, username_prefix: str = None):
    uid = uuid.uuid4().hex[:8]
    prefix = username_prefix or role.value.lower()
    username = f"{prefix}_{uid}"
    user = AuthService.register_user(
        db,
        username,
        f"{username}@test.et",
        DEFAULT_TEST_PASSWORD,
        role=role.value,
    )
    token = AuthService.create_token_for_user(user)["access_token"]
    return user, {"Authorization": f"Bearer {token}"}


def make_analyst(db, username_prefix: str = None):
    """Create an ANALYST user and return (user, auth_headers)."""
    return _create_user_with_headers(db, UserRole.ANALYST, username_prefix)


def make_admin(db, username_prefix: str = None):
    """Create an ADMIN user and return (user, auth_headers)."""
    return _create_user_with_headers(db, UserRole.ADMIN, username_prefix)


def make_viewer(db, username_prefix: str = None):
    """Create a VIEWER user and return (user, auth_headers)."""
    return _create_user_with_headers(db, UserRole.VIEWER, username_prefix)
