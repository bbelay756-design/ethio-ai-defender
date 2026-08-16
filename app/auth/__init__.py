"""
Authentication and Access Control Package
"""

from app.auth.roles import (
    UserRole,
    Permission,
    ROLE_PERMISSIONS,
    has_permission,
)
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.auth.rate_limiter import rate_limiter
from app.auth.service import (
    AuthService,
    AuthenticationError,
    AccountLockedError,
    RateLimitExceededError,
)
from app.auth.dependencies import (
    get_current_user,
    require_roles,
    require_permissions,
)

__all__ = [
    "UserRole",
    "Permission",
    "ROLE_PERMISSIONS",
    "has_permission",
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "rate_limiter",
    "AuthService",
    "AuthenticationError",
    "AccountLockedError",
    "RateLimitExceededError",
    "get_current_user",
    "require_roles",
    "require_permissions",
]
