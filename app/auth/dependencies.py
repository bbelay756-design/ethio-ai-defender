"""
FastAPI Authentication and Role-Based Authorization Dependencies.
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.session import get_db
from app.db.models import UserModel
from app.auth.roles import UserRole, Permission, has_permission
from app.auth.security import decode_access_token
from app.auth.service import AuthService


def get_token_from_header(authorization: Optional[str] = Header(None)) -> str:
    """
    Extracts Bearer token from HTTP Authorization header.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return parts[1]


def get_current_user(
    token: str = Depends(get_token_from_header),
    db: Session = Depends(get_db)
) -> UserModel:
    """
    Validates token signature and expiration, checks token revocation, and fetches active user.
    """
    try:
        payload = decode_access_token(token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )

    jti = payload.get("jti")
    if jti and AuthService.is_token_revoked(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token subject identifier missing.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(UserModel).filter(UserModel.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    return user


def _normalize_role_values(*roles) -> List[str]:
    result = []
    for r in roles:
        if isinstance(r, (list, tuple, set)):
            result.extend(_normalize_role_values(*r))
        elif hasattr(r, "value"):
            result.append(str(r.value))
        else:
            result.append(str(r))
    return result


def require_roles(*allowed_roles):
    """
    Authorization guard requiring the authenticated user to hold one of the specified roles.
    Supports both `require_roles(UserRole.ADMIN)` and `require_roles([UserRole.ADMIN])`.
    """
    allowed_role_values = _normalize_role_values(*allowed_roles)

    def role_checker(current_user: UserModel = Depends(get_current_user)) -> UserModel:
        if current_user.role not in allowed_role_values:
            logger.warning(
                f"Access Denied: User '{current_user.username}' with role '{current_user.role}' "
                f"attempted to access restricted endpoint requiring {allowed_role_values}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: Requires one of {allowed_role_values} roles."
            )
        return current_user

    return role_checker


def require_permissions(*required_permissions):
    """
    Authorization guard requiring the authenticated user's role to possess the specified permissions.
    """
    flat_perms = []
    for p in required_permissions:
        if isinstance(p, (list, tuple, set)):
            flat_perms.extend(p)
        else:
            flat_perms.append(p)

    def permission_checker(current_user: UserModel = Depends(get_current_user)) -> UserModel:
        for perm in flat_perms:
            if not has_permission(current_user.role, perm):
                perm_val = perm.value if hasattr(perm, "value") else str(perm)
                logger.warning(
                    f"Permission Denied: User '{current_user.username}' (Role: {current_user.role}) "
                    f"lacks permission '{perm_val}'"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access forbidden: Missing required permission '{perm_val}'."
                )
        return current_user

    return permission_checker


def get_optional_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> Optional[UserModel]:
    """
    Extracts and validates current user if Authorization header is present; otherwise returns None.
    """
    if not authorization:
        return None
    try:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        payload = decode_access_token(parts[1])
        user_id = payload.get("sub")
        if not user_id:
            return None
        user = db.query(UserModel).filter(UserModel.id == int(user_id)).first()
        return user if user and user.is_active else None
    except Exception:
        return None
