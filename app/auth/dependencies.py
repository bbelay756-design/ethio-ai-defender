"""
FastAPI Authentication and Role-Based Authorization Dependencies.
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, Header, Request, status, Cookie
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.session import get_db
from app.db.models import UserModel
from app.auth.roles import UserRole, Permission, has_permission
from app.auth.security import decode_access_token
from app.auth.service import AuthService


def get_token_from_header_or_cookie(
    authorization: Optional[str] = Header(None),
    auth_token: Optional[str] = Cookie(None)
) -> str:
    """
    Extracts Bearer token from HTTP Authorization header or HttpOnly cookie.
    Priority: Authorization header > auth_token cookie.
    """
    # First try Authorization header (for API clients)
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Fallback to HttpOnly cookie (for browser clients)
    if auth_token:
        return auth_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication. Provide Authorization header or auth_token cookie.",
        headers={"WWW-Authenticate": "Bearer"}
    )


# Backward compatibility alias
get_token_from_header = get_token_from_header_or_cookie


def get_current_user(
    token: str = Depends(get_token_from_header_or_cookie),
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

    # SEC-06: Validate token version against user's current token version
    token_version = payload.get("tv", 1)
    if token_version != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated due to security changes. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
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
    auth_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> Optional[UserModel]:
    """
    Extracts and validates current user if Authorization header or auth_token cookie is present; otherwise returns None.
    
    Validates token signature, expiration, revocation, token version, and user active status.
    Returns None for any validation failure (treats invalid tokens as anonymous).
    Does not silently downgrade valid-but-rejected tokens to anonymous on sensitive endpoints.
    """
    token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    elif auth_token:
        token = auth_token
    
    if not token:
        return None
    
    try:
        payload = decode_access_token(token)
        
        # Check token revocation
        jti = payload.get("jti")
        if jti and AuthService.is_token_revoked(db, jti):
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        user = db.query(UserModel).filter(UserModel.id == int(user_id)).first()
        if not user or not user.is_active:
            return None
        
        # SEC-06: Validate token version against user's current token version
        token_version = payload.get("tv", 1)
        if token_version != user.token_version:
            return None
        
        return user
    except Exception:
        return None
