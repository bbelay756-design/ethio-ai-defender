"""
CSRF Protection for Cookie-Based Authentication.

Provides double-submit cookie pattern CSRF protection for state-changing requests
when using HttpOnly cookie authentication.
"""

import secrets
import hmac
import hashlib
from typing import Optional
from fastapi import Request, HTTPException, status, Depends, Cookie, Header
from app.core.config import settings


CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_TOKEN_LENGTH = 32


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_LENGTH)


def set_csrf_cookie(response, csrf_token: str) -> None:
    """Set the CSRF token as a cookie (not HttpOnly so JS can read it for double-submit)."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=False,  # Must be readable by JavaScript for double-submit pattern
        secure=not settings.DEBUG,
        samesite="strict",
        path="/"
    )


def clear_csrf_cookie(response) -> None:
    """Clear the CSRF cookie on logout."""
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/", httponly=False, secure=not settings.DEBUG, samesite="strict")


def verify_csrf_token(request: Request, csrf_header: Optional[str] = Header(None, alias=CSRF_HEADER_NAME), csrf_cookie: Optional[str] = Cookie(None, alias=CSRF_COOKIE_NAME)) -> bool:
    """
    Verify CSRF token using double-submit cookie pattern.
    
    For cookie-based auth, the CSRF token must be present in both:
    - The CSRF cookie (set by server, readable by JS)
    - The X-CSRF-Token header (sent by JS with each state-changing request)
    
    Returns True if valid, raises HTTPException if invalid.
    """
    # Only enforce CSRF for state-changing methods when cookie auth is used
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    
    # Exempt authentication endpoints from CSRF protection
    # These are entry points that establish the session
    auth_paths = ["/api/auth/login", "/api/auth/register", "/api/auth/logout", "/api/auth/csrf-token"]
    if request.url.path in auth_paths:
        return True
    
    # Check if request uses cookie authentication (has auth_token cookie)
    auth_cookie = request.cookies.get("auth_token")
    auth_header = request.headers.get("Authorization", "")
    
    # If using Bearer header (API client), skip CSRF check
    if auth_header.startswith("Bearer "):
        return True
    
    # If using cookie auth, enforce CSRF
    if auth_cookie:
        if not csrf_cookie or not csrf_header:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing. Include X-CSRF-Token header with cookie authentication."
            )
        
        # Constant-time comparison
        if not hmac.compare_digest(csrf_cookie, csrf_header):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token."
            )
    
    return True


async def get_csrf_token_endpoint(request: Request, response: Response) -> dict:
    """Endpoint to get a new CSRF token for the client."""
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)
    return {"csrf_token": csrf_token}