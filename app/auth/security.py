"""
Cryptographic Password Hashing and Token Signing Engine

Security Guarantees:
- Passwords are salted and hashed using PBKDF2-HMAC-SHA256 (100,000 iterations).
- Passwords are never stored or compared in plaintext (constant-time verification).
- Tokens are cryptographically signed using HMAC-SHA256.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Tuple, Optional

from app.core.config import settings


def hash_password(password: str) -> Tuple[str, str]:
    """
    Generates a cryptographically random 16-byte salt and computes PBKDF2-HMAC-SHA256 hash.
    Returns (salt_hex, hashed_hex).
    """
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=100_000
    )
    return salt, key.hex()


def verify_password(password: str, salt: str, hashed_expected: str) -> bool:
    """
    Verifies a password attempt against stored salt and hash using constant-time comparison.
    """
    if not password or not salt or not hashed_expected:
        return False

    key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        iterations=100_000
    )
    return hmac.compare_digest(key.hex(), hashed_expected)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> Tuple[str, str, datetime]:
    """
    Creates an HMAC-SHA256 signed access token with unique JTI.
    Returns (token_string, token_jti, expires_at_datetime).
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    jti = secrets.token_hex(16)
    payload = data.copy()
    payload.update({
        "jti": jti,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "tv": data.get("token_version", 1),  # token version for revocation
    })

    # Header & Payload base64url encoding
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip('=')
    
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        key=settings.SECRET_KEY.encode('utf-8'),
        msg=signing_input.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    token = f"{signing_input}.{signature_b64}"
    return token, jti, expire


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Validates token signature, structure, and expiration.
    Raises ValueError if invalid or expired.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Malformed token format.")

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}"

    # Verify signature
    expected_sig = hmac.new(
        key=settings.SECRET_KEY.encode('utf-8'),
        msg=signing_input.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode('utf-8').rstrip('=')

    if not hmac.compare_digest(signature_b64, expected_sig_b64):
        raise ValueError("Invalid token signature.")

    # Decode payload (add padding if needed)
    padding = '=' * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode('utf-8')
    payload = json.loads(payload_json)

    # Verify expiration
    exp = payload.get("exp")
    if not exp or time.time() > exp:
        raise ValueError("Token has expired.")

    return payload
