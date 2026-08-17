"""
Authentication Service and RBAC Lifecycle Manager.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.models import UserModel, RevokedTokenModel
from app.auth.roles import UserRole
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.auth.rate_limiter import rate_limiter


class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when an account is temporarily locked due to failed attempts."""
    pass


class RateLimitExceededError(AuthenticationError):
    """Raised when request rate limit is exceeded."""
    pass


class AuthService:
    """
    Encapsulates user authentication, registration, password hashing, and token revocation.
    """

    @staticmethod
    def register_user(
        db: Session,
        username: str,
        email: str,
        password: str,
        role: str = "STUDENT"
    ) -> UserModel:
        """
        Registers a new user with salted PBKDF2-HMAC-SHA256 password digest.
        Zero plaintext password storage.
        """
        # Validate role
        role_norm = role.upper()
        if role_norm not in [r.value for r in UserRole]:
            raise ValueError(f"Invalid user role '{role}'. Allowed roles: {[r.value for r in UserRole]}")

        # Check existing username or email
        existing = db.query(UserModel).filter(
            (UserModel.username == username) | (UserModel.email == email)
        ).first()
        if existing:
            if existing.username == username:
                raise ValueError(f"Username '{username}' is already registered.")
            raise ValueError(f"Email '{email}' is already registered.")

        # Hash password securely
        salt, hashed = hash_password(password)

        user = UserModel(
            username=username,
            email=email,
            hashed_password=hashed,
            salt=salt,
            role=role_norm,
            is_active=1
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Audit log (zero password/secret logging)
        logger.info(f"Registered new platform user: '{username}' with role '{role_norm}' (ID: {user.id})")
        return user

    @staticmethod
    def authenticate_user(
        db: Session,
        username: str,
        password: str,
        client_ip: str = "127.0.0.1"
    ) -> UserModel:
        """
        Authenticates username and password against stored cryptographic salt & digest.
        Enforces rate limiting and account lockout protection.
        """
        rate_key = f"login:{username}:{client_ip}"

        # 1. Check Rate Limiting
        if rate_limiter.is_rate_limited(rate_key, max_requests=10, window_seconds=60):
            logger.warning(f"Rate limit exceeded for login attempt on '{username}' from IP {client_ip}")
            raise RateLimitExceededError("Too many login attempts. Please wait 1 minute before trying again.")

        # 2. Check Account Lockout
        is_locked, remaining_secs = rate_limiter.is_account_locked(username)
        if is_locked:
            logger.warning(f"Login rejected: Account '{username}' is locked for {remaining_secs} seconds.")
            raise AccountLockedError(f"Account is temporarily locked. Please try again in {remaining_secs // 60 + 1} minutes.")

        # 3. Lookup user
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            rate_limiter.record_failed_attempt(username)
            logger.warning(f"Failed login: User '{username}' not found.")
            raise AuthenticationError("Invalid username or password.")

        if not user.is_active:
            logger.warning(f"Failed login: User account '{username}' is deactivated.")
            raise AuthenticationError("Account is inactive. Please contact your administrator.")

        # 4. Verify password digest (constant-time)
        is_valid = verify_password(password, user.salt, user.hashed_password)
        if not is_valid:
            is_now_locked, lock_mins = rate_limiter.record_failed_attempt(username)
            logger.warning(f"Failed login: Invalid password for '{username}' (Attempt recorded).")
            if is_now_locked:
                logger.error(f"Security Alert: Account '{username}' locked out for {lock_mins} minutes due to repeated failures.")
                raise AccountLockedError(f"Account locked for {lock_mins} minutes due to excessive failed attempts.")
            raise AuthenticationError("Invalid username or password.")

        # 5. Success
        rate_limiter.record_successful_login(username)
        logger.info(f"Successful authentication for user '{username}' (Role: {user.role})")
        return user

    @staticmethod
    def create_token_for_user(user: UserModel) -> Dict[str, Any]:
        """
        Creates an HMAC-SHA256 signed access token for an authenticated user.
        """
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
        }
        token, jti, expires_at = create_access_token(payload)
        role_str = str(user.role).upper()
        role_path = role_str.lower()
        dashboard_url = f"/{role_path}/dashboard"
        return {
            "access_token": token,
            "token_type": "bearer",
            "jti": jti,
            "user_id": user.id,
            "username": user.username,
            "role": role_str,
            "dashboard_url": dashboard_url,
            "user": {
                "user_id": user.id,
                "username": user.username,
                "role": role_str,
                "dashboard_url": dashboard_url,
            },
            "expires_at": expires_at.isoformat()
        }

    @staticmethod
    def revoke_token(db: Session, token: str) -> bool:
        """
        Blacklists a token by recording its unique JTI in the database.
        """
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            exp_ts = payload.get("exp")
            if not jti or not exp_ts:
                return False

            expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            revocation = RevokedTokenModel(
                token_jti=jti,
                expires_at=expires_at
            )
            db.add(revocation)
            db.commit()
            logger.info(f"Token '{jti}' successfully revoked (Logged out).")
            return True
        except Exception as e:
            logger.warning(f"Token revocation error: {e}")
            return False

    @staticmethod
    def is_token_revoked(db: Session, token_jti: str) -> bool:
        """Checks if a token JTI has been revoked."""
        return db.query(RevokedTokenModel).filter(RevokedTokenModel.token_jti == token_jti).first() is not None

    @staticmethod
    def list_users(db: Session, skip: int = 0, limit: int = 50) -> List[UserModel]:
        """Lists users ordered by creation date."""
        return db.query(UserModel).order_by(UserModel.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_user_role(db: Session, user_id: int, new_role: str) -> Optional[UserModel]:
        """Updates a user's authorization role."""
        role_norm = new_role.upper()
        if role_norm not in [r.value for r in UserRole]:
            raise ValueError(f"Invalid role '{new_role}'. Allowed: {[r.value for r in UserRole]}")

        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            return None

        user.role = role_norm
        db.commit()
        db.refresh(user)
        logger.info(f"Updated role for user '{user.username}' (ID: {user_id}) to '{role_norm}'")
        return user
