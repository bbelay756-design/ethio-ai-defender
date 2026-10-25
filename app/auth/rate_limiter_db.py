"""
Database-Backed Rate Limiter and Brute-Force Protection Engine.

Replaces in-memory rate limiter for multi-worker/distributed deployments.
Uses FailedLoginAttemptModel for shared state across processes.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import FailedLoginAttemptModel


class DatabaseRateLimiter:
    """
    Sliding-window request rate limiter and authentication attempt tracker
    backed by the database for multi-worker deployments.
    """

    def __init__(self, db: Session):
        self.db = db

    def is_rate_limited(self, identifier: str, max_requests: int = None, window_seconds: int = 60) -> bool:
        """
        Evaluates if the identifier (e.g. username:ip or ip) has exceeded max_requests within window_seconds.
        For login rate limiting, we track by username:ip combination.
        """
        max_requests = max_requests or settings.RATE_LIMIT_LOGIN_PER_MINUTE
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)

        record = self.db.query(FailedLoginAttemptModel).filter(
            FailedLoginAttemptModel.identifier == identifier
        ).first()

        if not record:
            return False

        if record.last_attempt_at and record.last_attempt_at > window_start:
            if record.attempt_count >= max_requests:
                return True

        return False

    def is_account_locked(self, identifier: str) -> Tuple[bool, int]:
        """
        Checks if an account or IP is locked out.
        Returns (is_locked, remaining_lockout_seconds).
        """
        now = datetime.now(timezone.utc)
        record = self.db.query(FailedLoginAttemptModel).filter(
            FailedLoginAttemptModel.identifier == identifier
        ).first()

        if not record or not record.locked_until:
            return False, 0

        # Database stores naive UTC datetimes; make them offset-aware for comparison
        locked_until = record.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if locked_until > now:
            remaining = int((locked_until - now).total_seconds())
            return True, remaining
        else:
            # Lock expired, clear it
            record.locked_until = None
            record.attempt_count = 0
            self.db.commit()
            return False, 0

    def record_failed_attempt(self, identifier: str) -> Tuple[bool, int]:
        """
        Increments failed attempt counter. Locks identifier if threshold is met.
        Returns (is_now_locked, lock_duration_minutes).
        """
        now = datetime.now(timezone.utc)
        record = self.db.query(FailedLoginAttemptModel).filter(
            FailedLoginAttemptModel.identifier == identifier
        ).first()

        if not record:
            record = FailedLoginAttemptModel(
                identifier=identifier,
                attempt_count=1,
                last_attempt_at=now,
                created_at=now
            )
            self.db.add(record)
        else:
            record.attempt_count += 1
            record.last_attempt_at = now

        if record.attempt_count >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            lockout_time = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            record.locked_until = lockout_time
            self.db.commit()
            return True, settings.LOCKOUT_DURATION_MINUTES

        self.db.commit()
        return False, 0

    def record_successful_login(self, identifier: str) -> None:
        """Resets failed attempt counters upon valid authentication."""
        record = self.db.query(FailedLoginAttemptModel).filter(
            FailedLoginAttemptModel.identifier == identifier
        ).first()

        if record:
            record.attempt_count = 0
            record.locked_until = None
            self.db.commit()

    def reset_all(self) -> None:
        """Resets all rate limit state (useful in testing)."""
        self.db.query(FailedLoginAttemptModel).delete()
        self.db.commit()


def get_db_rate_limiter(db: Session) -> DatabaseRateLimiter:
    """Factory function to create a DatabaseRateLimiter with a session."""
    return DatabaseRateLimiter(db)