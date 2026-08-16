"""
In-Memory Rate Limiter and Brute-Force Protection Engine.
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple
from app.core.config import settings


class InMemoryRateLimiter:
    """
    Sliding-window request rate limiter and authentication attempt tracker.
    """

    def __init__(self):
        # Key -> List of timestamps
        self._requests: Dict[str, List[float]] = defaultdict(list)
        # Key -> Failed attempt count and lockout expiry
        self._failed_attempts: Dict[str, int] = defaultdict(int)
        self._lockouts: Dict[str, float] = {}

    def is_rate_limited(self, identifier: str, max_requests: int = None, window_seconds: int = 60) -> bool:
        """
        Evaluates if the identifier (e.g. IP or username) has exceeded max_requests within window_seconds.
        """
        max_requests = max_requests or settings.RATE_LIMIT_LOGIN_PER_MINUTE
        now = time.time()
        timestamps = self._requests[identifier]

        # Evict timestamps older than the sliding window
        self._requests[identifier] = [t for t in timestamps if now - t < window_seconds]

        if len(self._requests[identifier]) >= max_requests:
            return True

        self._requests[identifier].append(now)
        return False

    def is_account_locked(self, identifier: str) -> Tuple[bool, int]:
        """
        Checks if an account or IP is locked out.
        Returns (is_locked, remaining_lockout_seconds).
        """
        now = time.time()
        lock_until = self._lockouts.get(identifier, 0)
        if now < lock_until:
            remaining = int(lock_until - now)
            return True, remaining
        elif identifier in self._lockouts:
            # Lock expired
            del self._lockouts[identifier]
            self._failed_attempts[identifier] = 0

        return False, 0

    def record_failed_attempt(self, identifier: str) -> Tuple[bool, int]:
        """
        Increments failed attempt counter. Locks identifier if threshold is met.
        Returns (is_now_locked, lock_duration_minutes).
        """
        self._failed_attempts[identifier] += 1
        if self._failed_attempts[identifier] >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            lockout_time = time.time() + (settings.LOCKOUT_DURATION_MINUTES * 60)
            self._lockouts[identifier] = lockout_time
            return True, settings.LOCKOUT_DURATION_MINUTES
        return False, 0

    def record_successful_login(self, identifier: str) -> None:
        """Resets failed attempt counters upon valid authentication."""
        self._failed_attempts.pop(identifier, None)
        self._lockouts.pop(identifier, None)

    def reset_all(self) -> None:
        """Resets all rate limit state (useful in testing)."""
        self._requests.clear()
        self._failed_attempts.clear()
        self._lockouts.clear()


rate_limiter = InMemoryRateLimiter()
