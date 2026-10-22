"""
SEC-02: Signing-secret validation and fail-closed startup.

The platform must refuse to start when SECRET_KEY is missing, empty, the
historical insecure default, or too short, and must never leak the secret.
"""

import asyncio
import secrets
import unittest
from unittest.mock import patch

from app.main import app, lifespan
from app.core.config import Settings, LEGACY_INSECURE_SECRET, MIN_SECRET_KEY_LENGTH


def _settings_with_key(value):
    s = Settings()
    s.SECRET_KEY = value
    return s


class TestSecretKeyConfig(unittest.TestCase):
    def test_empty_key_rejected(self):
        with self.assertRaises(RuntimeError):
            _settings_with_key("").validate_security()

    def test_none_key_rejected(self):
        with self.assertRaises(RuntimeError):
            _settings_with_key(None).validate_security()

    def test_whitespace_key_rejected(self):
        with self.assertRaises(RuntimeError):
            _settings_with_key("     ").validate_security()

    def test_legacy_literal_rejected(self):
        with self.assertRaises(RuntimeError):
            _settings_with_key(LEGACY_INSECURE_SECRET).validate_security()

    def test_short_key_rejected(self):
        with self.assertRaises(RuntimeError):
            _settings_with_key("x" * (MIN_SECRET_KEY_LENGTH - 1)).validate_security()

    def test_strong_key_accepted(self):
        _settings_with_key(secrets.token_hex(32)).validate_security()

    def test_error_message_never_contains_secret(self):
        secret = "tiny"
        try:
            _settings_with_key(secret).validate_security()
            self.fail("validate_security() should have raised for a short secret")
        except RuntimeError as exc:
            self.assertNotIn(secret, str(exc))

    def test_startup_fails_closed_with_missing_secret(self):
        with patch("app.main.settings.SECRET_KEY", ""):
            with self.assertRaises(RuntimeError):
                asyncio.run(self._enter_lifespan())

    def test_startup_succeeds_with_valid_secret(self):
        with patch("app.main.settings.SECRET_KEY", secrets.token_hex(32)):
            asyncio.run(self._enter_lifespan())

    @staticmethod
    async def _enter_lifespan():
        async with lifespan(app):
            return None


if __name__ == "__main__":
    unittest.main()
