"""
P1 / SEC-07 regression tests: frontend render-safety static guards.

These are source-level assertions over frontend/static/js/app.js. They lock in
the fix that untrusted values embedded inside inline event-handler JavaScript
string literals are escaped with escapeJsString() rather than escapeHtml()
(which the HTML parser decodes back into raw quotes before JS parsing).
"""

import re
import unittest

from app.core.config import BASE_DIR


APP_JS = BASE_DIR / "frontend" / "static" / "js" / "app.js"


class TestFrontendRenderSafety(unittest.TestCase):
    """Static source guards for the inline-handler XSS fix."""

    @classmethod
    def setUpClass(cls):
        cls.source = APP_JS.read_text(encoding="utf-8")

    def test_escape_js_string_defined(self):
        self.assertIn("function escapeJsString", self.source)

    def test_escape_js_string_escapes_quotes_and_backslash(self):
        # Backslash, single-quote and double-quote must be neutralised.
        self.assertIn("\\x27", self.source)
        self.assertIn("\\x22", self.source)
        self.assertIn(".replace(/\\\\/g", self.source)

    def test_no_escape_html_inside_inline_handler_string_arg(self):
        """escapeHtml must never be used inside a quoted inline-handler JS arg."""
        pattern = re.compile(r"""on\w+="[^"]*'\$\{\s*escapeHtml\(""")
        matches = pattern.findall(self.source)
        self.assertEqual(
            matches,
            [],
            f"escapeHtml used in inline handler JS string arg at {len(matches)} site(s).",
        )

    def test_admin_handlers_use_js_string_escaping(self):
        for snippet in (
            "openAdminRoleModal(${u.id}, '${escapeJsString(u.username)}'",
            "openAdminResetPassModal(${u.id}, '${escapeJsString(u.username)}'",
            "handleAdminUnlockUser(${u.id}, '${escapeJsString(u.username)}'",
            "deleteUserAccount(${u.id}, '${escapeJsString(u.username)}'",
        ):
            self.assertIn(snippet, self.source, snippet)

    def test_user_controlled_username_no_longer_uses_escape_html_in_handler(self):
        self.assertNotIn("'${escapeHtml(u.username)}'", self.source)

    def test_student_upload_intake_removed_from_navigation(self):
        # The Student "Safe Sample Analysis" upload nav label is gone.
        self.assertNotIn("Safe Sample Analysis", self.source)
        # A guard redirects/denies Student attempts to reach the upload intake.
        self.assertIn(
            "Uploading binaries is restricted to Analysts and Administrators",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
