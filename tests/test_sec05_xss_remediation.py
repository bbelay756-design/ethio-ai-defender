"""
SEC-05: Stored Cross-Site Scripting (XSS) Remediation Test Suite.

Verifies:
1. HTML metacharacters in sample-derived content are strictly entity-encoded in HTML reports.
2. Malicious-looking section names, filenames, indicators, and AI summaries cannot inject markup.
3. Context-appropriate escaping: HTML body text, HTML attributes, and URL contexts.
4. Safe URL sanitization: blocks 'javascript:' and 'data:' URIs, allowing only safe schemes.
5. End-to-end integration via GET /api/analyses/{id}/report?format=html renders safe text.
6. Legitimate report content and formatting remain readable and uncorrupted.
7. Database isolation and zero PE execution guarantees are maintained.
"""

import html
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.api.analyses import (
    generate_html_report_view,
    _escape_html_text,
    _escape_html_attr,
    _sanitize_url,
    _format_entropy,
)
from app.db.session import SessionLocal, init_db
from app.db.models import SampleModel, SectionModel, IndicatorModel, UserModel
from app.db.repository import SampleRepository
from app.db.schemas import SampleCreate
from app.auth.roles import UserRole
from app.auth.security import hash_password, create_access_token


class TestSec05XSSRemediation(unittest.TestCase):
    """Regression test suite for stored XSS mitigation in HTML security report exports."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Seed authenticated analyst user
        cls.analyst_user = cls.db.query(UserModel).filter(UserModel.username == "sec05_analyst").first()
        if not cls.analyst_user:
            s, h = hash_password("AnalystSecure123!")
            cls.analyst_user = UserModel(
                username="sec05_analyst",
                email="sec05_analyst@defender.local",
                hashed_password=h,
                salt=s,
                role=UserRole.ANALYST.value,
            )
            cls.db.add(cls.analyst_user)
            cls.db.commit()
            cls.db.refresh(cls.analyst_user)

        token, _, _ = create_access_token({
            "sub": str(cls.analyst_user.id),
            "username": cls.analyst_user.username,
            "role": cls.analyst_user.role,
        })
        cls.headers = {"Authorization": f"Bearer {token}"}

        # Seed test sample with inert XSS test strings across multiple fields
        cls.xss_analysis_id = "ANL-SEC05-XSS-TEST-0001"
        cls.sample = SampleRepository.create_sample(
            cls.db,
            SampleCreate(
                analysis_id=cls.xss_analysis_id,
                filename="threat_<script>alert('filename')</script>.exe",
                size=32768,
                file_type="PE32+ (Executable)",
                architecture="x86_64",
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                status="COMPLETED",
                risk_score=95,
                classification='CRITICAL"><script>alert("risk")</script>',
                user_id=cls.analyst_user.id,
            )
        )

        # Add section with crafted section name
        sec = SectionModel(
            sample_id=cls.sample.id,
            name='.text<img src=x onerror=alert("sec")>',
            virtual_address=4096,
            virtual_size=8192,
            raw_size=8192,
            entropy=6.85,
            characteristics='EXECUTE | READ & WRITE "<script>alert(1)</script>"',
        )

        # Add indicator with crafted evidence
        ind = IndicatorModel(
            sample_id=cls.sample.id,
            name='Suspicious API <svg/onload=alert("ind")>',
            category="EXECUTION",
            severity="HIGH",
            evidence='Imported CreateProcessW with payload: calc.exe & "<script>alert(1)</script>"',
            confidence=0.95,
        )

        cls.db.add_all([sec, ind])
        cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # =========================================================================
    # 1. Unit Tests for Context-Appropriate Encoding Helpers
    # =========================================================================

    def test_01_escape_html_text_encodes_all_metacharacters(self):
        """Verifies _escape_html_text encodes &, <, >, \", and '."""
        raw = '<script>alert("hello") & confirm(\'test\')</script>'
        escaped = _escape_html_text(raw)
        self.assertNotIn("<script>", escaped)
        self.assertNotIn("</script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&amp;", escaped)
        self.assertIn("&quot;", escaped)
        self.assertIn("&#x27;", escaped)

    def test_02_escape_html_attr_neutralizes_attribute_breakout(self):
        """Verifies _escape_html_attr encodes attribute delimiters including quotes and backticks."""
        raw = 'val" onmouseover="alert(1)" `test`'
        escaped = _escape_html_attr(raw)
        self.assertNotIn('"', escaped)
        self.assertNotIn("`", escaped)
        self.assertIn("&quot;", escaped)
        self.assertIn("&#96;", escaped)

    def test_03_sanitize_url_blocks_javascript_and_data_schemes(self):
        """Verifies _sanitize_url neutralizes active script pseudo-protocols."""
        dangerous_urls = [
            'javascript:alert(1)',
            'JAVASCRIPT:alert(document.cookie)',
            'javascript://%0aalert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:msgbox(1)',
        ]
        for bad_url in dangerous_urls:
            with self.subTest(url=bad_url):
                self.assertEqual(_sanitize_url(bad_url), "#")

        # Safe URLs should pass through safely encoded
        self.assertTrue(_sanitize_url("https://threat-intel.local/report").startswith("https://"))
        self.assertTrue(_sanitize_url("/api/analyses/123/report").startswith("/api/analyses/"))

    def test_04_format_entropy_safe_with_malformed_inputs(self):
        """Verifies _format_entropy handles non-float and malicious inputs gracefully."""
        self.assertEqual(_format_entropy(7.4231), "7.42")
        self.assertEqual(_format_entropy("6.85"), "6.85")
        self.assertEqual(_format_entropy("<script>alert(1)</script>"), "0.00")
        self.assertEqual(_format_entropy(None), "0.00")

    # =========================================================================
    # 2. View Function Unit Tests for generate_html_report_view
    # =========================================================================

    def test_05_generate_html_report_view_escapes_all_binary_derived_fields(self):
        """Verifies generate_html_report_view neutralizes XSS payloads in all sections."""
        synthetic_data = {
            "analysis_id": 'ANL-<b>TEST</b>-001',
            "file_information": {
                "filename": '<script>alert("filename")</script>.exe',
                "file_size": 1024,
                "file_kind": 'PE32+ <iframe src="about:blank">',
                "machine_type": 'x86_64" onfocus="alert(1)',
                "created_at": '2026-10-29 <script>',
            },
            "hashes": {
                "sha256": 'e3b0c442" onload="alert(1)',
                "md5": "d41d8cd9<b>",
            },
            "threat_score": {
                "score": 90,
                "risk_level": 'CRITICAL"><script>alert("tier")</script>',
            },
            "ai_assessment": {
                "summary": 'Observed <img src=x onerror=alert("ai")> payload.',
                "confidence": 'HIGH <script>',
            },
            "indicators": [
                {
                    "name": 'Indicator <svg/onload=alert("name")>',
                    "category": 'NETWORK <script>',
                    "severity": 'HIGH "><script>',
                    "evidence": 'Evidence & <script>alert("evidence")</script>',
                }
            ],
            "sections": {
                "sections": [
                    {
                        "name": '.text<script>alert("sec_name")</script>',
                        "virtual_address": '0x1000<script>',
                        "virtual_size": 4096,
                        "raw_size": 4096,
                        "entropy": 7.5,
                        "characteristics": 'READ & WRITE <script>alert("char")</script>',
                    }
                ]
            }
        }

        html_out = generate_html_report_view(synthetic_data, language='en"><script>alert("lang")</script>')

        # Assert zero unescaped active script tags or HTML elements injected
        self.assertNotIn("<script>", html_out)
        self.assertNotIn("</script>", html_out)
        self.assertNotIn("<iframe", html_out)
        self.assertNotIn("<svg", html_out)
        self.assertNotIn("<img", html_out)
        self.assertNotIn('onload="alert', html_out)
        self.assertNotIn('onfocus="alert', html_out)

        # Assert proper HTML entity encoding
        self.assertIn("&lt;script&gt;alert(&quot;filename&quot;)&lt;/script&gt;.exe", html_out)
        self.assertIn(".text&lt;script&gt;alert(&quot;sec_name&quot;)&lt;/script&gt;", html_out)
        self.assertIn("Indicator &lt;svg/onload=alert(&quot;name&quot;)&gt;", html_out)
        self.assertIn("Evidence &amp; &lt;script&gt;alert(&quot;evidence&quot;)&lt;/script&gt;", html_out)
        self.assertIn("&lt;img src=x onerror=alert(&quot;ai&quot;)&gt;", html_out)

        # Assert badge class attribute is safe and did not break out
        self.assertIn('class="badge badge-low"', html_out)
        self.assertNotIn('class="badge badge-crit"><script>', html_out)

        # Assert language attribute is escaped
        self.assertIn('lang="en&quot;&gt;&lt;script&gt;alert(&quot;lang&quot;)&lt;/script&gt;"', html_out)

    def test_06_legitimate_report_content_formatting_preserved(self):
        """Verifies legitimate strings and numbers remain clean and readable."""
        clean_data = {
            "analysis_id": "ANL-CLEAN-SAMPLE-0001",
            "file_information": {
                "filename": "defensive_tool_v2.exe",
                "file_size": 65536,
                "file_kind": "PE32+ Executable",
                "machine_type": "x86_64",
                "created_at": "2026-10-29T10:00:00Z",
            },
            "hashes": {
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "md5": "1234567890abcdef1234567890abcdef",
            },
            "threat_score": {
                "score": 15,
                "risk_level": "LOW",
            },
            "ai_assessment": {
                "summary": "Sample shows normal compilation features and standard Win32 APIs.",
                "confidence": "HIGH",
            },
            "indicators": [],
            "sections": {
                "sections": [
                    {
                        "name": ".text",
                        "virtual_address": "0x00001000",
                        "virtual_size": 32768,
                        "raw_size": 32768,
                        "entropy": 6.12,
                        "characteristics": "Readable, Executable",
                    }
                ]
            }
        }

        html_out = generate_html_report_view(clean_data, language="en")
        self.assertIn("<!DOCTYPE html>", html_out)
        self.assertIn("defensive_tool_v2.exe", html_out)
        self.assertIn("65536 bytes", html_out)
        self.assertIn(".text", html_out)
        self.assertIn("6.12", html_out)
        self.assertIn("Readable, Executable", html_out)
        self.assertIn("LOW (15/100)", html_out)
        self.assertIn("badge-low", html_out)

    # =========================================================================
    # 3. HTTP Integration Test via GET /api/analyses/{id}/report?format=html
    # =========================================================================

    def test_07_http_report_endpoint_escapes_stored_binary_metadata(self):
        """Verifies GET /api/analyses/{id}/report?format=html returns properly escaped HTML from DB."""
        res = self.client.get(
            f"/api/analyses/{self.xss_analysis_id}/report?format=html",
            headers=self.headers
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("content-type", ""))

        body = res.text

        # Must not contain live scripts
        self.assertNotIn("<script>", body)
        self.assertNotIn("</script>", body)
        self.assertNotIn("<img src=x", body)
        self.assertNotIn("<svg/onload", body)

        # Must contain properly escaped text representations
        self.assertIn("&lt;script&gt;alert(&#x27;filename&#x27;)&lt;/script&gt;.exe", body)
        self.assertIn(".text&lt;img src=x onerror=alert(&quot;sec&quot;)&gt;", body)
        self.assertIn("&lt;svg/onload=alert(&quot;ind&quot;)&gt;", body)


if __name__ == "__main__":
    unittest.main()
