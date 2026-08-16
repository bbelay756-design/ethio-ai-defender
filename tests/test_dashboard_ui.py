"""
Unit tests for Module 15: Defensive Security Dashboard.

Tests:
1. Dashboard root HTML route serving.
2. Structure verification for all 8 dedicated dashboard views in frontend/index.html.
3. Language toggle and navigation buttons.
4. Dashboard REST API (/api/dashboard/samples, /api/dashboard/analyze, /api/dashboard/samples/{id}/full).
5. End-to-end multi-module analysis pipeline integration.
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import BASE_DIR
from app.db.session import init_db


class TestDefensiveSecurityDashboard(unittest.TestCase):
    """Unit test suite for Defensive Security Dashboard UI and API."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def test_root_serves_html_dashboard(self):
        """Verify GET / returns HTML dashboard when requested by a browser."""
        response = self.client.get("/", headers={"accept": "text/html"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("ETHIO-AI Defender", response.text)

    def test_all_8_views_present_in_html(self):
        """Verify frontend/index.html contains all 8 required view containers."""
        index_file = BASE_DIR / "frontend" / "index.html"
        self.assertTrue(index_file.exists(), "frontend/index.html must exist.")
        content = index_file.read_text(encoding="utf-8")

        required_view_ids = [
            "view-home",
            "view-analysis",
            "view-pe-analysis",
            "view-imports",
            "view-strings",
            "view-indicators",
            "view-ai-analyst",
            "view-learning"
        ]

        for view_id in required_view_ids:
            self.assertIn(f'id="{view_id}"', content, f"Missing view container: {view_id}")

    def test_navigation_tabs_present_in_html(self):
        """Verify navigation links exist for all 8 views."""
        content = (BASE_DIR / "frontend" / "index.html").read_text(encoding="utf-8")
        required_nav_tabs = [
            'data-tab="home"',
            'data-tab="analysis"',
            'data-tab="pe-analysis"',
            'data-tab="imports"',
            'data-tab="strings"',
            'data-tab="indicators"',
            'data-tab="ai-analyst"',
            'data-tab="learning"'
        ]
        for nav_tab in required_nav_tabs:
            self.assertIn(nav_tab, content, f"Missing navigation tab: {nav_tab}")

    def test_language_selectors_present(self):
        """Verify language toggle buttons exist in the HTML."""
        content = (BASE_DIR / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="lang-btn-en"', content)
        self.assertIn('id="lang-btn-am"', content)

    def test_dashboard_api_analyze_and_full_pipeline(self):
        """Verify POST /api/dashboard/analyze processes a valid PE file through all modules."""
        # Minimal valid synthetic PE binary
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder='little')
        pe_sig = b'PE\x00\x00'
        coff_header = b'\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01'
        synthetic_pe = bytes(dos_header) + pe_sig + coff_header + (b'\x00' * 512)

        files = {"file": ("test_dashboard_sample.exe", synthetic_pe, "application/octet-stream")}
        response = self.client.post("/api/dashboard/analyze?language=en", files=files)

        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("analysis_id", data)
        self.assertIn("file_information", data)
        self.assertIn("hashes", data)
        self.assertIn("pe_information", data)
        self.assertIn("sections", data)
        self.assertIn("entropy", data)
        self.assertIn("strings", data)
        self.assertIn("imports", data)
        self.assertIn("indicators", data)
        self.assertIn("threat_score", data)
        self.assertIn("ethiopian_context", data)
        self.assertIn("ai_assessment", data)
        self.assertIn("learning_mode", data)
        self.assertIn("report", data)

    def test_dashboard_api_list_samples(self):
        """Verify GET /api/dashboard/samples lists analyzed samples."""
        response = self.client.get("/api/dashboard/samples")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)


if __name__ == "__main__":
    unittest.main()
