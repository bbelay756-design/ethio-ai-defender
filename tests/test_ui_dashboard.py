"""
UI and Frontend Dashboard Route Tests for Module 02 and Module 15.
"""

import unittest
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient
from app.main import app


class TestUIDashboard(unittest.TestCase):
    """Verifies that the UI Dashboard, routes, and static assets are served properly."""

    def setUp(self):
        self.client = TestClient(app)

    def test_dashboard_endpoint_html(self):
        """Test that GET /dashboard serves the HTML document with proper page title and branding."""
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("ETHIO-AI Defender", response.text)
        self.assertIn("SHA-256", response.text)

    def test_root_browser_request_serves_html(self):
        """Test that browser requests with text/html receive the UI dashboard."""
        response = self.client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("ETHIO-AI Defender", response.text)

    def test_root_api_request_serves_json(self):
        """Test that API requests with application/json receive the health JSON payload."""
        response = self.client.get("/", headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.headers.get("content-type", ""))
        data = response.json()
        self.assertEqual(data.get("platform"), "ETHIO-AI Defender")
        self.assertEqual(data.get("status"), "OPERATIONAL")

    def test_static_css_served(self):
        """Test that CSS styling is accessible at /static/css/style.css."""
        response = self.client.get("/static/css/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/css", response.headers.get("content-type", ""))
        self.assertIn("--bg-app", response.text)

    def test_static_js_served(self):
        """Test that JavaScript logic is accessible at /static/js/app.js."""
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("javascript", response.headers.get("content-type", "").lower())
        self.assertIn("setLanguage", response.text)


if __name__ == "__main__":
    unittest.main()
