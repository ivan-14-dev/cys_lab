"""
XSS Lab Tests — validates both vulnerable and secure behavior.
Run: python -m pytest tests/ -v
"""
from __future__ import annotations

import sys
import os
import json

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "secure", "src"))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def vuln_client():
    import importlib
    spec = importlib.util.spec_from_file_location(
        "vuln_app",
        os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    mod._comments.clear()
    with mod.app.test_client() as c:
        yield c
    mod._comments.clear()


@pytest.fixture()
def secure_client():
    import importlib
    spec = importlib.util.spec_from_file_location(
        "secure_app",
        os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    mod._comments.clear()
    with mod.app.test_client() as c:
        yield c
    mod._comments.clear()


# ─── Vulnerable Tests ─────────────────────────────────────────────────────────

class TestVulnerableXSS:
    XSS_PAYLOAD = "<script>alert('xss')</script>"
    IMG_PAYLOAD = '<img src=x onerror="document.title=\'XSS_PROOF\'">'

    def test_homepage_loads(self, vuln_client):
        r = vuln_client.get("/")
        assert r.status_code == 200

    def test_script_tag_stored_unescaped(self, vuln_client):
        """VULNERABLE: <script> tag is stored and returned as raw HTML via API."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Attacker", "comment": self.XSS_PAYLOAD}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/last")
        data = json.loads(r.data)
        assert "<script>" in data["comment"], "Vulnerable app must store raw HTML payload"

    def test_raw_html_stored_in_api(self, vuln_client):
        """VULNERABLE: HTML payload appears unescaped in API response."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Tester", "comment": self.IMG_PAYLOAD}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/comments")
        body = r.data.decode()
        assert 'onerror=' in body, "Vulnerable: raw event handler in API response"

    def test_bold_html_rendered_raw(self, vuln_client):
        """VULNERABLE: <b> tag stored without encoding."""
        payload = "<b>INJECTION_DETECTED</b>"
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Test", "comment": payload}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/last")
        data = json.loads(r.data)
        assert "<b>INJECTION_DETECTED</b>" == data["comment"]

    def test_normal_comment_works(self, vuln_client):
        """Normal input is stored and returned."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Alice", "comment": "Hello world!"}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/comments")
        body = r.data.decode()
        assert "Hello world!" in body


# ─── Secure Tests ─────────────────────────────────────────────────────────────

class TestSecureXSS:
    XSS_PAYLOAD = "<script>alert('xss')</script>"
    IMG_PAYLOAD = '<img src=x onerror="document.title=\'XSS_PROOF\'">'

    def test_homepage_loads(self, secure_client):
        r = secure_client.get("/")
        assert r.status_code == 200

    def test_csp_header_present(self, secure_client):
        """SECURE: Content-Security-Policy header is set."""
        r = secure_client.get("/")
        csp = r.headers.get("Content-Security-Policy", "")
        assert "script-src" in csp
        assert "'none'" in csp

    def test_script_tag_rejected_by_validation(self, secure_client):
        """SECURE: <script> in name is rejected by input validation."""
        r = secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "<script>", "comment": "test"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_valid_comment_accepted(self, secure_client):
        """SECURE: normal comment is accepted."""
        r = secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "Alice", "comment": "Great lab!"}),
            content_type="application/json",
        )
        assert r.status_code == 200

    def test_normal_comment_returned(self, secure_client):
        """SECURE: valid comments are stored and retrievable."""
        secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "Bob", "comment": "Great lab!"}),
            content_type="application/json",
        )
        r = secure_client.get("/api/comments")
        assert b"Great lab!" in r.data

    def test_x_content_type_options(self, secure_client):
        r = secure_client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, secure_client):
        r = secure_client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_invalid_name_rejected(self, secure_client):
        r = secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "x" * 200, "comment": "test"}),
            content_type="application/json",
        )
        assert r.status_code == 400
