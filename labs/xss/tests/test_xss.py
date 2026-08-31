"""
XSS Lab Tests — validates both vulnerable and secure behavior.
Run: python -m pytest tests/ -v
"""
from __future__ import annotations

import sys
import os
import json

import pytest

# Allow importing from sibling directories
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "secure", "src"))


# ─── Vulnerable App Tests ─────────────────────────────────────────────────────

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
        """Sanity check: the app starts."""
        r = vuln_client.get("/")
        assert r.status_code == 200

    def test_script_tag_stored_unescaped(self, vuln_client):
        """VULNERABLE: <script> tag is stored and returned as raw HTML."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Attacker", "comment": self.XSS_PAYLOAD}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/last")
        data = json.loads(r.data)
        # The raw payload is stored without modification
        assert "<script>" in data["comment"], "Vulnerable app must store raw HTML payload"

    def test_raw_html_in_page_response(self, vuln_client):
        """VULNERABLE: HTML payload appears unescaped in the page body."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Tester", "comment": self.IMG_PAYLOAD}),
            content_type="application/json",
        )
        r = vuln_client.get("/")
        body = r.data.decode()
        assert 'onerror=' in body, "Vulnerable: raw event handler in HTML output"
        assert "&lt;" not in body.split("comment-body")[1][:200], \
            "Vulnerable: should NOT encode < in comment output"

    def test_bold_html_rendered_raw(self, vuln_client):
        """VULNERABLE: <b> tag rendered as HTML, not escaped text."""
        payload = "<b>INJECTION_DETECTED</b>"
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Test", "comment": payload}),
            content_type="application/json",
        )
        r = vuln_client.get("/")
        body = r.data.decode()
        assert "<b>INJECTION_DETECTED</b>" in body

    def test_normal_comment_works(self, vuln_client):
        """Normal input is stored and displayed."""
        vuln_client.post(
            "/api/comment",
            data=json.dumps({"name": "Alice", "comment": "Hello world!"}),
            content_type="application/json",
        )
        r = vuln_client.get("/")
        assert b"Hello world!" in r.data


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

    def test_script_tag_is_html_encoded(self, secure_client):
        """SECURE: <script> is encoded as &lt;script&gt; in output."""
        secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "Alice", "comment": self.XSS_PAYLOAD}),
            content_type="application/json",
        )
        r = secure_client.get("/")
        body = r.data.decode()
        assert "&lt;script&gt;" in body, "Secure: < must be HTML-encoded"
        assert "<script>" not in body, "Secure: raw <script> must not appear"

    def test_event_handler_encoded(self, secure_client):
        """SECURE: onerror= attribute is HTML-encoded via Jinja2 auto-escaping."""
        secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "Alice", "comment": self.IMG_PAYLOAD}),
            content_type="application/json",
        )
        r = secure_client.get("/")
        body = r.data.decode()
        # Jinja2 auto-escaping converts < and " — the raw onerror= attribute cannot execute
        # Check that the opening < of <img is encoded
        assert "&lt;img" in body or "onerror" not in body, \
            "Secure: <img tag must be HTML-encoded, preventing onerror execution"

    def test_normal_comment_works(self, secure_client):
        """Normal input displayed correctly."""
        secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "Bob", "comment": "Great lab!"}),
            content_type="application/json",
        )
        r = secure_client.get("/")
        assert b"Great lab!" in r.data

    def test_invalid_name_rejected(self, secure_client):
        """SECURE: input validation rejects invalid names."""
        r = secure_client.post(
            "/api/comment",
            data=json.dumps({"name": "<script>", "comment": "test"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_x_content_type_options(self, secure_client):
        """SECURE: X-Content-Type-Options header prevents MIME sniffing."""
        r = secure_client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, secure_client):
        """SECURE: X-Frame-Options header prevents clickjacking."""
        r = secure_client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"
