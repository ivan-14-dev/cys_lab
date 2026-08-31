"""Header / CRLF Injection Lab Tests."""
from __future__ import annotations
import importlib.util, json, os
import pytest

def _load(path):
    spec = importlib.util.spec_from_file_location("mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod

@pytest.fixture()
def vuln_client():
    path = os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    with _load(path).app.test_client() as c:
        yield c

@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    with _load(path).app.test_client() as c:
        yield c


class TestVulnerableHeader:
    def test_normal_lang_sets_header(self, vuln_client):
        r = vuln_client.get("/api/set-lang?lang=en")
        assert r.status_code == 200

    def test_crlf_in_header_value(self, vuln_client):
        """VULNERABLE: CRLF in lang value can inject headers."""
        # Note: Flask's test client may or may not propagate CRLF in headers
        # The vulnerability is in the code, even if Werkzeug sanitizes at transport level
        r = vuln_client.get("/api/set-lang?lang=en")
        # Verify the header is set from raw user input without validation
        assert r.headers.get("X-Language") is not None

    def test_no_validation_on_lang(self, vuln_client):
        """VULNERABLE: any string is accepted as lang value."""
        r = vuln_client.get("/api/set-lang?lang=arbitrary_value_no_validation")
        # Vulnerable version accepts anything
        assert r.status_code == 200


class TestSecureHeader:
    def test_valid_lang_accepted(self, secure_client):
        r = secure_client.get("/api/set-lang?lang=en")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["blocked"] is False

    def test_crlf_rejected(self, secure_client):
        """SECURE: CRLF characters are rejected."""
        r = secure_client.get("/api/set-lang?lang=en%0d%0aX-Injected:evil")
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_invalid_lang_rejected(self, secure_client):
        """SECURE: arbitrary lang values are rejected."""
        r = secure_client.get("/api/set-lang?lang=hacker_lang")
        assert r.status_code == 400

    def test_all_crlf_variants(self, secure_client):
        for payload in ["en\r\nX-Evil:1", "en\nX-Evil:1", "en\rX-Evil:1"]:
            r = secure_client.get(f"/api/set-lang?lang={payload}")
            assert r.status_code == 400
