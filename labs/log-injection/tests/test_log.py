"""Log Injection Lab Tests."""
from __future__ import annotations
import importlib.util, json, os
import pytest

def _load(path):
    spec = importlib.util.spec_from_file_location("mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    mod._log_records.clear()
    return mod

@pytest.fixture()
def vuln_client():
    path = os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    mod = _load(path)
    with mod.app.test_client() as c:
        yield c, mod

@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    mod = _load(path)
    with mod.app.test_client() as c:
        yield c, mod


class TestVulnerableLog:
    def test_normal_login_logged(self, vuln_client):
        client, mod = vuln_client
        client.post(
            "/api/login",
            data=json.dumps({"username": "alice"}),
            content_type="application/json",
        )
        r = client.get("/api/logs")
        logs = json.loads(r.data)["logs"]
        assert any("alice" in entry for entry in logs)

    def test_newline_injection_creates_fake_entry(self, vuln_client):
        """VULNERABLE: \\n in username creates a fake log line."""
        client, mod = vuln_client
        payload = "alice\nINFO 2024-01-01 00:00:00,000 [INFO] Login SUCCESS for user: root"
        client.post(
            "/api/login",
            data=json.dumps({"username": payload}),
            content_type="application/json",
        )
        r = client.get("/api/logs")
        logs = json.loads(r.data)["logs"]
        # The injected line appears in the log
        full_log = " ".join(logs)
        assert "root" in full_log or any("root" in l for l in logs), \
            "Vulnerable: fake log entry should appear"


class TestSecureLog:
    def test_normal_login_logged(self, secure_client):
        client, mod = secure_client
        r = client.post(
            "/api/login",
            data=json.dumps({"username": "alice"}),
            content_type="application/json",
        )
        assert r.status_code == 200

    def test_newline_injection_rejected(self, secure_client):
        """SECURE: username with \\n is rejected by validation."""
        client, mod = secure_client
        payload = "alice\nfake_entry"
        r = client.post(
            "/api/login",
            data=json.dumps({"username": payload}),
            content_type="application/json",
        )
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_special_chars_rejected(self, secure_client):
        client, mod = secure_client
        for payload in ["test\nINJECTED", "user\rFAKE", "admin\x00null"]:
            r = client.post(
                "/api/login",
                data=json.dumps({"username": payload}),
                content_type="application/json",
            )
            assert r.status_code == 400
