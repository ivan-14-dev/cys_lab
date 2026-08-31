"""XPath Injection Lab Tests."""
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


class TestVulnerableXPath:
    def test_normal_query(self, vuln_client):
        r = vuln_client.get("/api/lookup?username=alice")
        data = json.loads(r.data)
        assert data["count"] == 1

    def test_or_injection_returns_all(self, vuln_client):
        """VULNERABLE: ' or '1'='1 returns all users."""
        r = vuln_client.get("/api/lookup?username=' or '1'='1")
        data = json.loads(r.data)
        assert data["count"] > 1, "Vulnerable: injection should return all users"

    def test_always_true_injection(self, vuln_client):
        r = vuln_client.get("/api/lookup?username=alice' or '1'='1")
        data = json.loads(r.data)
        assert data["count"] >= 2


class TestSecureXPath:
    def test_normal_query(self, secure_client):
        r = secure_client.get("/api/lookup?username=alice")
        data = json.loads(r.data)
        assert data["count"] == 1

    def test_injection_rejected(self, secure_client):
        """SECURE: injection characters rejected by validation."""
        r = secure_client.get("/api/lookup?username=' or '1'='1")
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_unknown_user_returns_empty(self, secure_client):
        r = secure_client.get("/api/lookup?username=charlie")
        data = json.loads(r.data)
        assert data["count"] == 0

    def test_special_chars_rejected(self, secure_client):
        for p in ["' or '", "']//user[role='admin", "/*"]:
            r = secure_client.get(f"/api/lookup?username={p}")
            assert r.status_code == 400
