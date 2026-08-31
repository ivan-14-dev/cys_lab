"""LDAP Injection Lab Tests."""
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


class TestVulnerableLDAP:
    def test_valid_search(self, vuln_client):
        r = vuln_client.get("/api/search?username=alice")
        data = json.loads(r.data)
        assert data["count"] == 1
        assert "alice" in data["users"]

    def test_wildcard_returns_all(self, vuln_client):
        """VULNERABLE: * returns all users."""
        r = vuln_client.get("/api/search?username=*")
        data = json.loads(r.data)
        assert data["count"] == len(data["users"]) >= 1
        assert "filter" in data
        assert "(uid=*)" == data["filter"]

    def test_injection_returns_all(self, vuln_client):
        """VULNERABLE: injection payload causes filter bypass."""
        r = vuln_client.get("/api/search?username=*)(uid=*))(|(uid=*")
        data = json.loads(r.data)
        # Injection causes all users to be returned
        assert data["count"] > 1


class TestSecureLDAP:
    def test_valid_search(self, secure_client):
        r = secure_client.get("/api/search?username=alice")
        data = json.loads(r.data)
        assert data["count"] == 1
        assert "alice" in data["users"]

    def test_wildcard_rejected(self, secure_client):
        """SECURE: * is rejected by allowlist validation."""
        r = secure_client.get("/api/search?username=*")
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_injection_payload_rejected(self, secure_client):
        """SECURE: injection chars are rejected."""
        r = secure_client.get("/api/search?username=*)(uid=*))(|(uid=*")
        assert r.status_code == 400

    def test_special_chars_rejected(self, secure_client):
        for payload in ["(uid=*)", "alice)(", "test*"]:
            r = secure_client.get(f"/api/search?username={payload}")
            assert r.status_code == 400, f"Should reject: {payload}"

    def test_unknown_user_returns_empty(self, secure_client):
        r = secure_client.get("/api/search?username=charlie")
        data = json.loads(r.data)
        assert data["count"] == 0
