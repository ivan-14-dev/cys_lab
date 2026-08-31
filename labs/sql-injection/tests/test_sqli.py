"""SQL Injection Lab Tests | CWE-89 | OWASP A03:2021"""
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


def login(client, username, password):
    return client.post(
        "/api/login",
        data=json.dumps({"username": username, "password": password}),
        content_type="application/json",
    )


class TestVulnerableSQLi:
    def test_valid_login(self, vuln_client):
        r = login(vuln_client, "alice", "lab_alice_pass")
        assert r.status_code == 200
        assert json.loads(r.data)["status"] == "authenticated"

    def test_wrong_password_fails(self, vuln_client):
        r = login(vuln_client, "alice", "wrong")
        assert r.status_code == 401

    def test_tautology_bypass(self, vuln_client):
        """VULNERABLE: ' OR '1'='1 bypasses password check."""
        r = login(vuln_client, "admin", "' OR '1'='1")
        assert r.status_code == 200, "Vulnerable: tautology should bypass auth"
        data = json.loads(r.data)
        assert data["status"] == "authenticated"

    def test_comment_bypass(self, vuln_client):
        """VULNERABLE: admin'-- skips the password clause."""
        r = login(vuln_client, "admin'--", "anything")
        assert r.status_code == 200, "Vulnerable: comment injection should bypass"

    def test_union_injection(self, vuln_client):
        """VULNERABLE: UNION SELECT injects an arbitrary row."""
        r = login(vuln_client, "' UNION SELECT 1,'injected','data','admin'--", "x")
        assert r.status_code == 200, "Vulnerable: UNION injection should return a row"
        data = json.loads(r.data)
        assert data["username"] == "injected"


class TestSecureSQLi:
    def test_valid_login(self, secure_client):
        r = login(secure_client, "alice", "lab_alice_pass")
        assert r.status_code == 200
        assert json.loads(r.data)["status"] == "authenticated"

    def test_wrong_password_fails(self, secure_client):
        r = login(secure_client, "alice", "wrong")
        assert r.status_code == 401

    def test_tautology_rejected(self, secure_client):
        """SECURE: ' OR '1'='1 is treated as a literal string."""
        r = login(secure_client, "admin", "' OR '1'='1")
        assert r.status_code == 401, "Secure: tautology must be rejected"

    def test_comment_injection_rejected(self, secure_client):
        """SECURE: admin'-- is compared literally, not as SQL."""
        r = login(secure_client, "admin'--", "anything")
        assert r.status_code == 401, "Secure: comment injection must be rejected"

    def test_union_injection_rejected(self, secure_client):
        """SECURE: UNION SELECT is treated as a literal value."""
        r = login(secure_client, "' UNION SELECT 1,'injected','data','admin'--", "x")
        assert r.status_code == 401, "Secure: UNION injection must be rejected"

    def test_admin_valid_credentials(self, secure_client):
        """SECURE: real credentials still work after protection."""
        r = login(secure_client, "admin", "lab_admin_pass")
        assert r.status_code == 200
        assert json.loads(r.data)["role"] == "admin"
