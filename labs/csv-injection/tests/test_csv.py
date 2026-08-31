"""CSV Injection Lab Tests."""
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
    mod = _load(path)
    mod._ENTRIES.clear()
    with mod.app.test_client() as c:
        yield c

@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    mod = _load(path)
    mod._ENTRIES.clear()
    with mod.app.test_client() as c:
        yield c


class TestVulnerableCSV:
    def test_formula_in_csv_unescaped(self, vuln_client):
        """VULNERABLE: formula cell written as-is to CSV."""
        vuln_client.post(
            "/api/add",
            data=json.dumps({"name": "=SUM(1+1)", "email": "test@lab.local", "company": "Test"}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/csv")
        csv_content = json.loads(r.data)["csv"]
        assert "=SUM(1+1)" in csv_content, "Vulnerable: formula must appear unescaped"

    def test_plus_formula_unescaped(self, vuln_client):
        vuln_client.post(
            "/api/add",
            data=json.dumps({"name": "+INJECTION", "email": "x@lab.local", "company": "T"}),
            content_type="application/json",
        )
        r = vuln_client.get("/api/csv")
        csv_content = json.loads(r.data)["csv"]
        assert "+INJECTION" in csv_content


class TestSecureCSV:
    def test_formula_neutralized(self, secure_client):
        """SECURE: formula cells are prefixed to neutralize them."""
        secure_client.post(
            "/api/add",
            data=json.dumps({"name": "=SUM(1+1)", "email": "test@lab.local", "company": "Test"}),
            content_type="application/json",
        )
        r = secure_client.get("/api/csv")
        csv_content = json.loads(r.data)["csv"]
        # The formula should be prefixed (tab or quote) — not raw =
        assert "=SUM(1+1)" not in csv_content or csv_content.count("=SUM") == 0 or \
               "\t=SUM(1+1)" in csv_content, "Secure: formula must be neutralized"

    def test_normal_entry_preserved(self, secure_client):
        secure_client.post(
            "/api/add",
            data=json.dumps({"name": "Alice", "email": "alice@lab.local", "company": "LabCorp"}),
            content_type="application/json",
        )
        r = secure_client.get("/api/csv")
        csv_content = json.loads(r.data)["csv"]
        assert "Alice" in csv_content

    def test_at_sign_formula_neutralized(self, secure_client):
        """SECURE: @formula neutralized."""
        secure_client.post(
            "/api/add",
            data=json.dumps({"name": "@SUM(A1:A10)", "email": "x@lab.local", "company": "T"}),
            content_type="application/json",
        )
        r = secure_client.get("/api/csv")
        csv_content = json.loads(r.data)["csv"]
        assert "@SUM" not in csv_content or "\t@SUM" in csv_content
