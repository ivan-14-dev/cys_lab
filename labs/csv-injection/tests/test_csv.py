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
    with _load(path).app.test_client() as c:
        yield c


@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    with _load(path).app.test_client() as c:
        yield c


def _export(client, entries):
    """Helper: POST entries to /api/export and return CSV text."""
    r = client.post(
        "/api/export",
        data=json.dumps({"entries": entries}),
        content_type="application/json",
    )
    return r.data.decode()


class TestVulnerableCSV:
    def test_formula_in_csv_unescaped(self, vuln_client):
        """VULNERABLE: formula cell written as-is to CSV."""
        csv_content = _export(vuln_client, [
            {"name": "=SUM(1+1)", "email": "test@lab.local", "company": "Test"}
        ])
        assert "=SUM(1+1)" in csv_content, "Vulnerable: formula must appear unescaped"

    def test_plus_formula_unescaped(self, vuln_client):
        csv_content = _export(vuln_client, [
            {"name": "+INJECTION", "email": "x@lab.local", "company": "T"}
        ])
        assert "+INJECTION" in csv_content


class TestSecureCSV:
    def test_formula_neutralized(self, secure_client):
        """SECURE: formula cells are prefixed to neutralize them."""
        csv_content = _export(secure_client, [
            {"name": "=SUM(1+1)", "email": "test@lab.local", "company": "Test"}
        ])
        # The formula should be prefixed with tab — not raw =
        assert "=SUM(1+1)" not in csv_content or "\t=SUM(1+1)" in csv_content, \
            "Secure: formula must be neutralized"

    def test_normal_entry_preserved(self, secure_client):
        csv_content = _export(secure_client, [
            {"name": "Alice", "email": "alice@lab.local", "company": "LabCorp"}
        ])
        assert "Alice" in csv_content

    def test_at_sign_formula_neutralized(self, secure_client):
        """SECURE: @formula neutralized."""

class TestSecureCSV:
    def test_formula_neutralized(self, secure_client):
        csv_content = _export(secure_client, [
            {"name": "=SUM(1+1)", "email": "test@lab.local", "company": "Test"}
        ])
        assert "=SUM(1+1)" not in csv_content or "\t=SUM(1+1)" in csv_content

    def test_normal_entry_preserved(self, secure_client):
        csv_content = _export(secure_client, [
            {"name": "Alice", "email": "alice@lab.local", "company": "LabCorp"}
        ])
        assert "Alice" in csv_content

    def test_at_sign_formula_neutralized(self, secure_client):
        csv_content = _export(secure_client, [
            {"name": "@SUM(A1:A10)", "email": "x@lab.local", "company": "T"}
        ])
        assert "@SUM" not in csv_content or "\t@SUM" in csv_content
