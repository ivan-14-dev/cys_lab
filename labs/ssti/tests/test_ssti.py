"""SSTI Lab Tests."""
from __future__ import annotations

import importlib.util
import json
import os

import pytest


def _load(path: str):
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


class TestVulnerableSSTI:
    def test_normal_name_works(self, vuln_client):
        r = vuln_client.get("/api/greet?name=Alice")
        data = json.loads(r.data)
        assert data["output"] == "Hello Alice!"

    def test_math_expression_evaluated(self, vuln_client):
        """VULNERABLE: {{7*7}} is evaluated to 49 by the template engine."""
        r = vuln_client.get("/api/greet?name={{7*7}}")
        data = json.loads(r.data)
        assert data["output"] == "Hello 49!", \
            f"Expected 'Hello 49!' but got '{data['output']}' — template engine should evaluate"

    def test_string_multiplication_evaluated(self, vuln_client):
        """VULNERABLE: string * int is evaluated."""
        r = vuln_client.get('/api/greet?name={{"x"*5}}')
        data = json.loads(r.data)
        assert "xxxxx" in data.get("output", "")


class TestSecureSSTI:
    def test_normal_name_works(self, secure_client):
        r = secure_client.get("/api/greet?name=Alice")
        data = json.loads(r.data)
        assert data["output"] == "Hello Alice!"

    def test_math_expression_not_evaluated(self, secure_client):
        """SECURE: {{7*7}} is treated as literal text, not evaluated."""
        r = secure_client.get("/api/greet?name={{7*7}}")
        # Should be blocked by input validation (invalid chars) or returned as literal
        if r.status_code == 400:
            data = json.loads(r.data)
            assert data.get("blocked") is True
        else:
            data = json.loads(r.data)
            # If accepted, output must not evaluate the expression
            assert "49" not in data.get("output", ""), \
                "Secure: template expression must NOT be evaluated"

    def test_invalid_chars_rejected(self, secure_client):
        """SECURE: names with {{ are rejected by validation."""
        r = secure_client.get("/api/greet?name={{config}}")
        assert r.status_code == 400

    def test_world_default(self, secure_client):
        r = secure_client.get("/api/greet")
        data = json.loads(r.data)
        assert data["output"] == "Hello World!"
