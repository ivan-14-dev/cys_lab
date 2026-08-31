"""
Command Injection Lab Tests
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest


def _load_app(path: str):
    spec = importlib.util.spec_from_file_location("app_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod


@pytest.fixture()
def vuln_client():
    path = os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    mod = _load_app(path)
    with mod.app.test_client() as c:
        yield c


@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    mod = _load_app(path)
    with mod.app.test_client() as c:
        yield c


class TestVulnerableCommandInjection:
    def test_homepage_loads(self, vuln_client):
        r = vuln_client.get("/")
        assert r.status_code == 200
        assert b"VULN" in r.data or b"Command" in r.data

    def test_api_accepts_injection_target(self, vuln_client):
        """VULNERABLE: injection payload is passed to shell without validation."""
        r = vuln_client.post(
            "/api/ping",
            data=json.dumps({"target": "127.0.0.1; echo INJECTION_DETECTED"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = json.loads(r.data)
        # The command was constructed with the injection payload
        assert "INJECTION_DETECTED" in data.get("command", "") or \
               "INJECTION_DETECTED" in data.get("output", ""), \
               "Vulnerable app should pass injection to shell"

    def test_no_validation_on_target(self, vuln_client):
        """VULNERABLE: arbitrary strings are accepted as target."""
        r = vuln_client.post(
            "/api/ping",
            data=json.dumps({"target": "127.0.0.1"}),
            content_type="application/json",
        )
        assert r.status_code == 200


class TestSecureCommandInjection:
    def test_homepage_loads(self, secure_client):
        r = secure_client.get("/")
        assert r.status_code == 200
        assert b"CUR" in r.data or b"Command" in r.data

    def test_injection_payload_rejected(self, secure_client):
        """SECURE: injection payload is rejected by allowlist."""
        r = secure_client.post(
            "/api/ping",
            data=json.dumps({"target": "127.0.0.1; echo INJECTION_DETECTED"}),
            content_type="application/json",
        )
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_valid_target_accepted(self, secure_client):
        """SECURE: valid allowlisted target works."""
        r = secure_client.post(
            "/api/ping",
            data=json.dumps({"target": "127.0.0.1"}),
            content_type="application/json",
        )
        # May succeed or fail based on ping availability, but should not be blocked
        data = json.loads(r.data)
        assert data.get("blocked") is not True

    def test_external_ip_rejected(self, secure_client):
        """SECURE: external IPs are not in allowlist."""
        r = secure_client.post(
            "/api/ping",
            data=json.dumps({"target": "8.8.8.8"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_empty_target_rejected(self, secure_client):
        r = secure_client.post(
            "/api/ping",
            data=json.dumps({"target": ""}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_special_chars_rejected(self, secure_client):
        """SECURE: shell metacharacters in target are rejected."""
        for payload in ["127.0.0.1 && id", "$(id)", "`id`", "127.0.0.1|cat /etc/passwd"]:
            r = secure_client.post(
                "/api/ping",
                data=json.dumps({"target": payload}),
                content_type="application/json",
            )
            assert r.status_code == 400, f"Should reject: {payload}"
