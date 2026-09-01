"""IDOR Lab Tests"""
from __future__ import annotations

import importlib.util
import json
import os

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


class TestVulnerableIDOR:
    def test_homepage_loads(self, vuln_client):
        r = vuln_client.get("/")
        assert r.status_code == 200

    def test_own_profile_accessible(self, vuln_client):
        r = vuln_client.get("/api/user/1")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["username"] == "alice"

    def test_other_user_accessible(self, vuln_client):
        """VULNERABLE: can access any user's data without authorization."""
        r = vuln_client.get("/api/user/2")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["username"] == "bob"

    def test_admin_profile_accessible(self, vuln_client):
        """VULNERABLE: admin data including flag is exposed."""
        r = vuln_client.get("/api/user/3")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["role"] == "admin"
        assert "FLAG{" in data["notes"]

    def test_nonexistent_user_404(self, vuln_client):
        r = vuln_client.get("/api/user/999")
        assert r.status_code == 404

    def test_user_list_available(self, vuln_client):
        r = vuln_client.get("/api/users")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data["users"]) == 3


class TestSecureIDOR:
    def test_homepage_loads(self, secure_client):
        r = secure_client.get("/")
        assert r.status_code == 200

    def test_own_profile_accessible(self, secure_client):
        r = secure_client.get("/api/user/1")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["username"] == "alice"

    def test_other_user_blocked(self, secure_client):
        r = secure_client.get("/api/user/2")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True

    def test_admin_profile_blocked(self, secure_client):
        r = secure_client.get("/api/user/3")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True
