"""SSRF Lab Tests"""
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


class TestVulnerableSSRF:
    def test_homepage_loads(self, vuln_client):
        r = vuln_client.get("/")
        assert r.status_code == 200

    def test_fetch_requires_url(self, vuln_client):
        r = vuln_client.get("/api/fetch")
        assert r.status_code == 400
        assert b"url" in r.data

    def test_internal_metadata_accessible(self, vuln_client):
        r = vuln_client.get("/internal/metadata")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["internal"] is True

    def test_internal_flag_accessible(self, vuln_client):
        r = vuln_client.get("/internal/flag")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "flag" in data
        assert data["flag"].startswith("FLAG{")


class TestSecureSSRF:
    def test_homepage_loads(self, secure_client):
        r = secure_client.get("/")
        assert r.status_code == 200

    def test_fetch_requires_url(self, secure_client):
        r = secure_client.get("/api/fetch")
        assert r.status_code == 400

    def test_private_domain_blocked(self, secure_client):
        r = secure_client.get("/api/fetch?url=http://localhost:5000/internal/flag")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True

    def test_private_ip_blocked(self, secure_client):
        r = secure_client.get("/api/fetch?url=http://127.0.0.1:5000/")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True

    def test_invalid_scheme_blocked(self, secure_client):
        r = secure_client.get("/api/fetch?url=file:///etc/passwd")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True

    def test_arbitrary_domain_blocked(self, secure_client):
        r = secure_client.get("/api/fetch?url=http://evil.com/steal")
        assert r.status_code == 403
        data = json.loads(r.data)
        assert data["blocked"] is True
