"""NoSQL Injection Lab Tests."""
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


class TestVulnerableNoSQL:
    def test_valid_login_works(self, vuln_client):
        r = vuln_client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "lab_alice_pass"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert json.loads(r.data)["status"] == "authenticated"

    def test_wrong_password_fails(self, vuln_client):
        r = vuln_client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "wrong"}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_ne_operator_bypasses_auth(self, vuln_client):
        """VULNERABLE: $ne operator bypasses password check."""
        r = vuln_client.post(
            "/api/login",
            data=json.dumps({"username": "admin", "password": {"$ne": None}}),
            content_type="application/json",
        )
        assert r.status_code == 200, "Vulnerable: $ne operator should bypass auth"
        data = json.loads(r.data)
        assert data["status"] == "authenticated"
        assert data["username"] == "admin"

    def test_gt_operator_bypasses_auth(self, vuln_client):
        """VULNERABLE: $gt operator bypasses password check."""
        r = vuln_client.post(
            "/api/login",
            data=json.dumps({"username": "bob", "password": {"$gt": ""}}),
            content_type="application/json",
        )
        assert r.status_code == 200


class TestSecureNoSQL:
    def test_valid_login_works(self, secure_client):
        r = secure_client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "lab_alice_pass"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert json.loads(r.data)["status"] == "authenticated"

    def test_wrong_password_fails(self, secure_client):
        r = secure_client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "wrong"}),
            content_type="application/json",
        )
        assert r.status_code == 401

    def test_ne_operator_rejected(self, secure_client):
        """SECURE: $ne operator is rejected by schema validation."""
        r = secure_client.post(
            "/api/login",
            data=json.dumps({"username": "admin", "password": {"$ne": None}}),
            content_type="application/json",
        )
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data.get("blocked") is True

    def test_gt_operator_rejected(self, secure_client):
        """SECURE: $gt operator is rejected."""
        r = secure_client.post(
            "/api/login",
            data=json.dumps({"username": "bob", "password": {"$gt": ""}}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_operator_prefix_rejected(self, secure_client):
        """SECURE: username/password starting with $ are rejected."""
        r = secure_client.post(
            "/api/login",
            data=json.dumps({"username": "$admin", "password": "test"}),
            content_type="application/json",
        )
        assert r.status_code == 400
