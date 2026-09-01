"""Path Traversal Lab Tests"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile

import pytest


def _load_app(path: str):
    spec = importlib.util.spec_from_file_location("app_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod


@pytest.fixture()
def vuln_client(tmp_path):
    path = os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    mod = _load_app(path)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    (files_dir / "test.txt").write_text("test content")
    mod._FILES_DIR = str(files_dir)
    with mod.app.test_client() as c:
        yield c


@pytest.fixture()
def secure_client(tmp_path):
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    mod = _load_app(path)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    (files_dir / "test.txt").write_text("test content")
    mod._FILES_DIR = str(files_dir)
    with mod.app.test_client() as c:
        yield c


class TestVulnerablePathTraversal:
    def test_homepage_loads(self, vuln_client):
        r = vuln_client.get("/")
        assert r.status_code == 200

    def test_read_requires_file_param(self, vuln_client):
        r = vuln_client.get("/api/read")
        assert r.status_code == 400

    def test_read_normal_file(self, vuln_client):
        r = vuln_client.get("/api/read?file=test.txt")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["content"] == "test content"

    def test_traversal_accepted(self, vuln_client):
        """VULNERABLE: ../../../etc/passwd is not blocked."""
        r = vuln_client.get("/api/read?file=../../../etc/passwd")
        # May succeed or fail depending on filesystem, but not blocked
        assert r.status_code != 403

    def test_nonexistent_file_404(self, vuln_client):
        r = vuln_client.get("/api/read?file=nope.txt")
        assert r.status_code == 404


class TestSecurePathTraversal:
    def test_homepage_loads(self, secure_client):
        r = secure_client.get("/")
        assert r.status_code == 200

    def test_read_normal_file(self, secure_client):
        r = secure_client.get("/api/read?file=test.txt")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["content"] == "test content"
        assert data["blocked"] is False

    def test_traversal_blocked(self, secure_client):
        r = secure_client.get("/api/read?file=../../../etc/passwd")
        data = json.loads(r.data)
        # basename strips ../ so it becomes "passwd" which won't exist
        assert r.status_code in (403, 404)

    def test_absolute_path_blocked(self, secure_client):
        r = secure_client.get("/api/read?file=/etc/passwd")
        data = json.loads(r.data)
        assert r.status_code in (403, 404)
