"""
NoSQL Injection Lab — Secure Version
<i class="fa-solid fa-circle-check"></i> SECURE IMPLEMENTATION

Defenses applied:
- Pydantic schema validation (enforces string types)
- Explicit type checking (rejects operator objects)
- Allowlist for expected fields only
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request
from pydantic import BaseModel, field_validator, ValidationError

app = Flask(__name__)
app.secret_key = "lab-nosql-secure-key"

_USERS_DB = [
    {"username": "alice", "password": "lab_alice_pass", "role": "user"},
    {"username": "bob", "password": "lab_bob_pass", "role": "user"},
    {"username": "admin", "password": "lab_admin_pass", "role": "admin"},
]

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>NoSQL Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.result {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; margin: 16px 0; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-circle-check"></i> NOSQL INJECTION LAB — SECURE — Schema Validation Applied</div>
<h1>Authentication Portal</h1>
<div class="defense-box">
<strong><i class="fa-solid fa-shield-halved"></i> Defenses active:</strong> Pydantic schema | String type enforcement | Operator rejection
<br><small>Try sending <code>{{"password": {{"$ne": null}}}}</code> — it will be rejected as wrong type.</small>
</div>
<p>Use the API: <code>POST /api/login</code> with JSON body.</p>
<div class="result">{result}</div>
</body></html>"""


class LoginRequest(BaseModel):
    """Validates that credentials are plain strings — rejects operator objects."""
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def no_operators(cls, v: str) -> str:
        # Extra check: reject MongoDB operator prefixes
        if v.startswith("$"):
            raise ValueError("Operator prefixes are not allowed.")
        if len(v) > 128:
            raise ValueError("Value too long.")
        return v


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(result="Send a POST to /api/login with JSON credentials.")


@app.route("/api/login", methods=["POST"])
def api_login() -> Any:
    """SECURE: Pydantic validates types before any query."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    try:
        creds = LoginRequest.model_validate(body)
    except ValidationError as e:
        return jsonify({
            "error": "Invalid input",
            "details": str(e),
            "blocked": True,
        }), 400

    # Only reach here if both fields are validated plain strings
    user = next(
        (u for u in _USERS_DB
         if u["username"] == creds.username and u["password"] == creds.password),
        None,
    )
    if user:
        return jsonify({
            "status": "authenticated",
            "username": user["username"],
            "role": user["role"],
        })
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
