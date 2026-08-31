"""
NoSQL Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: MongoDB operator injection via unvalidated JSON body
CWE-943, OWASP A03:2021
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-nosql-vuln-key"

# In-memory user store (simulates MongoDB behavior for unit tests)
_USERS_DB = [
    {"username": "alice", "password": "lab_alice_pass", "role": "user"},
    {"username": "bob", "password": "lab_bob_pass", "role": "user"},
    {"username": "admin", "password": "lab_admin_pass", "role": "admin"},
]

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>NoSQL Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.result {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; margin: 16px 0; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 300px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> NOSQL INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Authentication Portal</h1>
<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Bypass authentication without knowing the password.
<br>Hint: Send JSON with <code>{{"username": "admin", "password": {{"$ne": null}}}}</code>
<br><strong>Objective:</strong> Log in as admin using a MongoDB operator.
</div>
<p>Use the API: <code>POST /api/login</code> with JSON body.</p>
<p>Normal users: alice, bob, admin</p>
<div class="result" id="result">{result}</div>
<a href="/demo">View demo payloads</a>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>NoSQL Demo</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
</style></head><body>
<h1>NoSQL Injection Demo Payloads</h1>
<h2>Normal Login (use curl)</h2>
<code>curl -X POST http://localhost:5007/api/login \\
  -H "Content-Type: application/json" \\
  -d '{{"username":"alice","password":"lab_alice_pass"}}'</code>
<h2>Injection — $ne operator (password bypass)</h2>
<code>curl -X POST http://localhost:5007/api/login \\
  -H "Content-Type: application/json" \\
  -d '{{"username":"admin","password":{{"$ne":null}}}}'</code>
<p>The <code>$ne: null</code> operator matches any non-null value → bypasses password check.</p>
<h2>Injection — $gt operator</h2>
<code>curl -X POST http://localhost:5007/api/login \\
  -H "Content-Type: application/json" \\
  -d '{{"username":"admin","password":{{"$gt":""}}}}'</code>
<a href="/">Back</a>
</body></html>"""


def _find_user_vulnerable(username: Any, password: Any) -> dict | None:
    """VULNERABLE: accepts operator objects as filter values."""
    # Simulate MongoDB-style query evaluation
    for user in _USERS_DB:
        # Username check
        if user["username"] != username:
            continue
        # VULNERABILITY: password can be a MongoDB operator object
        if isinstance(password, dict):
            # Simulate $ne, $gt operators — this is what MongoDB does with untrusted objects
            if "$ne" in password:
                if user["password"] != password["$ne"]:
                    return user
            elif "$gt" in password:
                if user["password"] > password["$gt"]:
                    return user
            elif "$regex" in password:
                import re
                if re.match(password["$regex"], user["password"]):
                    return user
        elif user["password"] == password:
            return user
    return None


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(result="Send a POST to /api/login with JSON credentials.")


@app.route("/api/login", methods=["POST"])
def api_login() -> Any:
    """VULNERABLE: JSON body used directly as query filter."""
    body = request.get_json(force=True, silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    # VULNERABILITY: no type validation — operator objects accepted
    username = body.get("username")
    password = body.get("password")

    user = _find_user_vulnerable(username, password)
    if user:
        return jsonify({
            "status": "authenticated",
            "username": user["username"],
            "role": user["role"],
            "message": f"Welcome {user['username']}! Role: {user['role']}",
        })
    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401


@app.route("/demo")
def demo() -> Any:
    return _DEMO


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
