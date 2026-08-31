"""
LDAP Injection Lab — Secure Version
<i class="fa-solid fa-circle-check"></i> SECURE IMPLEMENTATION

Defenses applied:
- LDAP special character escaping
- Allowlist validation
- Input length limit
"""
from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-ldap-secure-key"

_LDAP_USERS = {
    "ivan": {"cn": "ivan", "sn": "Lab User", "mail": "ivan@lab.local", "role": "admin"},
    "alice": {"cn": "alice", "sn": "Alice Test", "mail": "alice@lab.local", "role": "user"},
    "bob": {"cn": "bob", "sn": "Bob Test", "mail": "bob@lab.local", "role": "user"},
}

# LDAP special characters that must be escaped
_LDAP_SPECIAL = re.compile(r'[\\*()\x00]')
_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>LDAP Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.result {{ background: #f8f9fa; border: 1px solid #ddd; padding: 16px; margin: 16px 0; border-radius: 4px; font-family: monospace; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 300px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-circle-check"></i> LDAP INJECTION LAB — SECURE — Filter Escaping Applied</div>
<h1>LDAP Directory Search</h1>
<div class="defense-box">
<strong><i class="fa-solid fa-shield-halved"></i> Defenses active:</strong> LDAP special char escaping | Username allowlist | Length limit
<br><small>Try injecting <code>*</code> or <code>*)(uid=*)</code> — they will be escaped.</small>
</div>
<form method="GET" action="/search">
  <label>Search username:</label><br>
  <input type="text" name="username" value="{username}" placeholder="e.g. alice">
  <button type="submit">Search</button>
</form>
<div class="result">
<strong>Escaped filter used:</strong> <code>{ldap_filter}</code>
<br><br>
<strong>Results:</strong><br>{result}
</div>
</body></html>"""


def _escape_ldap_filter(value: str) -> str:
    """Escape LDAP special characters — RFC 4515."""
    replacements = {
        '\\': r'\5c',
        '*': r'\2a',
        '(': r'\28',
        ')': r'\29',
        '\x00': r'\00',
    }
    for char, escaped in replacements.items():
        value = value.replace(char, escaped)
    return value


def _validate_username(username: str) -> str | None:
    """Returns error or None if valid."""
    if not username:
        return "Username is required."
    if len(username) > 32:
        return "Username too long."
    if not _USERNAME_PATTERN.match(username):
        return "Username contains invalid characters (only letters, numbers, - _ allowed)."
    return None


def _search_secure(username: str) -> tuple[list[dict], str, str | None]:
    """SECURE: validates and escapes before constructing filter."""
    error = _validate_username(username)
    if error:
        return [], "", error

    # SECURE: escape before use in filter
    escaped = _escape_ldap_filter(username)
    ldap_filter = f"(uid={escaped})"

    # Exact match only (no wildcards possible after escaping)
    results = [_LDAP_USERS[username]] if username in _LDAP_USERS else []
    return results, ldap_filter, None


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(username="alice", ldap_filter="(uid=alice)", result="Enter a username.")


@app.route("/search", methods=["GET"])
def search() -> Any:
    username = request.args.get("username", "")
    results, ldap_filter, error = _search_secure(username)

    if error:
        return _PAGE.format(
            username=username,
            ldap_filter=f"[BLOCKED: {error}]",
            result=f"<span style='color:red'>Rejected: {error}</span>",
        ), 400

    result_str = ""
    if results:
        for u in results:
            result_str += f"cn={u['cn']}, mail={u['mail']}, role={u['role']}<br>"
    else:
        result_str = "No results found."

    return _PAGE.format(username=username, ldap_filter=ldap_filter, result=result_str)


@app.route("/api/search", methods=["GET"])
def api_search() -> Any:
    username = request.args.get("username", "")
    results, ldap_filter, error = _search_secure(username)
    if error:
        return jsonify({"error": error, "blocked": True}), 400
    return jsonify({
        "filter": ldap_filter,
        "count": len(results),
        "users": [r["cn"] for r in results],
        "blocked": False,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
