"""
LDAP Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: LDAP filter injection via string concatenation
CWE-90, OWASP A03:2021
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-ldap-vuln-key"

# Simulated LDAP directory — used for unit tests (no real LDAP required)
_LDAP_USERS = {
    "ivan": {"cn": "ivan", "sn": "Lab User", "mail": "ivan@lab.local", "role": "admin"},
    "alice": {"cn": "alice", "sn": "Alice Test", "mail": "alice@lab.local", "role": "user"},
    "bob": {"cn": "bob", "sn": "Bob Test", "mail": "bob@lab.local", "role": "user"},
}

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>LDAP Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.result {{ background: #f8f9fa; border: 1px solid #ddd; padding: 16px; margin: 16px 0; border-radius: 4px; font-family: monospace; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 300px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> LDAP INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>LDAP Directory Search</h1>
<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Modify the LDAP filter to retrieve all users.
<br>Hint: Try username <code>*)(uid=*))(|(uid=*</code>
<br><strong>Objective:</strong> Retrieve all users instead of just one.
</div>
<form method="GET" action="/search">
  <label>Search username:</label><br>
  <input type="text" name="username" value="{username}" placeholder="e.g. alice">
  <button type="submit">Search</button>
</form>
<div class="result">
<strong>LDAP Filter used:</strong> <code>(uid={username})</code>
<br><br>
<strong>Results:</strong><br>{result}
</div>
<p><a href="/demo">View demo payloads</a></p>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>LDAP Demo</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
</style></head><body>
<h1>LDAP Injection Demo Payloads</h1>
<h2>Normal Search</h2>
<code>GET /search?username=alice</code>
<p>Filter: (uid=alice) → returns alice's record</p>
<h2>Wildcard — Returns all users</h2>
<code>GET /search?username=*</code>
<p>Filter: (uid=*) → returns all entries</p>
<h2>Filter Escape — Enumerate all</h2>
<code>GET /search?username=*)(uid=*))(|(uid=*</code>
<p>Filter becomes: (uid=*)(uid=*))(|(uid=*)) → logic bypassed</p>
<h2>How it works</h2>
<p>The filter <code>(uid={input})</code> becomes <code>(uid=*)(uid=*))(|(uid=*)</code>
when the attacker injects special LDAP characters. The LDAP server may interpret
this as multiple conditions or return unexpected results.</p>
<a href="/">Back</a>
</body></html>"""


def _search_vulnerable(username: str) -> list[dict]:
    """VULNERABLE: string concatenation in LDAP filter — simulated."""
    # Constructed filter (shown to user and used for search)
    ldap_filter = f"(uid={username})"  # VULNERABLE: no escaping

    # Simulate LDAP wildcard and injection effects
    results = []
    if username == "*":
        results = list(_LDAP_USERS.values())
    elif "*" in username or ")" in username or "(" in username:
        # Injection detected — return all (simulating filter bypass)
        results = list(_LDAP_USERS.values())
    elif username in _LDAP_USERS:
        results = [_LDAP_USERS[username]]

    return results, ldap_filter


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(username="alice", result="Enter a username to search.")


@app.route("/search", methods=["GET"])
def search() -> Any:
    username = request.args.get("username", "")
    results, ldap_filter = _search_vulnerable(username)

    result_str = ""
    if results:
        for u in results:
            result_str += f"cn={u['cn']}, mail={u['mail']}, role={u['role']}<br>"
    else:
        result_str = "No results found."

    return _PAGE.format(
        username=username,
        result=result_str,
    ).replace(f"(uid={username})", ldap_filter)


@app.route("/api/search", methods=["GET"])
def api_search() -> Any:
    username = request.args.get("username", "")
    results, ldap_filter = _search_vulnerable(username)
    return jsonify({
        "filter": ldap_filter,
        "count": len(results),
        "users": [r["cn"] for r in results],
    })


@app.route("/demo")
def demo() -> Any:
    return _DEMO


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
