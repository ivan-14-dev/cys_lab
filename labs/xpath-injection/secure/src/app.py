"""
XPath Injection Lab — Secure Version
✅ SECURE IMPLEMENTATION

Defenses applied:
- Single-quote escaping in XPath values
- Input validation (allowlist pattern)
- Parameterized-style query construction
"""
from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)
app.secret_key = "lab-xpath-secure-key"

_XML_DATA = """<?xml version="1.0" encoding="UTF-8"?>
<users>
  <user id="1"><username>alice</username><role>user</role><email>alice@lab.local</email></user>
  <user id="2"><username>bob</username><role>user</role><email>bob@lab.local</email></user>
  <user id="3"><username>admin</username><role>admin</role><email>admin@lab.local</email></user>
</users>"""

_TREE = etree.fromstring(_XML_DATA.encode())
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')


def _escape_xpath_string(value: str) -> str:
    """
    Safely quote a string for XPath.
    If the value contains single quotes, use concat() to handle them.
    """
    if "'" not in value:
        return f"'{value}'"
    parts = value.split("'")
    quoted = ", \"'\", ".join(f"'{p}'" for p in parts)
    return f"concat({quoted})"


def _query_secure(username: str) -> tuple[list[dict], str, str | None]:
    """SECURE: validates and escapes before constructing XPath."""
    if not _USERNAME_RE.match(username):
        return [], "", "Invalid username format."

    # SECURE: escape the value before embedding
    safe_value = _escape_xpath_string(username)
    xpath_expr = f"//user[username={safe_value}]"

    nodes = _TREE.xpath(xpath_expr)
    results = [
        {"username": n.findtext("username", ""), "role": n.findtext("role", ""), "email": n.findtext("email", "")}
        for n in nodes
    ]
    return results, xpath_expr, None


@app.route("/", methods=["GET"])
def index() -> Any:
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XPath Secure</title>
<style>body{font-family:Arial,sans-serif;max-width:800px;margin:40px auto;padding:0 20px;}
.lab-banner{background:#28a745;color:white;padding:10px;border-radius:4px;}
.defense-box{background:#d4edda;border:1px solid #28a745;padding:12px;margin:16px 0;}
input{padding:8px;width:300px;}
button{background:#28a745;color:white;padding:10px 20px;border:none;cursor:pointer;}
</style></head>
<body>
<div class="lab-banner">✅ XPATH INJECTION LAB — SECURE</div>
<h1>User Lookup</h1>
<div class="defense-box">
<strong>🛡 Defenses:</strong> XPath string escaping | Username allowlist
</div>
<form method="GET" action="/lookup">
<input type="text" name="username" placeholder="alice">
<button type="submit">Lookup</button>
</form>
</body></html>"""


@app.route("/lookup", methods=["GET"])
def lookup() -> Any:
    username = request.args.get("username", "")
    results, xpath_expr, error = _query_secure(username)
    result_html = ""
    if error:
        result_html = f"<span style='color:red'>Rejected: {error}</span>"
    else:
        for u in results:
            result_html += f"username={u['username']}, role={u['role']}<br>"
        if not result_html:
            result_html = "No results."
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XPath Result</title></head><body>
<p><strong>Query:</strong> <code>{xpath_expr or 'blocked'}</code></p>
<p>{result_html}</p><a href="/">Back</a>
</body></html>"""


@app.route("/api/lookup", methods=["GET"])
def api_lookup() -> Any:
    username = request.args.get("username", "")
    results, xpath_expr, error = _query_secure(username)
    if error:
        return jsonify({"error": error, "blocked": True}), 400
    return jsonify({"xpath": xpath_expr, "count": len(results), "users": results, "blocked": False})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
