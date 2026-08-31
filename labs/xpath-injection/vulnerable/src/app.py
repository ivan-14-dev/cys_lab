"""
XPath Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: XPath filter injection via string concatenation
CWE-643, OWASP A03:2021
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request
from lxml import etree

app = Flask(__name__)
app.secret_key = "lab-xpath-vuln-key"

# Lab XML data (all fictional)
_XML_DATA = """<?xml version="1.0" encoding="UTF-8"?>
<users>
  <user id="1">
    <username>alice</username>
    <password>alice_lab_pass</password>
    <role>user</role>
    <email>alice@lab.local</email>
  </user>
  <user id="2">
    <username>bob</username>
    <password>bob_lab_pass</password>
    <role>user</role>
    <email>bob@lab.local</email>
  </user>
  <user id="3">
    <username>admin</username>
    <password>admin_lab_pass</password>
    <role>admin</role>
    <email>admin@lab.local</email>
  </user>
</users>
"""

_TREE = etree.fromstring(_XML_DATA.encode())

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>XPath Injection Lab — Vulnerable</title>
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
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> XPATH INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>User Lookup (XML Database)</h1>
<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Retrieve all users by manipulating the XPath query.
<br>Hint: Try username <code>' or '1'='1</code>
<br><strong>Objective:</strong> Get all users returned despite not knowing any password.
</div>
<form method="GET" action="/lookup">
  <label>Username:</label><br>
  <input type="text" name="username" value="{username}" placeholder="alice">
  <button type="submit">Lookup</button>
</form>
<div class="result">
<strong>XPath query:</strong> <code>//user[username='{username}']</code>
<br><br>
<strong>Results ({count}):</strong><br>{result}
</div>
<a href="/demo">Demo payloads</a>
</body></html>"""


def _query_vulnerable(username: str) -> tuple[list[dict], str]:
    """VULNERABLE: string concatenation in XPath — no escaping."""
    # VULNERABILITY: user input directly in XPath expression
    xpath_expr = f"//user[username='{username}']"
    try:
        nodes = _TREE.xpath(xpath_expr)
        results = []
        for node in nodes:
            results.append({
                "username": node.findtext("username", ""),
                "role": node.findtext("role", ""),
                "email": node.findtext("email", ""),
            })
    except etree.XPathEvalError:
        results = []
    return results, xpath_expr


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(username="alice", count=0, result="Enter a username.")


@app.route("/lookup", methods=["GET"])
def lookup() -> Any:
    username = request.args.get("username", "")
    results, xpath_expr = _query_vulnerable(username)
    result_html = ""
    for u in results:
        result_html += f"username={u['username']}, role={u['role']}, email={u['email']}<br>"
    if not result_html:
        result_html = "No results."
    return _PAGE.format(
        username=username,
        count=len(results),
        result=result_html,
    )


@app.route("/api/lookup", methods=["GET"])
def api_lookup() -> Any:
    username = request.args.get("username", "")
    results, xpath_expr = _query_vulnerable(username)
    return jsonify({"xpath": xpath_expr, "count": len(results), "users": results})


@app.route("/demo")
def demo() -> Any:
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>XPath Demo</title>
<style>body{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}
code{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}
</style></head><body>
<h1>XPath Injection Demo Payloads</h1>
<h2>Normal Query</h2>
<code>GET /lookup?username=alice</code>
<p>XPath: //user[username='alice'] → 1 result</p>
<h2>Always-True Condition</h2>
<code>GET /lookup?username=' or '1'='1</code>
<p>XPath: //user[username='' or '1'='1'] → all users returned</p>
<h2>Comment-out trick</h2>
<code>GET /lookup?username=alice' or '1'='1</code>
<p>XPath: //user[username='alice' or '1'='1'] → all users</p>
<a href="/">Back</a>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
