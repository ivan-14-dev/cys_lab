"""
Header Injection / CRLF Lab — Vulnerable Version
⚠️ INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: HTTP response header injection via CRLF characters
CWE-113, OWASP A03:2021
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-header-vuln-key"

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Header Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
pre {{ background: #f4f4f4; padding: 12px; border-radius: 4px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner">⚠️ HEADER INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>User Preferences API</h1>
<div class="ctf-box">
<strong>🎯 MISSION:</strong> Inject an extra HTTP response header via CRLF characters.
<br>Hint: Value = <code>en\\r\\nX-Injected: CRLF_INJECTION_DETECTED</code>
<br><strong>Objective:</strong> Make the response contain an injected header.
<br>Use: <code>curl -i "http://localhost:5017/set-lang?lang=en%0d%0aX-Injected:%20CRLF_INJECTION"</code>
</div>
<form method="GET" action="/set-lang">
  <label>Language preference:</label><br>
  <input type="text" name="lang" value="en" placeholder="e.g. en">
  <button type="submit">Set Language</button>
</form>
<pre>{result}</pre>
<a href="/demo">Demo payloads</a>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Header Demo</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
</style></head><body>
<h1>Header Injection Demo Payloads</h1>
<h2>Normal Request</h2>
<code>curl -i "http://localhost:5017/api/set-lang?lang=en"</code>
<h2>CRLF Injection (URL-encoded %0d%0a)</h2>
<code>curl -i "http://localhost:5017/api/set-lang?lang=en%0d%0aX-Injected:%20CRLF_INJECTION_DETECTED"</code>
<p>This injects the header: <strong>X-Injected: CRLF_INJECTION_DETECTED</strong></p>
<h2>Response Splitting (conceptual)</h2>
<code>lang=en%0d%0a%0d%0a&lt;html&gt;INJECTED_BODY&lt;/html&gt;</code>
<p>Two CRLF sequences end the headers section, allowing body injection.</p>
<a href="/">Back</a>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(result="Set a language preference above.")


@app.route("/set-lang", methods=["GET"])
def set_lang() -> Any:
    lang = request.args.get("lang", "en")
    resp = Response(
        _PAGE.format(result=f"Language set to: {lang}"),
        mimetype="text/html",
    )
    # VULNERABILITY: header value not validated — CRLF not stripped
    resp.headers["X-Language"] = lang
    return resp


@app.route("/api/set-lang", methods=["GET"])
def api_set_lang() -> Any:
    """API for automated testing — returns headers as JSON."""
    lang = request.args.get("lang", "en")
    resp = Response(
        jsonify({"lang": lang, "header_set": f"X-Language: {lang}"}).get_data(),
        mimetype="application/json",
    )
    # VULNERABILITY: raw user input in header
    resp.headers["X-Language"] = lang
    return resp


@app.route("/demo")
def demo() -> Any:
    return _DEMO


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
