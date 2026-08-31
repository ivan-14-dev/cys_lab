"""
Header Injection / CRLF Lab — Secure Version
✅ SECURE IMPLEMENTATION

Defenses applied:
- CRLF character stripping from all header values
- Allowlist validation for header values
- Reject values containing control characters
"""
from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-header-secure-key"

_ALLOWED_LANGS = frozenset({"en", "fr", "de", "es", "it", "pt", "nl", "ja", "zh"})
_HEADER_VALUE_RE = re.compile(r'^[a-zA-Z0-9\-_]{1,32}$')

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Header Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; }}
pre {{ background: #f4f4f4; padding: 12px; border-radius: 4px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner">✅ HEADER INJECTION LAB — SECURE — CRLF Stripping Applied</div>
<h1>User Preferences API</h1>
<div class="defense-box">
<strong>🛡 Defenses:</strong> CRLF stripping | Allowlist | Control char rejection
<br><small>Allowed langs: en, fr, de, es, it, pt, nl, ja, zh</small>
</div>
<form method="GET" action="/set-lang">
  <label>Language preference:</label><br>
  <input type="text" name="lang" value="en" placeholder="e.g. en">
  <button type="submit">Set Language</button>
</form>
<pre>{result}</pre>
</body></html>"""


def _sanitize_header_value(value: str) -> tuple[str, str | None]:
    """Strip CRLF and validate — returns (safe_value, error_or_None)."""
    if "\r" in value or "\n" in value or "\x00" in value:
        return "", "Header value contains illegal control characters (CRLF/null)."
    if value not in _ALLOWED_LANGS:
        return "", f"Language '{value}' is not in the allowed list."
    return value, None


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(result="Set a language preference above.")


@app.route("/set-lang", methods=["GET"])
def set_lang() -> Any:
    raw_lang = request.args.get("lang", "en")
    safe_lang, error = _sanitize_header_value(raw_lang)
    if error:
        resp = Response(
            _PAGE.format(result=f"[BLOCKED] {error}"),
            mimetype="text/html",
            status=400,
        )
        return resp
    resp = Response(
        _PAGE.format(result=f"Language set to: {safe_lang}"),
        mimetype="text/html",
    )
    resp.headers["X-Language"] = safe_lang
    return resp


@app.route("/api/set-lang", methods=["GET"])
def api_set_lang() -> Any:
    raw_lang = request.args.get("lang", "en")
    safe_lang, error = _sanitize_header_value(raw_lang)
    if error:
        return jsonify({"error": error, "blocked": True}), 400
    resp = Response(
        jsonify({"lang": safe_lang, "blocked": False}).get_data(),
        mimetype="application/json",
    )
    resp.headers["X-Language"] = safe_lang
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
