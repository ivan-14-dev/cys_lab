"""
Log Injection Lab — Secure Version
✅ SECURE IMPLEMENTATION

Defenses applied:
- Structured logging (extra dict — no string concatenation)
- Control character stripping
- Input validation
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import unicodedata
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-log-secure-key"

_log_records: list[dict] = []

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')


class _StructuredHandler(logging.Handler):
    """Stores log records as structured dicts — no free-form string concatenation."""
    def emit(self, record: logging.LogRecord) -> None:
        _log_records.append({
            "time": self.formatter.formatTime(record),
            "level": record.levelname,
            # username is a structured field — not embedded in the message string
            "message": record.getMessage(),
            "username": getattr(record, "username", None),
        })


_logger = logging.getLogger("lab.login.secure")
_logger.setLevel(logging.INFO)
_handler = _StructuredHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s"))
_logger.addHandler(_handler)


def _strip_control_chars(value: str) -> str:
    """Remove newlines and other control characters from log values."""
    return re.sub(r'[\r\n\x00-\x1f\x7f]', '', value)


def _validate_username(username: str) -> str | None:
    if not username:
        return "Username required."
    if not _USERNAME_RE.match(username):
        return "Invalid username format."
    return None


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; }}
pre {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; font-size: 0.85em; white-space: pre-wrap; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 350px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner">✅ LOG INJECTION LAB — SECURE — Structured Logging Applied</div>
<h1>Login Service</h1>
<div class="defense-box">
<strong>🛡 Defenses:</strong> Structured logging | Control char stripping | Username validation
<br><small>Username is a field, not embedded in the log string. \\n injection has no effect.</small>
</div>
<form method="POST" action="/login">
  <label>Username:</label><br>
  <input type="text" name="username" maxlength="32" placeholder="Enter username">
  <button type="submit">Login</button>
</form>
<h3>Log Output (structured):</h3>
<pre>{logs}</pre>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    logs = json.dumps(_log_records[-20:], indent=2) if _log_records else "[]"
    return _PAGE.format(logs=logs)


@app.route("/login", methods=["POST"])
def login() -> Any:
    raw_username = request.form.get("username", "")
    error = _validate_username(raw_username)
    safe_username = _strip_control_chars(raw_username)
    if error:
        # SECURE: log the rejection with username as a structured field
        _logger.warning(
            "Login rejected: invalid username format",
            extra={"username": safe_username},
        )
    else:
        _logger.info(
            "Login attempt",
            extra={"username": safe_username},
        )
    logs = json.dumps(_log_records[-20:], indent=2)
    return _PAGE.format(logs=logs)


@app.route("/api/login", methods=["POST"])
def api_login() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    raw_username = str(data.get("username", ""))
    error = _validate_username(raw_username)
    safe_username = _strip_control_chars(raw_username)
    if error:
        return jsonify({"error": error, "blocked": True}), 400
    _logger.info("Login attempt", extra={"username": safe_username})
    return jsonify({
        "status": "attempted",
        "log_count": len(_log_records),
        "blocked": False,
    })


@app.route("/api/logs")
def api_logs() -> Any:
    return jsonify({"logs": _log_records[-20:]})


@app.route("/reset")
def reset() -> Any:
    _log_records.clear()
    from flask import redirect
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
