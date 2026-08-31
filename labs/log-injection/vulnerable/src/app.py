"""
Log Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: Log entry injection via string concatenation
CWE-117, OWASP A09:2021
"""
from __future__ import annotations

import io
import logging
import os
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-log-vuln-key"

# In-memory log capture for testing
_log_records: list[str] = []

# VULNERABLE: simple stream handler that accepts any string
_handler = logging.StreamHandler(io.StringIO())
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

_logger = logging.getLogger("lab.login.vulnerable")
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)


class _CapturingHandler(logging.Handler):
    """Captures log records for test verification."""
    def emit(self, record: logging.LogRecord) -> None:
        _log_records.append(self.format(record))


_capture_handler = _CapturingHandler()
_capture_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_logger.addHandler(_capture_handler)

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>Log Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
pre {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; font-size: 0.85em; white-space: pre-wrap; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 350px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> LOG INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Login Service</h1>
<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Inject a fake log entry to forge audit logs.
<br>Hint: Username = <code>admin\\nINFO 2024-01-01 00:00:01,000 [INFO] Login SUCCESS for user: root</code>
<br><strong>Objective:</strong> Make the log appear to show a successful root login.
</div>
<form method="POST" action="/login">
  <label>Username:</label><br>
  <input type="text" name="username" placeholder="Enter username (try injection payload)">
  <button type="submit">Login</button>
</form>
<h3>Log Output:</h3>
<pre>{logs}</pre>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    logs = "\n".join(_log_records[-20:]) if _log_records else "No log entries yet."
    return _PAGE.format(logs=logs)


@app.route("/login", methods=["POST"])
def login() -> Any:
    """VULNERABLE: username concatenated directly into log message."""
    username = request.form.get("username", "")

    # VULNERABILITY: direct string concatenation in log
    # A username containing \n can inject fake log entries
    _logger.info("Login attempt for user: " + username)

    logs = "\n".join(_log_records[-20:])
    return _PAGE.format(logs=logs)


@app.route("/api/login", methods=["POST"])
def api_login() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", ""))
    # VULNERABILITY
    _logger.info("Login attempt for user: " + username)
    return jsonify({
        "status": "attempted",
        "log_entry": f"Login attempt for user: {username}",
        "log_count": len(_log_records),
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
