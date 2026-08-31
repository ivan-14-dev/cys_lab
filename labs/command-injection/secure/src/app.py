"""
Command Injection Lab — Secure Version
<i class="fa-solid fa-circle-check"></i> SECURE IMPLEMENTATION

Defenses applied:
- subprocess with argument list (no shell=True)
- strict target allowlist
- no string concatenation in command
- non-root execution
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-cmd-secure-key"

# Strict allowlist — only known lab targets are permitted
_ALLOWED_TARGETS = frozenset({
    "127.0.0.1",
    "localhost",
})

_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>Command Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
pre {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 300px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; border-radius: 4px; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-circle-check"></i> COMMAND INJECTION LAB — SECURE — Argument List + Allowlist Applied</div>
<h1>Network Diagnostic Tool</h1>

<div class="defense-box">
<strong><i class="fa-solid fa-shield-halved"></i> Defenses active:</strong>
subprocess list args (no shell=True) | Target allowlist | IP validation
<br><small>Try injecting: <code>127.0.0.1; echo INJECTION_DETECTED</code> — it will be rejected.</small>
<br><small>Allowed targets: 127.0.0.1, localhost</small>
</div>

<form method="POST" action="/ping">
  <label>Target address:</label><br>
  <input type="text" name="target" value="127.0.0.1" placeholder="127.0.0.1 or localhost">
  <button type="submit">Ping</button>
</form>

<h3>Output:</h3>
<pre id="output">{output}</pre>

<a href="/source">View secure source</a>
</body></html>"""

_SOURCE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Secure Source</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
pre{{background:#f4f4f4;padding:16px;border-radius:4px;}}
.secure{{background:#d4edda;border-left:4px solid #28a745;padding:8px;}}
</style></head>
<body>
<h1>Secure Code</h1>
<div class="secure">
<strong><i class="fa-solid fa-circle-check"></i> DEFENSE:</strong> subprocess list + allowlist + no shell
</div>
<pre>
# SECURE — argument list, no shell
_ALLOWED = frozenset({"127.0.0.1", "localhost"})

target = request.form.get("target", "").strip()

# Step 1: allowlist check
if target not in _ALLOWED:
    return error("Target not in allowlist.")

# Step 2: validate IP format
try:
    ipaddress.ip_address(target)  # raises ValueError if invalid
except ValueError:
    if target != "localhost":
        return error("Invalid IP address.")

# Step 3: execute WITHOUT shell — target is a list element, not part of a string
result = subprocess.run(
    ["ping", "-c", "2", target],  # list → no shell interpolation possible
    shell=False,                   # shell=False is default but explicit is better
    capture_output=True,
    text=True,
    timeout=10,
)
# Injecting "127.0.0.1; echo INJECTED" would fail:
# ping receives the LITERAL string "127.0.0.1; echo INJECTED" as hostname → DNS failure
# No shell is involved → no command chaining possible
</pre>
<a href="/">Back</a>
</body></html>"""


def _validate_target(target: str) -> str | None:
    """Returns an error message if target is invalid, else None."""
    if not target:
        return "Target is required."
    if target not in _ALLOWED_TARGETS:
        return f"Target '{target}' is not in the allowed list: {sorted(_ALLOWED_TARGETS)}"
    if target != "localhost" and _IP_PATTERN.match(target):
        try:
            addr = ipaddress.ip_address(target)
            if not (addr.is_loopback or addr.is_private):
                return "Only loopback or private addresses are allowed."
        except ValueError:
            return "Invalid IP address format."
    return None


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(output="Enter an address and click Ping.")


@app.route("/ping", methods=["POST"])
def ping() -> Any:
    """Execute ping — SECURE: argument list, allowlist, no shell."""
    target = request.form.get("target", "").strip()
    error = _validate_target(target)
    if error:
        return _PAGE.format(output=f"[BLOCKED] {error}"), 400

    try:
        # SECURE: argument list — target cannot inject shell commands
        result = subprocess.run(
            ["ping", "-c", "2", target],
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out."
    except Exception as e:
        output = f"Error: {type(e).__name__}"

    return _PAGE.format(output=output)


@app.route("/api/ping", methods=["POST"])
def api_ping() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    target = str(data.get("target", "")).strip()
    error = _validate_target(target)
    if error:
        return jsonify({"error": error, "blocked": True}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", target],
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "timeout"
    except Exception as e:
        output = str(type(e).__name__)

    return jsonify({"output": output, "blocked": False})


@app.route("/source")
def source() -> Any:
    return _SOURCE


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
