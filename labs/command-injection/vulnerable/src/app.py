"""
Command Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: OS command injection via shell=True + string concatenation
CWE-78, OWASP A03:2021
"""
from __future__ import annotations

import os
import subprocess
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-cmd-vuln-key"

# Allowed lab targets — even the vulnerable version restricts to local/internal
_LAB_TARGETS = {"127.0.0.1", "localhost", "cmd-secure", "cmd-vulnerable"}

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>Command Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
pre {{ background: #1e1e1e; color: #00ff00; padding: 16px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 300px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.danger {{ color: #dc3545; font-weight: bold; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> COMMAND INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Network Diagnostic Tool</h1>

<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Demonstrate that the tool executes more than just ping.
<br>Hint: Try <code>127.0.0.1; echo INJECTION_DETECTED</code>
<br><strong>Objective:</strong> See <code>INJECTION_DETECTED</code> in the output.
</div>

<form method="POST" action="/ping">
  <label>Target address:</label><br>
  <input type="text" name="target" value="127.0.0.1" placeholder="Enter IP (lab targets only)">
  <button type="submit">Ping</button>
</form>

<h3>Output:</h3>
<pre id="output">{output}</pre>

<hr>
<p class="danger"><i class="fa-solid fa-triangle-exclamation"></i> This is the vulnerable version. The command is constructed with shell=True.</p>
<p>See the <a href="/source">vulnerable source</a> | <a href="/demo">demo payloads</a></p>
</body></html>"""

_SOURCE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Vulnerable Source</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
pre{{background:#f4f4f4;padding:16px;border-radius:4px;}}
.vuln{{background:#ffe0e0;border-left:4px solid #dc3545;padding:8px;}}
</style></head>
<body>
<h1>Vulnerable Code</h1>
<div class="vuln">
<strong><i class="fa-solid fa-triangle-exclamation"></i> VULNERABILITY:</strong> shell=True + string concatenation
</div>
<pre>
# VULNERABLE — DO NOT DO THIS
target = request.form.get("target", "")
# The target is concatenated directly into the shell command
command = f"ping -c 2 {{target}}"
result = subprocess.run(command, shell=True, capture_output=True, text=True)
# shell=True means: /bin/sh -c "ping -c 2 {{target}}"
# Attacker input: 127.0.0.1; echo INJECTION_DETECTED
# Executed: /bin/sh -c "ping -c 2 127.0.0.1; echo INJECTION_DETECTED"
# Result: ping runs, THEN echo runs → INJECTION_DETECTED appears
</pre>
<a href="/">Back</a>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Demo Payloads</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
</style></head>
<body>
<h1>Command Injection Demo Payloads (Lab Only)</h1>
<h2>Payload 1 — Command chaining with semicolon</h2>
<code>127.0.0.1; echo INJECTION_DETECTED</code>
<p>Runs ping, then runs echo.</p>
<h2>Payload 2 — Second command only</h2>
<code>127.0.0.1 && echo CALC_7x7=$(expr 7 \\* 7)</code>
<p>Executes second command only if ping succeeds.</p>
<h2>Payload 3 — Read a lab file</h2>
<code>127.0.0.1; cat /app/data/lab-secret.txt</code>
<p>Reads a file created specifically for this demonstration.</p>
<h2>What is NOT allowed</h2>
<ul>
<li>Reverse shells</li>
<li>Destructive commands (rm, mkfs, dd)</li>
<li>Network scanning</li>
<li>Container escape attempts</li>
</ul>
<a href="/">Back</a>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    return _PAGE.format(output="Enter an address and click Ping.")


@app.route("/ping", methods=["POST"])
def ping() -> Any:
    """Execute ping — VULNERABLE: uses shell=True with string concatenation."""
    target = request.form.get("target", "").strip()
    if not target:
        return _PAGE.format(output="Error: no target provided."), 400

    # VULNERABILITY: shell=True + string concatenation → command injection
    command = f"ping -c 2 {target}"
    try:
        result = subprocess.run(
            command,
            shell=True,          # VULNERABLE — allows injection
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        if not output:
            output = f"[Command executed: {command}]"
    except subprocess.TimeoutExpired:
        output = "Command timed out."
    except Exception as e:
        output = f"Error: {e}"

    return _PAGE.format(output=output)


@app.route("/api/ping", methods=["POST"])
def api_ping() -> Any:
    """API endpoint for automated testing."""
    data = request.get_json(force=True, silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target:
        return jsonify({"error": "no target"}), 400

    command = f"ping -c 1 {target}"
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "timeout"
    except Exception as e:
        output = str(e)

    return jsonify({"command": command, "output": output})


@app.route("/source")
def source() -> Any:
    return _SOURCE


@app.route("/demo")
def demo() -> Any:
    return _DEMO


if __name__ == "__main__":
    # Create a demo file for lab demonstrations
    os.makedirs("/app/data", exist_ok=True)
    with open("/app/data/lab-secret.txt", "w") as f:
        f.write("LAB_FLAG: COMMAND_INJECTION_DEMONSTRATED\nThis file is for lab demonstration only.\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
