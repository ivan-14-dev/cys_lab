"""
SSTI Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: Server-Side Template Injection via user-controlled template string
CWE-94, OWASP A03:2021

IMPORTANT: Demonstration is limited to math expressions only ({{7*7}}).
System command payloads are intentionally documented but demonstration
is restricted to showing the template engine evaluates expressions.
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, request
from jinja2 import Environment, DictLoader

app = Flask(__name__)
app.secret_key = "lab-ssti-vuln-key"

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>SSTI Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.result {{ background: #f8f9fa; border: 2px solid #dc3545; padding: 16px; font-size: 1.3em; margin: 16px 0; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> SSTI LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Greeting Service</h1>

<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Show that the application evaluates your input as a template expression.
<br>Hint: Try <code>{{{{7*7}}}}</code> as your name.
<br><strong>Objective:</strong> See <code>49</code> in the result instead of <code>{{{{7*7}}}}</code>.
</div>

<form method="GET" action="/greet">
  <label>Your name:</label><br>
  <input type="text" name="name" value="{name_escaped}" placeholder="Enter your name">
  <button type="submit">Greet me</button>
</form>

<div class="result">{result}</div>

<p>Current input: <code>{name_escaped}</code></p>
<p><a href="/source">View vulnerable source</a> | <a href="/demo">Demo payloads</a></p>
</body></html>"""

_SOURCE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SSTI Source</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
pre{{background:#f4f4f4;padding:16px;}}
</style></head>
<body>
<h1>Vulnerable SSTI Code</h1>
<pre>
# VULNERABLE — user input becomes the TEMPLATE itself
name = request.args.get("name", "World")

# The template string is built from user data
template_string = f"Hello {name}!"  # name could be {{7*7}}

# Jinja2 renders the user-controlled template → EXECUTES expressions
env = Environment()
template = env.from_string(template_string)
result = template.render()
# Input: {{7*7}} → Output: Hello 49!
# The engine evaluated the expression as code.
</pre>
<a href="/">Back</a>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SSTI Demo</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
.warning{{background:#ffe0e0;border-left:4px solid red;padding:8px;}}
</style></head>
<body>
<h1>SSTI Demo Payloads (Lab Only)</h1>

<h2>Payload 1 — Math expression (safe proof)</h2>
<code>{{7*7}}</code>
<p>Expected output: <strong>Hello 49!</strong> — proves template evaluation.</p>

<h2>Payload 2 — String operation</h2>
<code>{{"injection"*3}}</code>
<p>Expected output: <strong>Hello injectioninjectioninjection!</strong></p>

<h2>Payload 3 — Variable access</h2>
<code>{{config}}</code>
<p>Expected output: Flask config object displayed.</p>

<div class="warning">
<strong><i class="fa-solid fa-triangle-exclamation"></i> Important:</strong> In real SSTI attacks, attackers can reach
<code>__class__.__mro__</code> to execute OS commands. This demonstration is
intentionally limited to math expressions only.
</div>

<a href="/">Back</a>
</body></html>"""


@app.route("/", methods=["GET"])
@app.route("/greet", methods=["GET"])
def greet() -> Any:
    """Render greeting — VULNERABLE: user input is the template string."""
    name = request.args.get("name", "World")

    # VULNERABILITY: user input is used as the template source
    template_string = f"Hello {name}!"
    try:
        env = Environment(autoescape=False)  # No autoescape — intentional
        template = env.from_string(template_string)
        result = template.render()
    except Exception as e:
        result = f"Template error: {type(e).__name__}: {e}"

    # Escape only for display in the meta section, not for the result
    from markupsafe import escape
    name_escaped = str(escape(name))
    return _PAGE.format(result=result, name_escaped=name_escaped)


@app.route("/api/greet", methods=["GET"])
def api_greet() -> Any:
    """API for automated testing."""
    from flask import jsonify
    name = request.args.get("name", "World")
    template_string = f"Hello {name}!"
    try:
        env = Environment(autoescape=False)
        template = env.from_string(template_string)
        result = template.render()
        error = None
    except Exception as e:
        result = None
        error = str(e)
    return jsonify({"input": name, "output": result, "error": error})


@app.route("/source")
def source() -> Any:
    return _SOURCE


@app.route("/demo")
def demo() -> Any:
    return _DEMO


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
