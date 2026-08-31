"""
SSTI Lab — Secure Version
✅ SECURE IMPLEMENTATION

Defenses applied:
- Fixed template string — user input is a VARIABLE, not part of the template
- Input validation
- Jinja2 autoescape enabled
"""
from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, jsonify, request
from jinja2 import Environment, select_autoescape

app = Flask(__name__)
app.secret_key = "lab-ssti-secure-key"

_NAME_PATTERN = re.compile(r"^[\w\s\-'.]{1,64}$")

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SSTI Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.result {{ background: #f8f9fa; border: 2px solid #28a745; padding: 16px; font-size: 1.3em; margin: 16px 0; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; border-radius: 4px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
.error {{ color: #dc3545; }}
</style></head>
<body>
<div class="lab-banner">✅ SSTI LAB — SECURE — Fixed Template + Variable Binding</div>
<h1>Greeting Service</h1>

<div class="defense-box">
<strong>🛡 Defenses active:</strong> Fixed template | User input as variable | Input validation
<br><small>Try <code>{{{{7*7}}}}</code> — it will be displayed as literal text, not evaluated.</small>
</div>

<form method="GET" action="/greet">
  <label>Your name:</label><br>
  <input type="text" name="name" value="{name_display}" maxlength="64" placeholder="Enter your name">
  <button type="submit">Greet me</button>
</form>

{error_html}
<div class="result">{result}</div>

<a href="/source">View secure source</a>
</body></html>"""


# SECURE: the template is FIXED — {{ name }} is a variable placeholder, not user data
_GREETING_TEMPLATE = "Hello {{ name }}!"

_env = Environment(autoescape=select_autoescape(["html", "xml"]))
_template = _env.from_string(_GREETING_TEMPLATE)


@app.route("/", methods=["GET"])
@app.route("/greet", methods=["GET"])
def greet() -> Any:
    """Render greeting — SECURE: user input bound as variable."""
    raw_name = request.args.get("name", "World")

    error = None
    if not _NAME_PATTERN.match(raw_name):
        error = "Name contains invalid characters. Only letters, spaces, hyphens allowed."
        raw_name = "World"

    # SECURE: name is passed as DATA to the template, not as template code
    result = _template.render(name=raw_name)

    from markupsafe import escape
    name_display = str(escape(raw_name))
    error_html = f'<p class="error">{error}</p>' if error else ""
    return _PAGE.format(result=result, name_display=name_display, error_html=error_html)


@app.route("/api/greet", methods=["GET"])
def api_greet() -> Any:
    raw_name = request.args.get("name", "World")
    if not _NAME_PATTERN.match(raw_name):
        return jsonify({"error": "Invalid name", "blocked": True}), 400
    result = _template.render(name=raw_name)
    return jsonify({"input": raw_name, "output": result, "blocked": False})


@app.route("/source")
def source() -> Any:
    return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SSTI Secure Source</title>
<style>body{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}
pre{background:#f4f4f4;padding:16px;}
</style></head>
<body>
<h1>Secure SSTI Code</h1>
<pre>
# SECURE — template is FIXED, user input is a VARIABLE

# Template defined by developer — never from user input
GREETING_TEMPLATE = "Hello {{ name }}!"
template = Environment().from_string(GREETING_TEMPLATE)

# User input is passed as DATA, not as template source
name = request.args.get("name", "World")
result = template.render(name=name)
# Input: {{7*7}} → Output: Hello {{7*7}}! (displayed as text)
# The {{ name }} placeholder receives the string "{{7*7}}" as a value
# It is NOT re-evaluated as a template expression
</pre>
<a href="/">Back</a>
</body></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
