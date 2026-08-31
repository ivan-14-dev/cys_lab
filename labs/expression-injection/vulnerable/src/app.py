"""
Expression Injection Lab — Vulnerable Version
⚠️ INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: eval() on user input enables code execution
CWE-94, OWASP A03:2021

IMPORTANT: The vulnerable version uses eval() but with a demonstration restricted to
showing the PROBLEM exists. Payloads that execute OS commands are intentionally
NOT demonstrated — we only show that eval() accepts more than math.
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-expr-vuln-key"

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Expression Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
.result {{ background: #f8f9fa; border: 2px solid #dc3545; padding: 16px; font-size: 1.4em; margin: 16px 0; border-radius: 4px; font-family: monospace; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner">⚠️ EXPRESSION INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Calculator</h1>
<div class="ctf-box">
<strong>🎯 MISSION:</strong> Show that the calculator accepts more than math.
<br>Hint: Try <code>__import__('os').environ.get('FLASK_ENV', 'EXPRESSION_INJECTION_DETECTED')</code>
<br>Or simpler: <code>1+1</code> vs <code>"a"*10</code> (string operations — not just math!)
<br><strong>Objective:</strong> Get a non-numeric result from the calculator.
</div>
<form method="GET" action="/calculate">
  <label>Expression:</label><br>
  <input type="text" name="expression" value="{expression}" placeholder="e.g. 2+2*10">
  <button type="submit">Calculate</button>
</form>
<div class="result">Result: {result}</div>
<p><a href="/demo">Demo payloads</a> | <a href="/source">View source</a></p>
</body></html>"""

_DEMO = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Expression Demo</title>
<style>body{{font-family:monospace;max-width:900px;margin:40px auto;padding:0 20px;}}
code{{background:#f4f4f4;padding:2px 6px;display:block;margin:4px 0;}}
.warning{{background:#ffe0e0;border-left:4px solid red;padding:8px;}}
</style></head><body>
<h1>Expression Injection Demo Payloads</h1>
<h2>Payload 1 — Normal math (expected)</h2>
<code>GET /calculate?expression=2%2B2*10</code>
<p>Result: 22 — correct math</p>
<h2>Payload 2 — String operation (unexpected)</h2>
<code>GET /calculate?expression="INJECTION"*3</code>
<p>Result: INJECTIONINJECTIONINJECTION — not a number!</p>
<h2>Payload 3 — Environment variable access</h2>
<code>GET /calculate?expression=__import__('os').environ.get('FLASK_ENV','detected')</code>
<p>Returns: development — accesses runtime environment!</p>
<div class="warning">
<strong>⚠️ In real attacks:</strong> eval() can execute arbitrary Python:
<code>__import__('os').system('id')  # executes OS command</code>
This demonstration intentionally stops at environment variable access.
Actual command execution is NOT demonstrated in this lab.
</div>
<a href="/">Back</a>
</body></html>"""


@app.route("/", methods=["GET"])
@app.route("/calculate", methods=["GET"])
def calculate() -> Any:
    """VULNERABLE: uses eval() on user input."""
    expression = request.args.get("expression", "")
    result = "Enter an expression above."

    if expression:
        try:
            # VULNERABILITY: eval() with user input — can execute any Python code
            result = str(eval(expression))  # noqa: S307 — intentional lab vulnerability
        except Exception as e:
            result = f"Error: {type(e).__name__}: {e}"

    from markupsafe import escape
    return _PAGE.format(expression=str(escape(expression)), result=result)


@app.route("/api/calculate", methods=["GET"])
def api_calculate() -> Any:
    expression = request.args.get("expression", "")
    if not expression:
        return jsonify({"error": "expression required"}), 400
    try:
        result = eval(expression)  # noqa: S307
        return jsonify({
            "expression": expression,
            "result": str(result),
            "type": type(result).__name__,
        })
    except Exception as e:
        return jsonify({"expression": expression, "error": str(e)}), 400


@app.route("/demo")
def demo() -> Any:
    return _DEMO


@app.route("/source")
def source() -> Any:
    return """<pre style="font-family:monospace;max-width:900px;margin:40px auto;padding:20px;background:#f4f4f4;">
# VULNERABLE
expression = request.args.get("expression", "")
result = eval(expression)  # eval() executes ANY Python expression
# Input: 2+2 → 4 (expected)
# Input: "x"*5 → xxxxx (not math!)
# Input: __import__('os').system('id') → executes OS command (not demonstrated)
</pre>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
