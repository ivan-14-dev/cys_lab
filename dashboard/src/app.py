"""
Injection Security Lab — Dashboard
Central portal for all labs.
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, render_template_string

app = Flask(__name__)
app.secret_key = "lab-dashboard-key"

_LABS = [
    {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "difficulty": "Easy",
        "points": 10,
        "component": "Browser / HTML",
        "description": "User input rendered as HTML allows script execution in the victim's browser.",
        "vuln_port": 5001,
        "secure_port": 5002,
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "status": "ready",
    },
    {
        "id": "command",
        "name": "Command Injection",
        "difficulty": "Medium",
        "points": 15,
        "component": "OS Shell",
        "description": "User input concatenated into a shell command allows arbitrary OS command execution.",
        "vuln_port": 5003,
        "secure_port": 5004,
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "status": "ready",
    },
    {
        "id": "ssti",
        "name": "Server-Side Template Injection (SSTI)",
        "difficulty": "Medium",
        "points": 15,
        "component": "Template Engine (Jinja2)",
        "description": "User input used as a template string allows expression evaluation by the engine.",
        "vuln_port": 5005,
        "secure_port": 5006,
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "status": "ready",
    },
    {
        "id": "nosql",
        "name": "NoSQL Injection",
        "difficulty": "Medium",
        "points": 10,
        "component": "MongoDB",
        "description": "Untrusted JSON accepted as a MongoDB query filter enables authentication bypass.",
        "vuln_port": 5007,
        "secure_port": 5008,
        "owasp": "A03:2021",
        "cwe": "CWE-943",
        "status": "ready",
    },
    {
        "id": "ldap",
        "name": "LDAP Injection",
        "difficulty": "Medium",
        "points": 10,
        "component": "LDAP Directory",
        "description": "Special characters in LDAP filter strings manipulate directory queries.",
        "vuln_port": 5009,
        "secure_port": 5010,
        "owasp": "A03:2021",
        "cwe": "CWE-90",
        "status": "ready",
    },
    {
        "id": "xpath",
        "name": "XPath Injection",
        "difficulty": "Medium",
        "points": 10,
        "component": "XML / XPath Engine",
        "description": "User input in XPath queries can manipulate XML data retrieval logic.",
        "vuln_port": 5011,
        "secure_port": 5012,
        "owasp": "A03:2021",
        "cwe": "CWE-643",
        "status": "ready",
    },
    {
        "id": "csv",
        "name": "CSV Injection",
        "difficulty": "Easy",
        "points": 5,
        "component": "Spreadsheet Application",
        "description": "Formula characters in CSV cells are executed by spreadsheet software on open.",
        "vuln_port": 5013,
        "secure_port": 5014,
        "owasp": "A03:2021",
        "cwe": "CWE-1236",
        "status": "ready",
    },
    {
        "id": "log",
        "name": "Log Injection",
        "difficulty": "Easy",
        "points": 5,
        "component": "Logging System",
        "description": "Newline characters in log entries allow forging fake log records.",
        "vuln_port": 5015,
        "secure_port": 5016,
        "owasp": "A09:2021",
        "cwe": "CWE-117",
        "status": "ready",
    },
    {
        "id": "header",
        "name": "HTTP Header / CRLF Injection",
        "difficulty": "Easy",
        "points": 5,
        "component": "HTTP Response Headers",
        "description": "CRLF characters in header values allow injecting additional HTTP headers.",
        "vuln_port": 5017,
        "secure_port": 5018,
        "owasp": "A03:2021",
        "cwe": "CWE-113",
        "status": "ready",
    },
    {
        "id": "expression",
        "name": "Expression / Code Injection",
        "difficulty": "Medium",
        "points": 10,
        "component": "Expression Evaluator",
        "description": "eval() on user input allows executing arbitrary Python expressions.",
        "vuln_port": 5019,
        "secure_port": 5020,
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "status": "ready",
    },
]

_TOTAL_POINTS = sum(lab["points"] for lab in _LABS)

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Injection Security Lab</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d1117;
    color: #e6edf3;
    min-height: 100vh;
  }
  header {
    background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
    border-bottom: 2px solid #30363d;
    padding: 24px 40px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header-title h1 { font-size: 1.8em; color: #58a6ff; }
  .header-title p { color: #8b949e; margin-top: 4px; font-size: 0.9em; }
  .score-badge {
    background: #21262d;
    border: 2px solid #30363d;
    border-radius: 12px;
    padding: 16px 24px;
    text-align: center;
  }
  .score-badge .score { font-size: 2em; color: #3fb950; font-weight: bold; }
  .score-badge .label { color: #8b949e; font-size: 0.85em; }
  .warning-bar {
    background: #3d1f00;
    border: 1px solid #d29922;
    color: #d29922;
    padding: 10px 40px;
    font-size: 0.85em;
    text-align: center;
  }
  main { padding: 32px 40px; max-width: 1400px; margin: 0 auto; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
    gap: 20px;
    margin-top: 24px;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px;
    transition: border-color 0.2s, transform 0.1s;
  }
  .card:hover { border-color: #58a6ff; transform: translateY(-2px); }
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
  }
  .card-title { font-size: 1.05em; font-weight: 600; color: #e6edf3; }
  .card-meta { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
  .badge {
    font-size: 0.75em;
    padding: 3px 8px;
    border-radius: 20px;
    font-weight: 500;
  }
  .badge-easy { background: #0d4a1e; color: #3fb950; border: 1px solid #238636; }
  .badge-medium { background: #3d2900; color: #d29922; border: 1px solid #9e6a03; }
  .badge-hard { background: #4a0d0d; color: #f85149; border: 1px solid #da3633; }
  .badge-points { background: #0d2145; color: #58a6ff; border: 1px solid #1f6feb; }
  .badge-owasp { background: #1a1f2e; color: #8b949e; border: 1px solid #30363d; }
  .card-desc { color: #8b949e; font-size: 0.9em; line-height: 1.5; margin-bottom: 16px; }
  .card-component { font-size: 0.8em; color: #6e7681; margin-bottom: 4px; }
  .cwe-tag { font-size: 0.8em; color: #6e7681; }
  .card-actions { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
  .btn {
    padding: 8px 16px;
    border-radius: 6px;
    text-decoration: none;
    font-size: 0.85em;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.2s;
    display: inline-block;
  }
  .btn:hover { opacity: 0.85; }
  .btn-vuln { background: #da3633; color: white; }
  .btn-secure { background: #238636; color: white; }
  .btn-docs { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  .status-ready { color: #3fb950; }
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #30363d;
    padding-bottom: 12px;
  }
  .sql-theory-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 20px;
    margin-top: 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .sql-icon { font-size: 2em; }
  footer {
    text-align: center;
    color: #6e7681;
    padding: 24px;
    border-top: 1px solid #21262d;
    font-size: 0.85em;
    margin-top: 48px;
  }
</style>
</head>
<body>

<header>
  <div class="header-title">
    <h1><i class="fa-solid fa-lock"></i> Injection Security Lab</h1>
    <p>Educational cybersecurity laboratory — Local sandbox only</p>
  </div>
  <div class="score-badge">
    <div class="score">0 / {{ total_points }}</div>
    <div class="label">Total Points</div>
  </div>
</header>

<div class="warning-bar">
  <i class="fa-solid fa-triangle-exclamation"></i> EDUCATIONAL USE ONLY &nbsp;|&nbsp; LOCAL SANDBOX &nbsp;|&nbsp;
  DO NOT EXPOSE TO THE INTERNET &nbsp;|&nbsp;
  All vulnerabilities are intentional
</div>

<main>
  <div class="section-header">
    <h2>Labs ({{ labs|length }})</h2>
    <span style="color:#8b949e;font-size:0.9em;">{{ total_points }} total points</span>
  </div>

  <div class="grid">
    {% for lab in labs %}
    <div class="card">
      <div class="card-header">
        <div class="card-title">{{ lab.name }}</div>
        <span class="status-ready"><i class="fa-solid fa-circle fa-xs"></i> ready</span>
      </div>
      <div class="card-meta">
        <span class="badge badge-{{ lab.difficulty|lower }}">{{ lab.difficulty }}</span>
        <span class="badge badge-points">{{ lab.points }} pts</span>
        <span class="badge badge-owasp">{{ lab.owasp }}</span>
      </div>
      <div class="card-component"><i class="fa-solid fa-crosshairs"></i> {{ lab.component }}</div>
      <div class="cwe-tag">{{ lab.cwe }}</div>
      <div class="card-desc">{{ lab.description }}</div>
      <div class="card-actions">
        <a class="btn btn-vuln" href="http://localhost:{{ lab.vuln_port }}" target="_blank">
          <i class="fa-solid fa-triangle-exclamation"></i> Vulnerable
        </a>
        <a class="btn btn-secure" href="http://localhost:{{ lab.secure_port }}" target="_blank">
          <i class="fa-solid fa-circle-check"></i> Secure
        </a>
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="sql-theory-card">
    <div class="sql-icon"><i class="fa-solid fa-book"></i></div>
    <div>
      <strong>SQL Injection — Theory Only</strong>
      <p style="color:#8b949e;font-size:0.9em;margin-top:4px;">
        SQL Injection is covered in documentation only.
        No practical exploit is included in this lab.
      </p>
      <a class="btn btn-docs" href="/sql-theory" style="margin-top:8px;display:inline-block;">
        Read Theory →
      </a>
    </div>
  </div>
</main>

<footer>
  Injection Security Lab — Educational Use Only — Run on isolated lab machine only
</footer>
</body>
</html>"""

_SQL_THEORY = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SQL Injection Theory</title>
<style>
body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }
h1, h2 { color: #1a1a2e; }
pre { background: #f4f4f4; padding: 16px; border-radius: 4px; overflow-x: auto; }
.note { background: #e7f3ff; border-left: 4px solid #2196f3; padding: 12px; margin: 16px 0; }
</style></head>
<body>
<h1>SQL Injection — Theory</h1>
<div class="note">
<strong>Note:</strong> SQL Injection is intentionally excluded from the practical labs.
This page covers the theory only.
</div>
<h2>Definition</h2>
<p>SQL Injection occurs when user input is included in a SQL query without proper
parameterization, allowing an attacker to alter the query's logic.</p>
<h2>Vulnerable Example (conceptual)</h2>
<pre># VULNERABLE
query = "SELECT * FROM users WHERE username='" + username + "'"
# username = "admin'--" → bypasses password check</pre>
<h2>Secure Implementation</h2>
<pre># SECURE — prepared statement
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))</pre>
<h2>Prevention</h2>
<ul>
<li>Prepared statements / parameterized queries</li>
<li>ORM (SQLAlchemy, Django ORM)</li>
<li>Input validation</li>
<li>Least privilege DB accounts</li>
</ul>
<p>See <a href="/docs/sql-injection-theory.md">full theory document</a>.</p>
<a href="/">← Back to Dashboard</a>
</body></html>"""


@app.route("/")
def index() -> Any:
    return render_template_string(_TEMPLATE, labs=_LABS, total_points=_TOTAL_POINTS)


@app.route("/sql-theory")
def sql_theory() -> Any:
    return _SQL_THEORY


@app.route("/api/labs")
def api_labs() -> Any:
    from flask import jsonify
    return jsonify({"labs": _LABS, "total_points": _TOTAL_POINTS})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
