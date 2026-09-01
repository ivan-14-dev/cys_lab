"""
Injection Security Lab — Dashboard
Central portal with CTF scoring, hints, quizzes, sandbox, and health monitoring.
"""
from __future__ import annotations

import os
import socket
import urllib.error
import urllib.request
from typing import Any

from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-dashboard-key"

# ── Lab Definitions ──────────────────────────────────────────

_LABS = [
    {"id": "xss", "name": "Cross-Site Scripting (XSS)", "difficulty": "Easy", "points": 10, "component": "Browser / HTML", "description": "User input rendered as HTML allows script execution in the victim's browser.", "vuln_port": 5001, "secure_port": 5002, "owasp": "A03:2021", "cwe": "CWE-79", "status": "ready"},
    {"id": "command", "name": "Command Injection", "difficulty": "Medium", "points": 15, "component": "OS Shell", "description": "User input concatenated into a shell command allows arbitrary OS command execution.", "vuln_port": 5003, "secure_port": 5004, "owasp": "A03:2021", "cwe": "CWE-78", "status": "ready"},
    {"id": "ssti", "name": "Server-Side Template Injection (SSTI)", "difficulty": "Medium", "points": 15, "component": "Template Engine (Jinja2)", "description": "User input used as a template string allows expression evaluation by the engine.", "vuln_port": 5005, "secure_port": 5006, "owasp": "A03:2021", "cwe": "CWE-94", "status": "ready"},
    {"id": "nosql", "name": "NoSQL Injection", "difficulty": "Medium", "points": 10, "component": "MongoDB", "description": "Untrusted JSON accepted as a MongoDB query filter enables authentication bypass.", "vuln_port": 5007, "secure_port": 5008, "owasp": "A03:2021", "cwe": "CWE-943", "status": "ready"},
    {"id": "ldap", "name": "LDAP Injection", "difficulty": "Medium", "points": 10, "component": "LDAP Directory", "description": "Special characters in LDAP filter strings manipulate directory queries.", "vuln_port": 5009, "secure_port": 5010, "owasp": "A03:2021", "cwe": "CWE-90", "status": "ready"},
    {"id": "xpath", "name": "XPath Injection", "difficulty": "Medium", "points": 10, "component": "XML / XPath Engine", "description": "User input in XPath queries can manipulate XML data retrieval logic.", "vuln_port": 5011, "secure_port": 5012, "owasp": "A03:2021", "cwe": "CWE-643", "status": "ready"},
    {"id": "csv", "name": "CSV Injection", "difficulty": "Easy", "points": 5, "component": "Spreadsheet Application", "description": "Formula characters in CSV cells are executed by spreadsheet software on open.", "vuln_port": 5013, "secure_port": 5014, "owasp": "A03:2021", "cwe": "CWE-1236", "status": "ready"},
    {"id": "log", "name": "Log Injection", "difficulty": "Easy", "points": 5, "component": "Logging System", "description": "Newline characters in log entries allow forging fake log records.", "vuln_port": 5015, "secure_port": 5016, "owasp": "A09:2021", "cwe": "CWE-117", "status": "ready"},
    {"id": "header", "name": "HTTP Header / CRLF Injection", "difficulty": "Easy", "points": 5, "component": "HTTP Response Headers", "description": "CRLF characters in header values allow injecting additional HTTP headers.", "vuln_port": 5017, "secure_port": 5018, "owasp": "A03:2021", "cwe": "CWE-113", "status": "ready"},
    {"id": "expression", "name": "Expression / Code Injection", "difficulty": "Medium", "points": 10, "component": "Expression Evaluator", "description": "eval() on user input allows executing arbitrary Python expressions.", "vuln_port": 5019, "secure_port": 5020, "owasp": "A03:2021", "cwe": "CWE-94", "status": "ready"},
    {"id": "sql", "name": "SQL Injection", "difficulty": "Medium", "points": 15, "component": "SQLite Database", "description": "String concatenation in SQL queries allows authentication bypass and data extraction.", "vuln_port": 5021, "secure_port": 5022, "owasp": "A03:2021", "cwe": "CWE-89", "status": "ready"},
    {"id": "ssrf", "name": "Server-Side Request Forgery (SSRF)", "difficulty": "Hard", "points": 15, "component": "HTTP Client / URL Fetcher", "description": "The server fetches user-supplied URLs without validation, exposing internal services.", "vuln_port": 5023, "secure_port": 5024, "owasp": "A10:2021", "cwe": "CWE-918", "status": "ready"},
    {"id": "idor", "name": "Insecure Direct Object Reference (IDOR)", "difficulty": "Easy", "points": 10, "component": "API / Access Control", "description": "Direct object references (IDs) are not verified, allowing access to other users' data.", "vuln_port": 5025, "secure_port": 5026, "owasp": "A01:2021", "cwe": "CWE-639", "status": "ready"},
    {"id": "pathtraversal", "name": "Path Traversal", "difficulty": "Medium", "points": 10, "component": "File System / Document Viewer", "description": "../ sequences in filenames allow reading files outside the intended directory.", "vuln_port": 5027, "secure_port": 5028, "owasp": "A01:2021", "cwe": "CWE-22", "status": "ready"},
]

_TOTAL_POINTS = sum(lab["points"] for lab in _LABS)

# ── Hints ────────────────────────────────────────────────────

_HINTS: dict[str, list[str]] = {
    "xss": [
        "Comments are rendered without HTML sanitization. Try injecting tags.",
        "Use an &lt;img&gt; tag with an onerror handler to execute JavaScript.",
        "The flag is at GET /api/admin/flag. Fetch it via XSS and read the response.",
    ],
    "command": [
        "The ping function passes your input directly to the OS shell.",
        "Use shell metacharacters like ; or | to chain additional commands.",
        "The flag is in /tmp/flag.txt. Try: 127.0.0.1; cat /tmp/flag.txt",
    ],
    "ssti": [
        "The template engine evaluates expressions inside double curly braces.",
        "Access Python objects through the MRO chain of built-in classes.",
        "Try: {{cycler.__init__.__globals__.os.environ.get('LAB_FLAG')}}",
    ],
    "nosql": [
        "MongoDB accepts query operators as JSON objects in filter fields.",
        "A hidden user 'flag_bearer' has the flag stored in their role field.",
        'Try: {"username":"flag_bearer","password":{"$regex":".*"}}',
    ],
    "ldap": [
        "LDAP wildcard character * matches all entries in the directory.",
        "A hidden user 'flag_user' stores the flag in the mail attribute.",
        "Search with username=* to dump all users including flag_user.",
    ],
    "xpath": [
        "XPath queries can be manipulated with union (|) operators.",
        "A secret node exists outside the users section in the XML data.",
        "Try: x'] | //secret | //data/users/user[username='x",
    ],
    "csv": [
        "Spreadsheet formulas start with special characters: = + - @",
        "When formula characters are detected, a special HTTP header is added.",
        "Submit an entry starting with = and check the X-CTF-Flag response header.",
    ],
    "log": [
        "Newline characters in input create separate entries in the log.",
        "If any log record contains 'Login successful', the flag is revealed.",
        'Inject: admin\\nLogin successful in the username, then check GET /api/logs.',
    ],
    "header": [
        "CRLF sequences (\\r\\n) in header values inject new HTTP headers.",
        "When injection is detected, the flag appears in the JSON response body.",
        "Try: en%0d%0aX-Injected:%20true",
    ],
    "expression": [
        "eval() accepts any Python expression, not just math.",
        "You can access environment variables through the os module.",
        "Try: __import__('os').environ.get('LAB_FLAG')",
    ],
    "sql": [
        "SQL queries are built by concatenating user input into the query string.",
        "A hidden 'secrets' table contains the flag. Use UNION SELECT to read it.",
        "Try: ' UNION SELECT 1,flag,3,4 FROM secrets--",
    ],
    "ssrf": [
        "The server fetches any URL you provide without restriction.",
        "Internal endpoints exist at /internal/metadata and /internal/flag.",
        "Try fetching: http://localhost:5000/internal/flag",
    ],
    "idor": [
        "User profiles are accessible by sequential numeric IDs without auth checks.",
        "The admin user (id=3) has sensitive data in the notes field.",
        "Simply request GET /api/user/3 to read the admin's private notes.",
    ],
    "pathtraversal": [
        "The file reader joins your filename with a base directory using os.path.join.",
        "Use ../ sequences to escape the allowed directory up to the filesystem root.",
        "Try: ../../../../tmp/flag.txt",
    ],
}

_hints_unlocked: dict[str, int] = {}

# ── Quizzes ──────────────────────────────────────────────────

_QUIZZES: dict[str, list[dict]] = {
    "xss": [
        {"q": "What does XSS stand for?", "opts": ["Cross-Site Scripting", "Cross-Server Scripting", "Client-Side Scripting", "Cross-System Security"], "ans": 0},
        {"q": "Which type of XSS persists in the server database?", "opts": ["Reflected", "Stored", "DOM-based", "Self-XSS"], "ans": 1},
        {"q": "What is the primary defense against XSS?", "opts": ["Input length limits", "Output encoding / escaping", "HTTPS encryption", "Rate limiting"], "ans": 1},
    ],
    "command": [
        {"q": "Which Python function is vulnerable to command injection?", "opts": ["subprocess.run(shell=True)", "subprocess.run(shell=False)", "os.path.join()", "json.loads()"], "ans": 0},
        {"q": "What character is commonly used to chain OS commands?", "opts": ["&", "@", ";", "?"], "ans": 2},
        {"q": "What is the secure alternative to os.system()?", "opts": ["exec()", "eval()", "subprocess with a list of args", "shell=True"], "ans": 2},
    ],
    "ssti": [
        {"q": "What does SSTI stand for?", "opts": ["Server-Side Template Injection", "Server-Side Token Injection", "Static Site Template Inclusion", "Secure Server TLS Integration"], "ans": 0},
        {"q": "Which Jinja2 feature enables SSTI exploitation?", "opts": ["Static files", "Expression evaluation in {{ }}", "CSS imports", "HTML comments"], "ans": 1},
        {"q": "How do you prevent SSTI?", "opts": ["Never use user input as template source", "Use longer passwords", "Enable HTTPS", "Block all GET requests"], "ans": 0},
    ],
    "nosql": [
        {"q": "Which database is commonly targeted by NoSQL injection?", "opts": ["PostgreSQL", "MongoDB", "SQLite", "MySQL"], "ans": 1},
        {"q": "What operator is used for regex matching in MongoDB?", "opts": ["$like", "$match", "$regex", "$find"], "ans": 2},
        {"q": "How do you prevent NoSQL injection?", "opts": ["Use SQL queries instead", "Validate input types and use schema validation", "Disable logging", "Use GET instead of POST"], "ans": 1},
    ],
    "ldap": [
        {"q": "What wildcard character matches all entries in LDAP?", "opts": ["?", "%", "*", "#"], "ans": 2},
        {"q": "What is the LDAP filter syntax for a search?", "opts": ["SELECT ... WHERE", "(attribute=value)", "{key: value}", "<query>value</query>"], "ans": 1},
        {"q": "How do you prevent LDAP injection?", "opts": ["Escape special characters in filter strings", "Use HTTP headers", "Encrypt the directory", "Use JSON instead"], "ans": 0},
    ],
    "xpath": [
        {"q": "XPath is used to query which data format?", "opts": ["JSON", "CSV", "XML", "YAML"], "ans": 2},
        {"q": "Which operator combines XPath result sets?", "opts": ["AND", "UNION", "|", "+"], "ans": 2},
        {"q": "How do you prevent XPath injection?", "opts": ["Parameterized XPath queries or input validation", "Use XML comments", "Encrypt the XML file", "Use HTTPS"], "ans": 0},
    ],
    "csv": [
        {"q": "Which character prefix triggers formula execution in spreadsheets?", "opts": ["#", "=", "&", "/"], "ans": 1},
        {"q": "What type of attack does CSV injection enable?", "opts": ["SQL injection", "Formula injection / DDE attack", "Buffer overflow", "DNS spoofing"], "ans": 1},
        {"q": "How do you prevent CSV injection?", "opts": ["Prepend cells with a single quote or tab", "Use XML instead", "Encrypt the CSV", "Use binary format"], "ans": 0},
    ],
    "log": [
        {"q": "What character enables log injection?", "opts": ["Tab (\\t)", "Newline (\\n)", "Null (\\0)", "Space"], "ans": 1},
        {"q": "What is the main risk of log injection?", "opts": ["Data loss", "Forging fake log entries / log spoofing", "Memory overflow", "CPU overload"], "ans": 1},
        {"q": "How do you prevent log injection?", "opts": ["Strip or encode control characters", "Disable logging", "Use binary logs only", "Increase log file size"], "ans": 0},
    ],
    "header": [
        {"q": "What does CRLF stand for?", "opts": ["Carriage Return Line Feed", "Cross-Reference Log File", "Client Request Load Factor", "Certificate Revocation List Format"], "ans": 0},
        {"q": "What can CRLF injection in headers allow?", "opts": ["SQL injection", "HTTP response splitting / header injection", "File upload", "DNS hijacking"], "ans": 1},
        {"q": "How do you prevent header injection?", "opts": ["Reject or encode CR/LF in header values", "Use POST only", "Encrypt all headers", "Use HTTP/2 exclusively"], "ans": 0},
    ],
    "expression": [
        {"q": "Which Python function is dangerous for evaluating user input?", "opts": ["print()", "len()", "eval()", "str()"], "ans": 2},
        {"q": "What can eval() access when given malicious input?", "opts": ["Only math operations", "The full Python runtime (os, sys, etc.)", "Only string functions", "Only the local scope"], "ans": 1},
        {"q": "What is the safe alternative to eval() for math?", "opts": ["exec()", "compile()", "ast.literal_eval() or a math parser", "input()"], "ans": 2},
    ],
    "sql": [
        {"q": "What makes a SQL query vulnerable to injection?", "opts": ["Using SELECT statements", "String concatenation with user input", "Using WHERE clauses", "Using JOINs"], "ans": 1},
        {"q": "What SQL keyword extracts data from another table?", "opts": ["JOIN", "UNION SELECT", "GROUP BY", "HAVING"], "ans": 1},
        {"q": "What is the best defense against SQL injection?", "opts": ["Input length limits", "Parameterized queries / prepared statements", "Stored procedures only", "Database encryption"], "ans": 1},
    ],
    "ssrf": [
        {"q": "What does SSRF stand for?", "opts": ["Server-Side Request Forgery", "Secure Socket Relay Framework", "System Service Resource Fault", "Server-Side Response Filter"], "ans": 0},
        {"q": "What is the primary risk of SSRF?", "opts": ["XSS attacks", "Access to internal services not exposed to the internet", "SQL injection", "Password theft"], "ans": 1},
        {"q": "How do you prevent SSRF?", "opts": ["URL allowlisting and blocking internal IP ranges", "Using HTTPS only", "Disabling cookies", "Using POST requests"], "ans": 0},
    ],
    "idor": [
        {"q": "What does IDOR stand for?", "opts": ["Insecure Direct Object Reference", "Internal Data Object Retrieval", "Indirect Domain Origin Request", "Input Data Output Redirect"], "ans": 0},
        {"q": "What OWASP category does IDOR fall under?", "opts": ["Injection", "Broken Access Control", "Cryptographic Failures", "Security Misconfiguration"], "ans": 1},
        {"q": "How do you prevent IDOR?", "opts": ["Use HTTPS", "Check authorization on every object access", "Use longer URLs", "Encrypt the database"], "ans": 1},
    ],
    "pathtraversal": [
        {"q": "Which sequence is used to traverse directories?", "opts": ["./", "~/", "../", "//"], "ans": 2},
        {"q": "What file is commonly targeted in path traversal on Linux?", "opts": ["/etc/passwd", "/var/www/index.html", "/tmp/test.txt", "/home/user/.bashrc"], "ans": 0},
        {"q": "How do you prevent path traversal?", "opts": ["Use os.path.basename() or a chroot jail", "Always use absolute paths", "Disable directory listing", "Use HTTPS"], "ans": 0},
    ],
}

_quiz_scores: dict[str, dict] = {}

# ── Sandbox defaults ─────────────────────────────────────────

_SANDBOX_DEFAULTS: dict[str, dict[str, str]] = {
    "xss": {"m": "POST", "p": "/api/comment", "ct": "application/json", "b": '{"name":"test","comment":"<b>hello</b>"}', "h": "Inject HTML tags. Try <script>alert(1)</script> or <img src=x onerror=alert(1)>."},
    "command": {"m": "POST", "p": "/api/ping", "ct": "application/json", "b": '{"target":"127.0.0.1"}', "h": "Append shell commands: 127.0.0.1; cat /tmp/flag.txt"},
    "ssti": {"m": "GET", "p": "/api/greet?name=test", "ct": "", "b": "", "h": "Replace 'test' with {{7*7}} to test template evaluation. Then try MRO chains."},
    "nosql": {"m": "POST", "p": "/api/login", "ct": "application/json", "b": '{"username":"admin","password":"test"}', "h": 'Replace password with {"$ne":""} to bypass authentication.'},
    "ldap": {"m": "GET", "p": "/api/search?username=admin", "ct": "", "b": "", "h": "Replace 'admin' with * to enumerate all LDAP entries."},
    "xpath": {"m": "GET", "p": "/api/lookup?username=admin", "ct": "", "b": "", "h": "Try: admin' or '1'='1 to break the XPath expression."},
    "csv": {"m": "POST", "p": "/api/export", "ct": "application/json", "b": '{"entries":[{"name":"John","email":"j@x.com","company":"Test"}]}', "h": "Change name to =1+1 for formula injection. Check response headers."},
    "log": {"m": "POST", "p": "/api/login", "ct": "application/json", "b": '{"username":"admin"}', "h": "Add \\n to forge new log lines: admin\\nLogin successful. Then GET /api/logs."},
    "header": {"m": "GET", "p": "/api/set-lang?lang=en", "ct": "", "b": "", "h": "Append %0d%0aX-Injected:%20true to the lang value."},
    "expression": {"m": "GET", "p": "/api/calculate?expression=2+2", "ct": "", "b": "", "h": "Replace 2+2 with __import__('os').popen('id').read()"},
    "sql": {"m": "POST", "p": "/api/login", "ct": "application/json", "b": '{"username":"admin","password":"test"}', "h": "Try username: admin'-- to bypass. Use UNION SELECT for data extraction."},
    "ssrf": {"m": "GET", "p": "/api/fetch?url=http://example.com", "ct": "", "b": "", "h": "Replace URL with http://localhost:5000/internal/flag"},
    "idor": {"m": "GET", "p": "/api/user/1", "ct": "", "b": "", "h": "Try different user IDs: /api/user/1, /api/user/2, /api/user/3"},
    "pathtraversal": {"m": "GET", "p": "/api/read?file=readme.txt", "ct": "", "b": "", "h": "Use ../ sequences: ../../../../tmp/flag.txt"},
}

# ── Docker service names for health checks ───────────────────

_SVC_NAMES: dict[str, str] = {
    "xss": "xss-vulnerable", "command": "cmd-vulnerable",
    "ssti": "ssti-vulnerable", "nosql": "nosql-vulnerable",
    "ldap": "ldap-vulnerable", "xpath": "xpath-vulnerable",
    "csv": "csv-vulnerable", "log": "log-vulnerable",
    "header": "header-vulnerable", "expression": "expr-vulnerable",
    "sql": "sqli-vulnerable", "ssrf": "ssrf-vulnerable",
    "idor": "idor-vulnerable", "pathtraversal": "pathtraversal-vulnerable",
}

# ── Template ─────────────────────────────────────────────────

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CYS LAB — Injection Security CTF</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{--bg:#0a0e14;--bg2:#141921;--bg3:#1c2230;--bdr:#2a3040;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149;--purple:#a371f7;--text:#e6edf3;--muted:#8b949e;--subtle:#484f58}
*{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}

/* Header */
.hdr{background:linear-gradient(135deg,#0c1220 0%,#151d2e 100%);border-bottom:1px solid var(--bdr);padding:20px 32px;display:flex;align-items:center;gap:24px}
.hdr-logo{display:flex;align-items:center;gap:12px}
.hdr-logo i{font-size:2em;background:linear-gradient(135deg,var(--accent),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hdr-logo div h1{font-size:1.4em;font-weight:700;letter-spacing:-.3px}
.hdr-logo div p{color:var(--muted);font-size:.78em;margin-top:2px}
.hdr-mid{display:flex;gap:24px;margin-left:auto;margin-right:24px}
.hdr-stat{text-align:center;padding:0 16px;border-right:1px solid var(--bdr)}
.hdr-stat:last-child{border:none;padding-right:0}
.hdr-stat .v{font-size:1.5em;font-weight:700;color:var(--green)}
.hdr-stat .l{font-size:.68em;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
.ring-wrap{position:relative;width:76px;height:76px;flex-shrink:0}
.ring-wrap svg{width:76px;height:76px;transform:rotate(-90deg)}
.ring-bg{fill:none;stroke:var(--bdr);stroke-width:6}
.ring-fg{fill:none;stroke:var(--green);stroke-width:6;stroke-linecap:round;stroke-dasharray:188.5;stroke-dashoffset:188.5;transition:stroke-dashoffset .8s ease}
.ring-pct{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:1.05em;font-weight:700}

/* Warning */
.warn{background:linear-gradient(90deg,#1a1200,#2d1f00,#1a1200);border-bottom:1px solid rgba(210,153,34,.3);color:var(--yellow);padding:8px 32px;font-size:.76em;text-align:center;letter-spacing:.3px}

main{max-width:1440px;margin:0 auto;padding:24px 32px}

/* Stats Row */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.sc{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:14px 16px;display:flex;align-items:center;gap:12px;transition:border-color .2s}
.sc:hover{border-color:var(--accent)}
.sc-i{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1em;flex-shrink:0}
.sc-i.g{background:rgba(63,185,80,.1);color:var(--green)}
.sc-i.b{background:rgba(88,166,255,.1);color:var(--accent)}
.sc-i.y{background:rgba(210,153,34,.1);color:var(--yellow)}
.sc-i.p{background:rgba(163,113,247,.1);color:var(--purple)}
.sc-v{font-size:1.4em;font-weight:700}
.sc-l{font-size:.74em;color:var(--muted)}
.sc-bar{height:3px;background:var(--bdr);border-radius:2px;margin-top:5px;overflow:hidden}
.sc-bar span{display:block;height:100%;border-radius:2px;transition:width .6s ease}

/* Toolbar */
.tb{display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.srch{flex:1;min-width:200px;position:relative}
.srch i{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--subtle);font-size:.82em}
.srch input{width:100%;padding:9px 12px 9px 34px;background:var(--bg2);border:1px solid var(--bdr);border-radius:8px;color:var(--text);font-size:.86em;outline:none;transition:border-color .2s}
.srch input:focus{border-color:var(--accent)}
.srch kbd{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:var(--bg);border:1px solid var(--bdr);border-radius:4px;padding:1px 6px;font-size:.65em;color:var(--subtle)}
.pills{display:flex;gap:5px}
.pill{padding:6px 14px;border-radius:18px;border:1px solid var(--bdr);background:transparent;color:var(--muted);font-size:.78em;cursor:pointer;transition:all .2s;font-weight:500}
.pill:hover{border-color:var(--accent);color:var(--text)}
.pill.on{background:var(--accent);color:#000;border-color:var(--accent);font-weight:600}

/* Grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:18px;position:relative;transition:all .25s;overflow:hidden}
.card:hover{border-color:var(--accent);transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.25)}
.card.won{border-color:var(--green);background:linear-gradient(135deg,var(--bg2) 0%,rgba(63,185,80,.05) 100%)}
.card.won .card-flag{display:flex}
.card-flag{display:none;position:absolute;top:10px;right:12px;align-items:center;gap:4px;padding:3px 8px;background:rgba(63,185,80,.15);border:1px solid rgba(63,185,80,.3);border-radius:12px;font-size:.68em;font-weight:700;color:var(--green);animation:popIn .4s ease}
.card-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.badges{display:flex;gap:5px;flex-wrap:wrap}
.bg{font-size:.68em;padding:2px 7px;border-radius:10px;font-weight:600;letter-spacing:.2px}
.bg-e{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.25)}
.bg-m{background:rgba(210,153,34,.12);color:var(--yellow);border:1px solid rgba(210,153,34,.25)}
.bg-h{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.25)}
.bg-p{background:rgba(88,166,255,.1);color:var(--accent);border:1px solid rgba(88,166,255,.2)}
.bg-o{background:var(--bg);border:1px solid var(--bdr);color:var(--subtle)}
.health{width:7px;height:7px;border-radius:50%;background:var(--subtle);flex-shrink:0;transition:all .3s}
.health.up{background:var(--green);box-shadow:0 0 5px rgba(63,185,80,.5)}
.health.dn{background:var(--red)}
.card h3{font-size:.97em;font-weight:600;margin-bottom:4px}
.card-inf{display:flex;gap:10px;font-size:.73em;color:var(--subtle);margin-bottom:6px}
.card-d{font-size:.82em;color:var(--muted);line-height:1.45;margin-bottom:12px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.card-act{display:flex;gap:6px;flex-wrap:wrap}
.btn{padding:6px 12px;border-radius:6px;text-decoration:none;font-size:.78em;font-weight:600;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:4px;border:none}
.btn:hover{opacity:.85;transform:translateY(-1px)}
.btn-r{background:var(--red);color:#fff}
.btn-g{background:#238636;color:#fff}
.btn-o{background:var(--bg3);border:1px solid var(--bdr);color:var(--muted)}
.btn-o:hover{border-color:var(--yellow);color:var(--yellow)}
.btn-a{background:var(--accent);color:#000}
.btn-p{background:rgba(163,113,247,.15);border:1px solid rgba(163,113,247,.3);color:var(--purple)}
.btn-p:hover{background:rgba(163,113,247,.25);opacity:1}
.btn-t{background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.3);color:var(--yellow)}
.btn-t:hover{background:rgba(210,153,34,.22);opacity:1}

/* CTF */
.ctf{background:var(--bg2);border:1px solid var(--green);border-radius:12px;padding:20px;margin-bottom:22px;position:relative;overflow:hidden}
.ctf::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--green),transparent)}
.ctf-hd{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.ctf-hd i{font-size:1.5em;color:var(--green)}
.ctf-hd h2{font-size:1.05em;color:var(--green);font-weight:700}
.ctf-hd p{font-size:.8em;color:var(--muted)}
.ctf-row{display:flex;gap:8px;margin-bottom:10px}
.ctf-in{flex:1;padding:10px 14px;background:var(--bg);border:1px solid var(--bdr);border-radius:8px;color:var(--text);font-family:monospace;font-size:.86em;outline:none;transition:border-color .2s}
.ctf-in:focus{border-color:var(--green)}
.ctf-btn{padding:10px 22px;background:var(--green);color:#000;border:none;border-radius:8px;font-weight:700;font-size:.86em;cursor:pointer;transition:all .15s}
.ctf-btn:hover{background:#4ac95e;transform:translateY(-1px)}
#flag-msg{min-height:22px;font-size:.83em;margin-bottom:8px}
.caps{display:flex;flex-wrap:wrap;gap:5px}
.cap{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);color:var(--green);border-radius:14px;font-size:.72em;font-weight:600;animation:popIn .3s ease}

/* Theory */
.thry{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:16px;display:flex;align-items:center;gap:14px;margin-bottom:20px}
.thry i.fa-book{font-size:1.6em;color:var(--accent)}

/* Modal */
.mdl-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px);z-index:100;align-items:center;justify-content:center}
.mdl-bg.show{display:flex}
.mdl{background:var(--bg2);border:1px solid var(--bdr);border-radius:14px;width:520px;max-width:92vw;max-height:82vh;overflow-y:auto;animation:slideUp .3s ease}
.mdl.wide{width:740px}
.mdl-h{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--bdr)}
.mdl-h h3{font-size:1em}
.mdl-h button{background:none;border:none;color:var(--muted);font-size:1.1em;cursor:pointer;padding:4px}
.mdl-h button:hover{color:var(--text)}
.mdl-b{padding:18px}
.hint{padding:12px 14px;border-radius:8px;margin-bottom:8px;border:1px solid var(--bdr);position:relative;transition:all .3s}
.hint.open{background:rgba(63,185,80,.05);border-color:rgba(63,185,80,.2)}
.hint.open .hn{color:var(--green)}
.hint.locked .ht{filter:blur(5px);user-select:none;pointer-events:none}
.hint.locked::after{content:'\\f023';font-family:'Font Awesome 6 Free';font-weight:900;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1em;color:var(--subtle)}
.hn{font-size:.7em;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--subtle);margin-bottom:3px}
.ht{font-size:.84em;line-height:1.5;color:var(--text);font-family:monospace}
.mdl-f{padding:12px 18px;border-top:1px solid var(--bdr);display:flex;justify-content:flex-end;gap:8px}

/* Quiz */
.quiz-prog{display:flex;align-items:center;gap:8px;margin-bottom:14px;font-size:.78em;color:var(--muted)}
.quiz-dots{display:flex;gap:4px;margin-left:auto}
.quiz-dot{width:8px;height:8px;border-radius:50%;background:var(--bdr);transition:all .2s}
.quiz-dot.cur{background:var(--accent);box-shadow:0 0 4px var(--accent)}
.quiz-dot.ok{background:var(--green)}
.quiz-dot.no{background:var(--red)}
.quiz-q{font-size:.95em;font-weight:600;margin-bottom:14px;line-height:1.5}
.quiz-opts{display:flex;flex-direction:column;gap:6px}
.quiz-opt{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--bg);border:1px solid var(--bdr);border-radius:8px;cursor:pointer;transition:all .2s;font-size:.86em}
.quiz-opt:hover{border-color:var(--accent)}
.quiz-opt.sel{border-color:var(--accent);background:rgba(88,166,255,.08)}
.quiz-opt.right{border-color:var(--green);background:rgba(63,185,80,.08);cursor:default}
.quiz-opt.wrong{border-color:var(--red);background:rgba(248,81,73,.08);cursor:default}
.quiz-opt .qd{width:16px;height:16px;border-radius:50%;border:2px solid var(--subtle);flex-shrink:0;transition:all .2s}
.quiz-opt.sel .qd{border-color:var(--accent);background:var(--accent)}
.quiz-opt.right .qd{border-color:var(--green);background:var(--green)}
.quiz-opt.wrong .qd{border-color:var(--red);background:var(--red)}
.quiz-res{text-align:center;padding:20px}
.quiz-res .big{font-size:2.4em;font-weight:700}
.quiz-res .big.pass{color:var(--green)}
.quiz-res .big.mid{color:var(--yellow)}
.quiz-res .big.fail{color:var(--red)}

/* Sandbox */
.sb-bar{display:flex;gap:6px;margin-bottom:8px;align-items:center;flex-wrap:wrap}
.sb-sel{padding:7px 10px;background:var(--bg);border:1px solid var(--bdr);border-radius:6px;color:var(--text);font-size:.82em;outline:none;font-family:monospace}
.sb-sel:focus{border-color:var(--accent)}
.sb-path{flex:1;min-width:120px;padding:7px 10px;background:var(--bg);border:1px solid var(--bdr);border-radius:6px;color:var(--green);font-family:monospace;font-size:.82em;outline:none}
.sb-path:focus{border-color:var(--accent)}
.sb-lbl{font-size:.72em;color:var(--subtle);text-transform:uppercase;letter-spacing:.5px;margin:10px 0 4px;font-weight:600}
.sb-editor{width:100%;min-height:80px;padding:10px 12px;background:var(--bg);border:1px solid var(--bdr);border-radius:8px;color:var(--green);font-family:'Cascadia Code','Fira Code',monospace;font-size:.82em;line-height:1.6;resize:vertical;outline:none;tab-size:2}
.sb-editor:focus{border-color:var(--accent)}
.sb-editor::placeholder{color:var(--subtle)}
.sb-hint{font-size:.76em;color:var(--accent);padding:6px 10px;background:rgba(88,166,255,.06);border-left:2px solid var(--accent);border-radius:0 4px 4px 0;margin-bottom:10px}
.sb-actions{display:flex;gap:6px;margin:10px 0}
.sb-resp{background:var(--bg);border:1px solid var(--bdr);border-radius:8px;overflow:hidden}
.sb-resp-hdr{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid var(--bdr);font-size:.78em}
.sb-st{padding:2px 8px;border-radius:4px;font-weight:700;font-size:.8em}
.sb-st.s2{background:rgba(63,185,80,.15);color:var(--green)}
.sb-st.s3{background:rgba(210,153,34,.15);color:var(--yellow)}
.sb-st.s4{background:rgba(248,81,73,.15);color:var(--red)}
.sb-st.s5{background:rgba(248,81,73,.15);color:var(--red)}
.sb-tabs{display:flex;margin-left:auto}
.sb-tab{padding:4px 10px;font-size:.78em;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}
.sb-tab:hover{color:var(--text)}
.sb-tab.on{color:var(--accent);border-color:var(--accent)}
.sb-pane{display:none}
.sb-pane.on{display:block}
.sb-out{padding:10px 12px;font-family:monospace;font-size:.8em;line-height:1.5;color:var(--text);max-height:280px;overflow:auto;white-space:pre-wrap;word-break:break-all}

/* Toast */
.toasts{position:fixed;bottom:20px;right:20px;z-index:200;display:flex;flex-direction:column;gap:6px;pointer-events:none}
.toast{padding:11px 16px;border-radius:8px;font-size:.83em;font-weight:500;display:flex;align-items:center;gap:8px;animation:slideIn .3s ease;min-width:260px;box-shadow:0 4px 16px rgba(0,0,0,.35);pointer-events:auto}
.toast.ok{background:#0f2d16;border:1px solid var(--green);color:var(--green)}
.toast.err{background:#2d0f0f;border:1px solid var(--red);color:var(--red)}

/* Confetti */
.confetti{position:fixed;width:8px;height:8px;z-index:300;pointer-events:none;animation:cfall var(--dur,1.5s) ease forwards;opacity:0;top:-10px}

footer{text-align:center;color:var(--subtle);padding:20px;border-top:1px solid var(--bdr);font-size:.78em;margin-top:16px}

@keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{opacity:0;transform:translateX(80px)}to{opacity:1;transform:translateX(0)}}
@keyframes popIn{from{opacity:0;transform:scale(.4)}to{opacity:1;transform:scale(1)}}
@keyframes cfall{0%{opacity:1;transform:translateY(0) rotate(0deg)}100%{opacity:0;transform:translateY(95vh) rotate(720deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

@media(max-width:960px){
  .hdr{flex-wrap:wrap;gap:14px;padding:16px 20px}
  .hdr-mid{gap:14px;margin:0}
  main{padding:16px 20px}
  .stats{grid-template-columns:repeat(2,1fr)}
  .grid{grid-template-columns:1fr}
  .tb{flex-direction:column;align-items:stretch}
}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-logo">
    <i class="fa-solid fa-shield-halved"></i>
    <div>
      <h1>CYS LAB</h1>
      <p>Injection Security CTF &mdash; Local Sandbox</p>
    </div>
  </div>
  <div class="hdr-mid">
    <div class="hdr-stat"><div class="v" id="h-labs">0/{{ labs|length }}</div><div class="l">Labs</div></div>
    <div class="hdr-stat"><div class="v" id="h-pts">0</div><div class="l">Points</div></div>
    <div class="hdr-stat"><div class="v" id="h-flags">0</div><div class="l">Flags</div></div>
  </div>
  <div class="ring-wrap">
    <svg viewBox="0 0 76 76"><circle class="ring-bg" cx="38" cy="38" r="30"/><circle class="ring-fg" id="ring" cx="38" cy="38" r="30"/></svg>
    <div class="ring-pct" id="ring-pct">0%</div>
  </div>
</header>

<div class="warn">
  <i class="fa-solid fa-triangle-exclamation"></i>
  EDUCATIONAL USE ONLY &nbsp;&bull;&nbsp; LOCAL SANDBOX &nbsp;&bull;&nbsp;
  DO NOT EXPOSE TO THE INTERNET &nbsp;&bull;&nbsp;
  All vulnerabilities are intentional
</div>

<main>

<div class="stats">
  <div class="sc"><div class="sc-i g"><i class="fa-solid fa-check-double"></i></div><div><div class="sc-v" id="s-done">0</div><div class="sc-l">Completed</div><div class="sc-bar"><span id="bar-done" style="width:0;background:var(--green)"></span></div></div></div>
  <div class="sc"><div class="sc-i b"><i class="fa-solid fa-star"></i></div><div><div class="sc-v" id="s-pts">0 / {{ total_points }}</div><div class="sc-l">Score</div><div class="sc-bar"><span id="bar-pts" style="width:0;background:var(--accent)"></span></div></div></div>
  <div class="sc"><div class="sc-i y"><i class="fa-solid fa-fire"></i></div><div><div class="sc-v" id="s-streak">-</div><div class="sc-l">Last Capture</div></div></div>
  <div class="sc"><div class="sc-i p"><i class="fa-solid fa-server"></i></div><div><div class="sc-v" id="s-up">...</div><div class="sc-l">Services Up</div><div class="sc-bar"><span id="bar-up" style="width:0;background:var(--purple)"></span></div></div></div>
</div>

<div class="tb">
  <div class="srch">
    <i class="fa-solid fa-magnifying-glass"></i>
    <input id="search" type="text" placeholder="Search labs...">
    <kbd>Ctrl+K</kbd>
  </div>
  <div class="pills">
    <button class="pill on" onclick="setFilter('all',this)">All ({{ labs|length }})</button>
    <button class="pill" onclick="setFilter('easy',this)">Easy</button>
    <button class="pill" onclick="setFilter('medium',this)">Medium</button>
    <button class="pill" onclick="setFilter('hard',this)">Hard</button>
    <button class="pill" onclick="setFilter('captured',this)"><i class="fa-solid fa-flag"></i> Captured</button>
  </div>
</div>

<div class="grid" id="grid">
  {% for lab in labs %}
  <div class="card" id="c-{{ lab.id }}" data-diff="{{ lab.difficulty|lower }}" data-name="{{ lab.name|lower }}">
    <div class="card-flag"><i class="fa-solid fa-flag"></i> Captured</div>
    <div class="card-top">
      <div class="badges">
        {% if lab.difficulty == 'Easy' %}<span class="bg bg-e">Easy</span>
        {% elif lab.difficulty == 'Medium' %}<span class="bg bg-m">Medium</span>
        {% else %}<span class="bg bg-h">Hard</span>{% endif %}
        <span class="bg bg-p">{{ lab.points }} pts</span>
        <span class="bg bg-o">{{ lab.owasp }}</span>
      </div>
      <div class="health" id="hp-{{ lab.id }}" title="Checking..."></div>
    </div>
    <h3>{{ lab.name }}</h3>
    <div class="card-inf">
      <span><i class="fa-solid fa-crosshairs"></i> {{ lab.component }}</span>
      <span>{{ lab.cwe }}</span>
    </div>
    <p class="card-d">{{ lab.description }}</p>
    <div class="card-act">
      <a class="btn btn-r" href="http://localhost:{{ lab.vuln_port }}" target="_blank"><i class="fa-solid fa-skull-crossbones"></i> Exploit</a>
      <a class="btn btn-g" href="http://localhost:{{ lab.secure_port }}" target="_blank"><i class="fa-solid fa-shield-halved"></i> Secure</a>
      <button class="btn btn-o" onclick="showHints('{{ lab.id }}','{{ lab.name }}')"><i class="fa-solid fa-lightbulb"></i> Hints</button>
      <button class="btn btn-t" onclick="showQuiz('{{ lab.id }}','{{ lab.name }}')"><i class="fa-solid fa-circle-question"></i> Quiz</button>
      <button class="btn btn-p" onclick="showSandbox('{{ lab.id }}','{{ lab.name }}')"><i class="fa-solid fa-terminal"></i> Sandbox</button>
    </div>
  </div>
  {% endfor %}
</div>

<div class="ctf" id="ctf">
  <div class="ctf-hd">
    <i class="fa-solid fa-flag-checkered"></i>
    <div>
      <h2>Capture The Flag</h2>
      <p>Exploit each lab to discover the hidden flag, then submit it here.</p>
    </div>
  </div>
  <div class="ctf-row">
    <input class="ctf-in" id="flag-in" type="text" placeholder="FLAG{...}" autocomplete="off">
    <button class="ctf-btn" onclick="submitFlag()"><i class="fa-solid fa-paper-plane"></i> Submit</button>
  </div>
  <div id="flag-msg"></div>
  <div class="caps" id="caps"></div>
</div>

<div class="thry">
  <i class="fa-solid fa-book"></i>
  <div>
    <strong>SQL Injection &mdash; Theory</strong>
    <p style="color:var(--muted);font-size:.85em;margin-top:3px">In-depth theory: tautologies, UNION attacks, prepared statements.</p>
    <a class="btn btn-o" href="/sql-theory" style="margin-top:6px"><i class="fa-solid fa-arrow-right"></i> Read Theory</a>
  </div>
</div>

</main>

<!-- Hints Modal -->
<div class="mdl-bg" id="mdl" onclick="if(event.target===this)closeHints()">
  <div class="mdl">
    <div class="mdl-h">
      <h3 id="mdl-title">Hints</h3>
      <button onclick="closeHints()"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="mdl-b" id="mdl-body"></div>
    <div class="mdl-f">
      <button class="btn btn-o" onclick="closeHints()">Close</button>
      <button class="btn btn-a" id="unlock-btn" onclick="unlockHint()"><i class="fa-solid fa-lock-open"></i> Unlock Next</button>
    </div>
  </div>
</div>

<!-- Quiz Modal -->
<div class="mdl-bg" id="qz-mdl" onclick="if(event.target===this)closeQuiz()">
  <div class="mdl">
    <div class="mdl-h">
      <h3 id="qz-title">Quiz</h3>
      <button onclick="closeQuiz()"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="mdl-b" id="qz-body"></div>
    <div class="mdl-f">
      <button class="btn btn-o" onclick="closeQuiz()">Close</button>
      <button class="btn btn-a" id="qz-check" onclick="checkQ()"><i class="fa-solid fa-check"></i> Check Answer</button>
      <button class="btn btn-a" id="qz-next" onclick="nextQ()" style="display:none"><i class="fa-solid fa-arrow-right"></i> Next</button>
    </div>
  </div>
</div>

<!-- Sandbox Modal -->
<div class="mdl-bg" id="sb-mdl" onclick="if(event.target===this)closeSandbox()">
  <div class="mdl wide">
    <div class="mdl-h">
      <h3 id="sb-title">Sandbox</h3>
      <button onclick="closeSandbox()"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="mdl-b">
      <div class="sb-bar">
        <select class="sb-sel" id="sb-method" onchange="sbToggleBody()">
          <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
        </select>
        <input class="sb-path" id="sb-url" type="text" placeholder="/" spellcheck="false">
        <select class="sb-sel" id="sb-ct">
          <option value="application/x-www-form-urlencoded">form-urlencoded</option>
          <option value="application/json">JSON</option>
          <option value="text/plain">text/plain</option>
        </select>
      </div>
      <div class="sb-hint" id="sb-hint-text"></div>
      <div id="sb-body-wrap">
        <div class="sb-lbl">Request Body</div>
        <textarea class="sb-editor" id="sb-body" placeholder="key=value or JSON..." rows="4" spellcheck="false"></textarea>
      </div>
      <div class="sb-actions">
        <button class="btn btn-a" id="sb-exec" onclick="sbExec()"><i class="fa-solid fa-play"></i> Execute</button>
        <button class="btn btn-o" onclick="sbClear()"><i class="fa-solid fa-eraser"></i> Clear</button>
        <button class="btn btn-o" onclick="sbReset()"><i class="fa-solid fa-rotate-left"></i> Reset Defaults</button>
      </div>
      <div id="sb-resp-wrap" style="display:none">
        <div class="sb-resp">
          <div class="sb-resp-hdr">
            <span style="color:var(--muted)">Response</span>
            <span class="sb-st" id="sb-st">200</span>
            <div class="sb-tabs">
              <span class="sb-tab on" data-tab="body" onclick="sbTab('body')">Body</span>
              <span class="sb-tab" data-tab="headers" onclick="sbTab('headers')">Headers</span>
            </div>
          </div>
          <div class="sb-pane on" data-tab="body"><pre class="sb-out" id="sb-rbody"></pre></div>
          <div class="sb-pane" data-tab="headers"><pre class="sb-out" id="sb-hdrs"></pre></div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<footer>CYS LAB &mdash; Injection Security Lab &mdash; Educational Use Only &mdash; Run on isolated lab machine only</footer>

<script>
var LABS={{ labs|tojson }};
var TOTAL={{ total_points }};
var captured=[];
var currentHintLab='';
var filter='all';

/* ── Init ─────────────────────────────── */
function init(){
  fetch('/api/scoreboard').then(function(r){return r.json()}).then(function(d){
    captured=d.captured||[];
    updateUI();
  });
  checkHealth();
}

/* ── Update UI ────────────────────────── */
function updateUI(){
  var score=0;
  captured.forEach(function(id){
    var lab=LABS.find(function(l){return l.id===id});
    if(lab)score+=lab.points;
    var c=document.getElementById('c-'+id);
    if(c)c.classList.add('won');
  });
  var pct=Math.round(score/TOTAL*100);
  document.getElementById('h-labs').textContent=captured.length+'/'+LABS.length;
  document.getElementById('h-pts').textContent=score;
  document.getElementById('h-flags').textContent=captured.length;
  document.getElementById('ring-pct').textContent=pct+'%';
  var circ=2*Math.PI*30;
  document.getElementById('ring').style.strokeDashoffset=circ-(circ*pct/100);
  document.getElementById('s-done').textContent=captured.length+' / '+LABS.length;
  document.getElementById('s-pts').textContent=score+' / '+TOTAL;
  document.getElementById('bar-done').style.width=(captured.length/LABS.length*100)+'%';
  document.getElementById('bar-pts').style.width=(score/TOTAL*100)+'%';
  var el=document.getElementById('caps');
  el.innerHTML=captured.map(function(id){return '<span class="cap"><i class="fa-solid fa-flag"></i> '+id+'</span>'}).join('');
}

/* ── Health Check ─────────────────────── */
function checkHealth(){
  var up=0,total=LABS.length;
  var done=0;
  LABS.forEach(function(lab){
    var ctrl=new AbortController();
    var t=setTimeout(function(){ctrl.abort()},4000);
    fetch('http://localhost:'+lab.vuln_port+'/',{mode:'no-cors',signal:ctrl.signal})
      .then(function(){
        clearTimeout(t);
        var dot=document.getElementById('hp-'+lab.id);
        if(dot){dot.className='health up';dot.title='Online'}
        up++;
      })
      .catch(function(){
        clearTimeout(t);
        var dot=document.getElementById('hp-'+lab.id);
        if(dot){dot.className='health dn';dot.title='Offline'}
      })
      .finally(function(){
        done++;
        if(done===total){
          document.getElementById('s-up').textContent=up+'/'+total;
          document.getElementById('bar-up').style.width=(up/total*100)+'%';
        }
      });
  });
}

/* ── Filter / Search ──────────────────── */
function setFilter(f,el){
  filter=f;
  document.querySelectorAll('.pill').forEach(function(p){p.classList.remove('on')});
  el.classList.add('on');
  applyFilter();
}
function applyFilter(){
  var q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.card').forEach(function(c){
    var diff=c.getAttribute('data-diff');
    var name=c.getAttribute('data-name');
    var matchF=filter==='all'||diff===filter||(filter==='captured'&&c.classList.contains('won'));
    var matchQ=!q||name.indexOf(q)!==-1;
    c.style.display=(matchF&&matchQ)?'':'none';
  });
}
document.getElementById('search').addEventListener('input',applyFilter);
document.addEventListener('keydown',function(e){
  if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();document.getElementById('search').focus()}
});

/* ── Flag Submission ──────────────────── */
function submitFlag(){
  var inp=document.getElementById('flag-in');
  var flag=inp.value.trim();
  if(!flag)return;
  inp.disabled=true;
  fetch('/api/validate-flag',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({flag:flag})
  }).then(function(r){return r.json()}).then(function(d){
    var el=document.getElementById('flag-msg');
    if(d.valid){
      el.innerHTML='<span style="color:var(--green)"><i class="fa-solid fa-circle-check"></i> '+d.message+'</span>';
      inp.value='';
      captured=d.captured;
      updateUI();
      toast(d.message,'ok');
      confetti();
      document.getElementById('s-streak').textContent=d.lab;
    }else{
      el.innerHTML='<span style="color:var(--red)"><i class="fa-solid fa-circle-xmark"></i> '+d.message+'</span>';
      toast(d.message,'err');
    }
    inp.disabled=false;
    inp.focus();
  });
}
document.getElementById('flag-in').addEventListener('keydown',function(e){
  if(e.key==='Enter')submitFlag();
});

/* ── Hints ────────────────────────────── */
function showHints(id,name){
  currentHintLab=id;
  document.getElementById('mdl-title').textContent='Hints \u2014 '+name;
  fetch('/api/hints/'+id).then(function(r){return r.json()}).then(function(d){
    var html='';
    d.hints.forEach(function(h,i){
      var cls=i<d.unlocked?'hint open':'hint locked';
      html+='<div class="'+cls+'"><div class="hn">Hint '+(i+1)+'</div><div class="ht">'+h+'</div></div>';
    });
    document.getElementById('mdl-body').innerHTML=html;
    var btn=document.getElementById('unlock-btn');
    btn.style.display=d.unlocked>=d.hints.length?'none':'';
  });
  document.getElementById('mdl').classList.add('show');
}
function closeHints(){document.getElementById('mdl').classList.remove('show')}
function unlockHint(){
  fetch('/api/hints/'+currentHintLab+'/unlock',{method:'POST'}).then(function(r){return r.json()}).then(function(d){
    showHints(currentHintLab,document.getElementById('mdl-title').textContent.replace('Hints \u2014 ',''));
    toast('Hint '+(d.unlocked)+' unlocked!','ok');
  });
}

/* ── Quiz ─────────────────────────────── */
var qzLab='',qzData=[],qzIdx=0,qzAns=[],qzLocked=false;
function showQuiz(id,name){
  qzLab=id;
  document.getElementById('qz-title').textContent='Quiz \u2014 '+name;
  fetch('/api/quiz/'+id).then(function(r){return r.json()}).then(function(d){
    qzData=d.questions;qzIdx=0;qzAns=[];qzLocked=false;
    renderQ();
  });
  document.getElementById('qz-mdl').classList.add('show');
}
function closeQuiz(){document.getElementById('qz-mdl').classList.remove('show')}
function renderQ(){
  if(qzIdx>=qzData.length){showQResult();return}
  var q=qzData[qzIdx],html='';
  html+='<div class="quiz-prog">Question '+(qzIdx+1)+' / '+qzData.length+'<div class="quiz-dots">';
  for(var i=0;i<qzData.length;i++){
    var dc='quiz-dot';
    if(i===qzIdx)dc+=' cur';
    else if(i<qzAns.length&&qzAns[i]!=null)dc+=(qzAns[i]===qzData[i].ans?' ok':' no');
    html+='<span class="'+dc+'"></span>';
  }
  html+='</div></div><div class="quiz-q">'+q.q+'</div><div class="quiz-opts">';
  for(var j=0;j<q.opts.length;j++){
    html+='<div class="quiz-opt" onclick="pickQ('+j+')"><span class="qd"></span><span>'+q.opts[j]+'</span></div>';
  }
  html+='</div>';
  document.getElementById('qz-body').innerHTML=html;
  document.getElementById('qz-check').style.display='';
  document.getElementById('qz-next').style.display='none';
  qzLocked=false;
}
function pickQ(i){
  if(qzLocked)return;
  qzAns[qzIdx]=i;
  var opts=document.querySelectorAll('#qz-body .quiz-opt');
  opts.forEach(function(el,idx){el.classList.toggle('sel',idx===i)});
}
function checkQ(){
  if(qzAns[qzIdx]==null)return;
  qzLocked=true;
  var correct=qzData[qzIdx].ans;
  var opts=document.querySelectorAll('#qz-body .quiz-opt');
  opts.forEach(function(el,i){
    el.style.pointerEvents='none';
    if(i===correct)el.className='quiz-opt right';
    else if(i===qzAns[qzIdx])el.className='quiz-opt wrong';
  });
  document.getElementById('qz-check').style.display='none';
  document.getElementById('qz-next').style.display='';
}
function nextQ(){qzIdx++;renderQ()}
function showQResult(){
  var ok=0;
  for(var i=0;i<qzData.length;i++)if(qzAns[i]===qzData[i].ans)ok++;
  var pct=Math.round(ok/qzData.length*100);
  var cls=pct>=80?'pass':pct>=50?'mid':'fail';
  var col=pct>=80?'green':pct>=50?'yellow':'red';
  var icon=pct>=50?'circle-check':'circle-xmark';
  var msg=pct>=80?'Excellent understanding!':pct>=50?'Good effort \u2014 review missed topics.':'Review the lab material and try again.';
  document.getElementById('qz-body').innerHTML='<div class="quiz-res"><div class="big '+cls+'">'+ok+'/'+qzData.length+'</div><div style="color:var(--muted);margin:4px 0 10px">'+pct+'% correct</div><div style="color:var(--muted);font-size:.86em"><i class="fa-solid fa-'+icon+'" style="color:var(--'+col+')"></i> '+msg+'</div></div>';
  document.getElementById('qz-check').style.display='none';
  document.getElementById('qz-next').style.display='none';
  fetch('/api/quiz/'+qzLab+'/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answers:qzAns})});
}

/* ── Sandbox ──────────────────────────── */
var sbLab='';
var SB_DEFAULTS={{ sandbox_defaults|tojson }};
function showSandbox(id,name){
  sbLab=id;
  document.getElementById('sb-title').textContent='Sandbox \u2014 '+name;
  sbLoadDefaults();
  document.getElementById('sb-resp-wrap').style.display='none';
  document.getElementById('sb-mdl').classList.add('show');
}
function sbLoadDefaults(){
  var d=SB_DEFAULTS[sbLab]||{m:'GET',p:'/',ct:'',b:'',h:'Send a request to explore the lab.'};
  document.getElementById('sb-method').value=d.m;
  document.getElementById('sb-url').value=d.p;
  var ctSel=document.getElementById('sb-ct');
  for(var i=0;i<ctSel.options.length;i++){if(ctSel.options[i].value===d.ct){ctSel.selectedIndex=i;break}}
  document.getElementById('sb-body').value=d.b;
  document.getElementById('sb-hint-text').textContent=d.h;
  sbToggleBody();
}
function closeSandbox(){document.getElementById('sb-mdl').classList.remove('show')}
function sbToggleBody(){
  var m=document.getElementById('sb-method').value;
  document.getElementById('sb-body-wrap').style.display=(m==='POST'||m==='PUT'||m==='PATCH')?'':'none';
}
function sbExec(){
  var btn=document.getElementById('sb-exec');
  btn.disabled=true;btn.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Executing...';
  var payload={lab_id:sbLab,method:document.getElementById('sb-method').value,path:document.getElementById('sb-url').value,body:document.getElementById('sb-body').value,content_type:document.getElementById('sb-ct').value};
  fetch('/api/sandbox/execute',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)
  }).then(function(r){return r.json()}).then(function(d){
    btn.disabled=false;btn.innerHTML='<i class="fa-solid fa-play"></i> Execute';
    document.getElementById('sb-resp-wrap').style.display='';
    var sc=d.status||0;
    var el=document.getElementById('sb-st');
    el.textContent=sc;
    el.className='sb-st '+(sc>=200&&sc<300?'s2':sc>=300&&sc<400?'s3':sc>=400&&sc<500?'s4':'s5');
    var hdrs=d.headers||{};
    document.getElementById('sb-hdrs').textContent=Object.keys(hdrs).map(function(k){return k+': '+hdrs[k]}).join('\\n')||'(none)';
    var body=d.body||d.error||'(empty)';
    try{body=JSON.stringify(JSON.parse(body),null,2)}catch(e){}
    document.getElementById('sb-rbody').textContent=body;
    sbTab('body');
    toast('Response: '+sc,'ok');
  }).catch(function(e){
    btn.disabled=false;btn.innerHTML='<i class="fa-solid fa-play"></i> Execute';
    toast('Request failed: '+e.message,'err');
  });
}
function sbTab(t){
  document.querySelectorAll('.sb-tab').forEach(function(el){el.classList.toggle('on',el.dataset.tab===t)});
  document.querySelectorAll('.sb-pane').forEach(function(el){el.classList.toggle('on',el.dataset.tab===t)});
}
function sbClear(){
  document.getElementById('sb-body').value='';
  document.getElementById('sb-url').value='/';
  document.getElementById('sb-resp-wrap').style.display='none';
}
function sbReset(){sbLoadDefaults();document.getElementById('sb-resp-wrap').style.display='none'}

/* ── Toast ────────────────────────────── */
function toast(msg,type){
  var el=document.createElement('div');
  el.className='toast '+(type||'ok');
  el.innerHTML='<i class="fa-solid fa-'+(type==='ok'?'circle-check':'circle-xmark')+'"></i> '+msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(function(){el.style.opacity='0';el.style.transition='opacity .3s';setTimeout(function(){el.remove()},300)},3500);
}

/* ── Confetti ─────────────────────────── */
function confetti(){
  var colors=['#3fb950','#58a6ff','#d29922','#a371f7','#f85149'];
  for(var i=0;i<35;i++){
    var el=document.createElement('div');
    el.className='confetti';
    el.style.left=Math.random()*100+'vw';
    el.style.background=colors[i%colors.length];
    el.style.borderRadius=Math.random()>.5?'50%':'2px';
    el.style.setProperty('--dur',(1.2+Math.random()*1)+'s');
    el.style.animationDelay=(Math.random()*.4)+'s';
    el.style.width=(5+Math.random()*6)+'px';
    el.style.height=(5+Math.random()*6)+'px';
    document.body.appendChild(el);
    setTimeout(function(e){return function(){e.remove()}}(el),2500);
  }
}

init();
</script>
</body>
</html>"""

# ── SQL Theory ───────────────────────────────────────────────

_SQL_THEORY = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SQL Injection Theory</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0a0e14;color:#e6edf3;line-height:1.7}
.wrap{max-width:800px;margin:0 auto;padding:40px 24px}
h1{font-size:1.6em;color:#58a6ff;margin-bottom:8px}
h2{font-size:1.15em;color:#e6edf3;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #2a3040}
p{margin-bottom:12px;color:#8b949e}
pre{background:#141921;border:1px solid #2a3040;border-radius:8px;padding:16px;overflow-x:auto;font-size:.88em;color:#3fb950;margin:12px 0}
.note{background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.2);border-radius:8px;padding:14px;margin:16px 0;color:#58a6ff;font-size:.9em}
ul{padding-left:20px;margin:10px 0;color:#8b949e}
li{margin-bottom:6px}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.back{display:inline-flex;align-items:center;gap:6px;margin-top:20px;padding:8px 16px;background:#141921;border:1px solid #2a3040;border-radius:6px;color:#8b949e;font-size:.85em}
.back:hover{border-color:#58a6ff;color:#58a6ff;text-decoration:none}
</style></head>
<body>
<div class="wrap">
<h1><i class="fa-solid fa-database"></i> SQL Injection &mdash; Theory</h1>
<div class="note">
<i class="fa-solid fa-flask"></i> &nbsp;See the practical lab on ports
<strong>5021</strong> (vulnerable) and <strong>5022</strong> (secure).
</div>
<h2>Definition</h2>
<p>SQL Injection occurs when user input is included in a SQL query without proper
parameterization, allowing an attacker to alter the query logic.</p>
<h2>Vulnerable Example</h2>
<pre># VULNERABLE &mdash; string concatenation
query = "SELECT * FROM users WHERE username='" + username + "'"
# username = "admin'--"  &rarr;  bypasses password check</pre>
<h2>Secure Implementation</h2>
<pre># SECURE &mdash; parameterized query
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))</pre>
<h2>Prevention</h2>
<ul>
<li>Prepared statements / parameterized queries</li>
<li>ORM (SQLAlchemy, Django ORM)</li>
<li>Input validation &amp; type checking</li>
<li>Least-privilege database accounts</li>
</ul>
<a class="back" href="/"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
</div>
</body></html>"""

# ── Routes ───────────────────────────────────────────────────


@app.route("/")
def index() -> Any:
    return render_template_string(
        _TEMPLATE,
        labs=_LABS,
        total_points=_TOTAL_POINTS,
        sandbox_defaults=_SANDBOX_DEFAULTS,
    )


@app.route("/sql-theory")
def sql_theory() -> Any:
    return _SQL_THEORY


@app.route("/api/labs")
def api_labs() -> Any:
    return jsonify({"labs": _LABS, "total_points": _TOTAL_POINTS})


@app.route("/api/health")
def api_health() -> Any:
    results: dict[str, bool] = {}
    for lab_id, svc in _SVC_NAMES.items():
        try:
            s = socket.create_connection((svc, 5000), timeout=1)
            s.close()
            results[lab_id] = True
        except OSError:
            results[lab_id] = False
    return jsonify(results)


# ── CTF Flag System ──────────────────────────────────────────

_FLAGS: dict[str, str] = {
    "xss": "FLAG{xss_stored_camera_hijack}",
    "command": "FLAG{cmd_rce_system_recon}",
    "ssti": "FLAG{ssti_rce_via_mro_chain}",
    "nosql": "FLAG{nosql_regex_blind_extract}",
    "ldap": "FLAG{ldap_filter_bypass_all}",
    "xpath": "FLAG{xpath_union_admin_extract}",
    "csv": "FLAG{csv_formula_exfiltration}",
    "log": "FLAG{log_injection_audit_forge}",
    "header": "FLAG{header_crlf_session_fixation}",
    "expression": "FLAG{expr_eval_rce_full_access}",
    "sql": "FLAG{sqli_union_credential_dump}",
    "ssrf": "FLAG{ssrf_internal_service_access}",
    "idor": "FLAG{idor_broken_access_control}",
    "pathtraversal": "FLAG{path_traversal_file_read}",
}
_captured: dict[str, bool] = {}


@app.route("/api/validate-flag", methods=["POST"])
def validate_flag() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    flag = str(data.get("flag", "")).strip()
    if not flag:
        return jsonify({"valid": False, "message": "Flag requis"}), 400
    for lab_id, correct in _FLAGS.items():
        if flag == correct:
            already = lab_id in _captured
            _captured[lab_id] = True
            pts = next((l["points"] for l in _LABS if l["id"] == lab_id), 0)
            score = sum(l["points"] for l in _LABS if l["id"] in _captured)
            msg = f"Flag {lab_id} (+{pts} pts)" if not already else f"Flag {lab_id} already captured"
            return jsonify({
                "valid": True, "lab": lab_id, "points": pts,
                "message": msg,
                "captured": list(_captured.keys()),
                "score": score,
            })
    return jsonify({"valid": False, "message": "Invalid flag"}), 400


@app.route("/api/scoreboard")
def scoreboard() -> Any:
    score = sum(l["points"] for l in _LABS if l["id"] in _captured)
    return jsonify({
        "captured": list(_captured.keys()),
        "score": score,
        "total": _TOTAL_POINTS,
        "progress": f"{len(_captured)}/{len(_FLAGS)}",
    })


# ── Hints System ─────────────────────────────────────────────


@app.route("/api/hints/<lab_id>")
def get_hints(lab_id: str) -> Any:
    hints = _HINTS.get(lab_id)
    if not hints:
        return jsonify({"error": "Lab not found"}), 404
    unlocked = _hints_unlocked.get(lab_id, 0)
    return jsonify({"lab": lab_id, "hints": hints, "unlocked": unlocked, "total": len(hints)})


@app.route("/api/hints/<lab_id>/unlock", methods=["POST"])
def unlock_hint(lab_id: str) -> Any:
    hints = _HINTS.get(lab_id)
    if not hints:
        return jsonify({"error": "Lab not found"}), 404
    current = _hints_unlocked.get(lab_id, 0)
    if current < len(hints):
        _hints_unlocked[lab_id] = current + 1
    return jsonify({"lab": lab_id, "unlocked": _hints_unlocked[lab_id], "total": len(hints)})


# ── Quiz System ──────────────────────────────────────────────


@app.route("/api/quiz/<lab_id>")
def get_quiz(lab_id: str) -> Any:
    questions = _QUIZZES.get(lab_id)
    if not questions:
        return jsonify({"error": "Lab not found"}), 404
    return jsonify({"lab": lab_id, "questions": questions, "total": len(questions)})


@app.route("/api/quiz/<lab_id>/check", methods=["POST"])
def check_quiz(lab_id: str) -> Any:
    questions = _QUIZZES.get(lab_id)
    if not questions:
        return jsonify({"error": "Lab not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    answers = data.get("answers", [])
    correct = 0
    results = []
    for i, q in enumerate(questions):
        user_ans = answers[i] if i < len(answers) else -1
        is_correct = user_ans == q["ans"]
        if is_correct:
            correct += 1
        results.append({"correct": is_correct, "answer": q["ans"]})
    _quiz_scores[lab_id] = {"correct": correct, "total": len(questions)}
    return jsonify({"lab": lab_id, "correct": correct, "total": len(questions), "results": results})


# ── Sandbox Proxy ────────────────────────────────────────────


@app.route("/api/sandbox/execute", methods=["POST"])
def sandbox_execute() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    lab_id = str(data.get("lab_id", ""))
    svc = _SVC_NAMES.get(lab_id)
    if not svc:
        return jsonify({"status": 0, "error": "Unknown lab"}), 404

    method = str(data.get("method", "GET")).upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        return jsonify({"status": 0, "error": "Invalid method"}), 400

    path = str(data.get("path", "/"))
    if not path.startswith("/"):
        path = "/" + path
    body = str(data.get("body", ""))
    ct = str(data.get("content_type", "application/x-www-form-urlencoded"))

    url = f"http://{svc}:5000{path}"
    try:
        req = urllib.request.Request(url, method=method)
        if method in ("POST", "PUT", "PATCH") and body:
            req.data = body.encode()
            req.add_header("Content-Type", ct)
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.status
            headers = {k: v for k, v in resp.headers.items()}
            rbody = resp.read().decode("utf-8", errors="replace")[:50000]
        return jsonify({"status": status, "headers": headers, "body": rbody})
    except urllib.error.HTTPError as e:
        rbody = e.read().decode("utf-8", errors="replace")[:50000]
        return jsonify({"status": e.code, "headers": {k: v for k, v in e.headers.items()}, "body": rbody})
    except Exception as e:
        return jsonify({"status": 0, "error": str(e)})


@app.route("/api/reset", methods=["POST"])
def reset_progress() -> Any:
    _captured.clear()
    _hints_unlocked.clear()
    _quiz_scores.clear()
    return jsonify({"status": "reset", "score": 0})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
