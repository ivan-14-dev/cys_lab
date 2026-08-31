"""
CSV Injection Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: Formula injection in CSV exports
CWE-1236, OWASP A03:2021
"""
from __future__ import annotations

import csv
import io
import os
from typing import Any

from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)
app.secret_key = "lab-csv-vuln-key"

_ENTRIES: list[dict[str, str]] = [
    {"name": "Alice Martin", "email": "alice@lab.local", "company": "LabCorp"},
    {"name": "Bob Test", "email": "bob@lab.local", "company": "TestInc"},
]

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>CSV Injection Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 250px; }}
button {{ background: #dc3545; color: white; padding: 8px 16px; border: none; cursor: pointer; margin: 4px; }}
.btn-green {{ background: #28a745; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> CSV INJECTION LAB — VULNERABLE — EDUCATIONAL USE ONLY</div>
<h1>Contact Export</h1>
<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Add an entry with a spreadsheet formula in the Name field.
<br>Hint: Name = <code>=SUM(1+1)*10</code> or <code>+LAB_INJECTION_DETECTED</code>
<br><strong>Objective:</strong> Export CSV and verify the formula appears unescaped.
</div>

<form method="POST" action="/add">
  <input type="text" name="name" placeholder="Name">
  <input type="text" name="email" placeholder="Email">
  <input type="text" name="company" placeholder="Company">
  <button type="submit">Add Entry</button>
  <a href="/export"><button type="button" class="btn-green">Export CSV</button></a>
</form>

<table>
<tr><th>Name</th><th>Email</th><th>Company</th></tr>
{rows}
</table>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    rows = "".join(
        f"<tr><td>{e['name']}</td><td>{e['email']}</td><td>{e['company']}</td></tr>"
        for e in _ENTRIES
    )
    return _PAGE.format(rows=rows)


@app.route("/add", methods=["POST"])
def add_entry() -> Any:
    # VULNERABLE: raw values stored and exported without sanitization
    _ENTRIES.append({
        "name": request.form.get("name", ""),
        "email": request.form.get("email", ""),
        "company": request.form.get("company", ""),
    })
    return redirect("/")


@app.route("/export")
def export_csv() -> Any:
    """VULNERABLE: CSV written with raw values — formulas not sanitized."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "Company"])
    for entry in _ENTRIES:
        # VULNERABILITY: values not escaped — formula cells remain active
        writer.writerow([entry["name"], entry["email"], entry["company"]])
    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=contacts_vulnerable.csv"},
    )


@app.route("/api/add", methods=["POST"])
def api_add() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    entry = {
        "name": str(data.get("name", "")),
        "email": str(data.get("email", "")),
        "company": str(data.get("company", "")),
    }
    _ENTRIES.append(entry)
    return jsonify({"status": "ok", "entry": entry})


@app.route("/api/entries")
def api_entries() -> Any:
    return jsonify(_ENTRIES)


@app.route("/api/csv")
def api_csv() -> Any:
    """Returns CSV content as string for testing."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "Company"])
    for entry in _ENTRIES:
        writer.writerow([entry["name"], entry["email"], entry["company"]])
    return jsonify({"csv": output.getvalue()})


@app.route("/reset")
def reset() -> Any:
    _ENTRIES.clear()
    _ENTRIES.extend([
        {"name": "Alice Martin", "email": "alice@lab.local", "company": "LabCorp"},
        {"name": "Bob Test", "email": "bob@lab.local", "company": "TestInc"},
    ])
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
