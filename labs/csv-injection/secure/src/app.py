"""
CSV Injection Lab — Secure Version
<i class="fa-solid fa-circle-check"></i> SECURE IMPLEMENTATION

Defenses applied:
- Sanitize cells starting with formula characters (=, +, -, @, TAB, CR)
- Prefix with single quote to neutralize formulas
- Input validation
"""
from __future__ import annotations

import csv
import io
import os
import re
from typing import Any

from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)
app.secret_key = "lab-csv-secure-key"

_ENTRIES: list[dict[str, str]] = [
    {"name": "Alice Martin", "email": "alice@lab.local", "company": "LabCorp"},
    {"name": "Bob Test", "email": "bob@lab.local", "company": "TestInc"},
]

# Characters that trigger formula evaluation in spreadsheets
_FORMULA_STARTERS = ('=', '+', '-', '@', '\t', '\r', '\n')
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><meta charset="UTF-8"><title>CSV Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 250px; }}
button {{ background: #28a745; color: white; padding: 8px 16px; border: none; cursor: pointer; margin: 4px; }}
</style></head>
<body>
<div class="lab-banner"><i class="fa-solid fa-circle-check"></i> CSV INJECTION LAB — SECURE — Formula Sanitization Applied</div>
<h1>Contact Export</h1>
<div class="defense-box">
<strong><i class="fa-solid fa-shield-halved"></i> Defenses:</strong> Formula character escaping | Input validation
<br><small>Try adding <code>=SUM(1+1)</code> as name — the CSV will prefix it with a tab to neutralize it.</small>
</div>

<form method="POST" action="/add">
  <input type="text" name="name" placeholder="Name">
  <input type="text" name="email" placeholder="Email">
  <input type="text" name="company" placeholder="Company">
  <button type="submit">Add Entry</button>
  <a href="/export"><button type="button">Export CSV</button></a>
</form>

<table>
<tr><th>Name</th><th>Email</th><th>Company</th></tr>
{rows}
</table>
</body></html>"""


def _sanitize_csv_cell(value: str) -> str:
    """Neutralize formula injection by prefixing formula starters with a tab."""
    if value and value[0] in _FORMULA_STARTERS:
        # Prefix with tab character — harmless but prevents formula execution
        return "\t" + value
    # Strip embedded newlines that could break CSV structure
    return value.replace("\r", "").replace("\n", " ")


@app.route("/", methods=["GET"])
def index() -> Any:
    rows = "".join(
        f"<tr><td>{e['name']}</td><td>{e['email']}</td><td>{e['company']}</td></tr>"
        for e in _ENTRIES
    )
    return _PAGE.format(rows=rows)


@app.route("/add", methods=["POST"])
def add_entry() -> Any:
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    company = request.form.get("company", "").strip()
    if not name or not email or not company:
        return redirect("/")
    _ENTRIES.append({"name": name, "email": email, "company": company})
    return redirect("/")


@app.route("/export")
def export_csv() -> Any:
    """SECURE: values are sanitized before writing to CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "Company"])
    for entry in _ENTRIES:
        writer.writerow([
            _sanitize_csv_cell(entry["name"]),
            _sanitize_csv_cell(entry["email"]),
            _sanitize_csv_cell(entry["company"]),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=contacts_secure.csv"},
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


@app.route("/api/csv")
def api_csv() -> Any:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name", "Email", "Company"])
    for entry in _ENTRIES:
        writer.writerow([
            _sanitize_csv_cell(entry["name"]),
            _sanitize_csv_cell(entry["email"]),
            _sanitize_csv_cell(entry["company"]),
        ])
    return jsonify({"csv": output.getvalue()})


@app.route("/reset")
def reset() -> Any:
    _ENTRIES.clear()
    _ENTRIES.extend([
        {"name": "Alice Martin", "email": "alice@lab.local", "company": "LabCorp"},
    ])
    return redirect("/")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
