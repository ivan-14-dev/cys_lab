"""
XSS Lab — Vulnerable Version
<i class="fa-solid fa-triangle-exclamation"></i> INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY

Demonstrates: Unescaped HTML output (CWE-79, OWASP A03:2021)
"""
from __future__ import annotations

import os
from typing import Any

from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "lab-xss-vuln-key"

# In-memory comment store (lab data only)
_comments: list[dict[str, str]] = []

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<meta charset="UTF-8">
<title>XSS Lab — Vulnerable</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #dc3545; color: white; padding: 10px; border-radius: 4px; }}
.comment {{ border: 1px solid #ddd; margin: 8px 0; padding: 12px; border-radius: 4px; }}
.comment-name {{ font-weight: bold; color: #333; }}
.comment-body {{ margin-top: 6px; }}
form {{ margin: 20px 0; }}
input, textarea {{ width: 100%; padding: 8px; margin: 4px 0 12px; box-sizing: border-box; }}
button {{ background: #dc3545; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
.ctf-box {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; margin: 16px 0; border-radius: 4px; }}
</style>
</head>
<body>
<div class="lab-banner"><i class="fa-solid fa-triangle-exclamation"></i> XSS LAB — VULNERABLE VERSION — EDUCATIONAL USE ONLY</div>
<h1>Community Comments</h1>

<div class="ctf-box">
<strong><i class="fa-solid fa-crosshairs"></i> MISSION:</strong> Show that the application interprets your input as code,
not as text. Payload hint: <code>&lt;img src=x onerror="document.title='XSS_PROOF'"&gt;</code>
<br><strong>Objective:</strong> Make the page title change to <code>XSS_PROOF</code>.
</div>

<form method="POST" action="/comment">
  <label>Name:</label>
  <input type="text" name="name" placeholder="Your name" required>
  <label>Comment:</label>
  <textarea name="comment" rows="4" placeholder="Write your comment..." required></textarea>
  <button type="submit">Post Comment</button>
</form>

<h2>Comments ({count})</h2>
{comments_html}

<hr>
<p><a href="/clear">Clear all comments</a> | <a href="/demo">View demo payloads</a></p>
</body>
</html>"""

_DEMO_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>XSS Demo Payloads</title>
<style>body {{ font-family: monospace; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
code {{ background: #f4f4f4; padding: 2px 6px; display: block; margin: 4px 0; }}
</style></head>
<body>
<h1>XSS Demo Payloads (Lab Only)</h1>
<p>These payloads demonstrate XSS concepts. Use only in this lab.</p>
<h2>Payload 1 — DOM Manipulation (title change)</h2>
<code>&lt;img src=x onerror="document.title='XSS_PROOF'"&gt;</code>
<h2>Payload 2 — Styled HTML Injection</h2>
<code>&lt;b style="color:red;font-size:24px"&gt;INJECTION_DETECTED&lt;/b&gt;</code>
<h2>Payload 3 — Alert Box</h2>
<code>&lt;script&gt;alert('Lab XSS — Score: 10 points')&lt;/script&gt;</code>
<h2>What you observe</h2>
<p>In the vulnerable version: the browser <strong>executes</strong> this as code.</p>
<p>In the secure version: this is displayed as <strong>plain text</strong>.</p>
<a href="/">Back to lab</a>
</body>
</html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    """Render the comment board with unescaped output."""
    comments_html = _build_comments_html_vulnerable()
    page = _PAGE_TEMPLATE.format(
        count=len(_comments),
        comments_html=comments_html,
    )
    return page


@app.route("/comment", methods=["POST"])
def add_comment() -> Any:
    """Accept a comment and store it — NO sanitization."""
    name = request.form.get("name", "")
    comment = request.form.get("comment", "")
    # VULNERABILITY: storing raw user input, rendered without escaping
    _comments.append({"name": name, "comment": comment})
    return index()


@app.route("/api/comments", methods=["GET"])
def api_comments() -> Any:
    """Return comments as JSON for automated testing."""
    from flask import jsonify
    return jsonify(_comments)


@app.route("/api/comment", methods=["POST"])
def api_add_comment() -> Any:
    """Add comment via JSON API."""
    from flask import jsonify, request as req
    data = req.get_json(force=True, silent=True) or {}
    name = str(data.get("name", ""))
    comment = str(data.get("comment", ""))
    _comments.append({"name": name, "comment": comment})
    return jsonify({"status": "ok", "total": len(_comments)})


@app.route("/api/last", methods=["GET"])
def api_last() -> Any:
    """Return the last stored comment for test verification."""
    from flask import jsonify
    if _comments:
        return jsonify(_comments[-1])
    return jsonify({}), 404


@app.route("/clear")
def clear() -> Any:
    """Clear all comments (lab utility)."""
    _comments.clear()
    from flask import redirect
    return redirect("/")


@app.route("/demo")
def demo() -> Any:
    """Show demo payload hints."""
    return _DEMO_PAGE


def _build_comments_html_vulnerable() -> str:
    """Build HTML with RAW (unescaped) user content — intentionally vulnerable."""
    if not _comments:
        return "<p><em>No comments yet. Be the first!</em></p>"
    parts = []
    for c in _comments:
        # VULNERABILITY: name and comment rendered as raw HTML — no escaping
        parts.append(
            f'<div class="comment">'
            f'<div class="comment-name">{c["name"]}</div>'
            f'<div class="comment-body">{c["comment"]}</div>'
            f'</div>'
        )
    return "\n".join(parts)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
