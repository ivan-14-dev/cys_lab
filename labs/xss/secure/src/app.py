"""
XSS Lab — Secure Version
<i class="fa-solid fa-circle-check"></i> SECURE IMPLEMENTATION — demonstrates proper output encoding

Defenses applied:
- Jinja2 auto-escaping (enabled by default)
- Content-Security-Policy header
- Input validation
"""
from __future__ import annotations

import os
import re
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template_string, request

app = Flask(__name__)
app.secret_key = "lab-xss-secure-key"

_comments: list[dict[str, str]] = []

_MAX_NAME_LEN = 64
_MAX_COMMENT_LEN = 500
_NAME_PATTERN = re.compile(r"^[\w\s\-'.]{1,64}$")

_CSP = (
    "default-src 'self'; "
    "script-src 'none'; "
    "object-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:;"
)

# Jinja2 auto-escaping is ON by default — {{ var }} encodes HTML entities
_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<meta charset="UTF-8">
<title>XSS Lab — Secure</title>
<style>
body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
.lab-banner { background: #28a745; color: white; padding: 10px; border-radius: 4px; }
.comment { border: 1px solid #ddd; margin: 8px 0; padding: 12px; border-radius: 4px; }
.comment-name { font-weight: bold; color: #333; }
.comment-body { margin-top: 6px; }
form { margin: 20px 0; }
input, textarea { width: 100%; padding: 8px; margin: 4px 0 12px; box-sizing: border-box; }
button { background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }
.defense-box { background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; border-radius: 4px; }
.error { color: #dc3545; background: #f8d7da; padding: 8px; border-radius: 4px; }
</style>
</head>
<body>
<div class="lab-banner"><i class="fa-solid fa-circle-check"></i> XSS LAB — SECURE VERSION — Output Encoding Applied</div>
<h1>Community Comments</h1>

<div class="defense-box">
<strong><i class="fa-solid fa-shield-halved"></i> Defenses active:</strong>
Content-Security-Policy (script-src: none) |
Jinja2 auto-escaping |
Input validation
<br><small>Try submitting the same XSS payloads — they will be displayed as text, not executed.</small>
</div>

{% if error %}
<p class="error">{{ error }}</p>
{% endif %}

<form method="POST" action="/comment">
  <label>Name:</label>
  <input type="text" name="name" placeholder="Your name (letters, spaces, hyphens)"
         maxlength="64" required>
  <label>Comment:</label>
  <textarea name="comment" rows="4" maxlength="500"
            placeholder="Write your comment..." required></textarea>
  <button type="submit">Post Comment</button>
</form>

<h2>Comments ({{ comments|length }})</h2>
{% for c in comments %}
<div class="comment">
  <div class="comment-name">{{ c.name }}</div>
  <div class="comment-body">{{ c.comment }}</div>
</div>
{% else %}
<p><em>No comments yet. Be the first!</em></p>
{% endfor %}

<hr>
<p><a href="/clear">Clear all comments</a></p>
<p><strong>Source proof:</strong> View page source to see &amp;lt;script&amp;gt; is encoded, not executed.</p>
</body>
</html>"""


def _make_response(html: str) -> Response:
    """Attach security headers to every response."""
    resp = Response(html, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.route("/", methods=["GET"])
def index() -> Any:
    html = render_template_string(_TEMPLATE, comments=_comments, error=None)
    return _make_response(html)


@app.route("/comment", methods=["POST"])
def add_comment() -> Any:
    """Validate and safely store a comment."""
    name = request.form.get("name", "").strip()
    comment = request.form.get("comment", "").strip()

    error = _validate_input(name, comment)
    if error:
        html = render_template_string(_TEMPLATE, comments=_comments, error=error)
        return _make_response(html), 400

    _comments.append({"name": name, "comment": comment})
    html = render_template_string(_TEMPLATE, comments=_comments, error=None)
    return _make_response(html)


@app.route("/api/comment", methods=["POST"])
def api_add_comment() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    name = str(data.get("name", "")).strip()
    comment = str(data.get("comment", "")).strip()
    error = _validate_input(name, comment)
    if error:
        return jsonify({"error": error}), 400
    _comments.append({"name": name, "comment": comment})
    return jsonify({"status": "ok", "total": len(_comments)})


@app.route("/api/last", methods=["GET"])
def api_last() -> Any:
    if _comments:
        return jsonify(_comments[-1])
    return jsonify({}), 404


@app.route("/api/comments", methods=["GET"])
def api_comments() -> Any:
    return jsonify(_comments)


@app.route("/clear")
def clear() -> Any:
    _comments.clear()
    return redirect("/")


def _validate_input(name: str, comment: str) -> str | None:
    """Validate input — returns error message or None if valid."""
    if not name or not comment:
        return "Name and comment are required."
    if len(name) > _MAX_NAME_LEN:
        return f"Name too long (max {_MAX_NAME_LEN} chars)."
    if len(comment) > _MAX_COMMENT_LEN:
        return f"Comment too long (max {_MAX_COMMENT_LEN} chars)."
    if not _NAME_PATTERN.match(name):
        return "Name contains invalid characters."
    return None


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
