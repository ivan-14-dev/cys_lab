"""
XSS Lab — Secure Version
CWE-79 | OWASP A03:2021
"""
from __future__ import annotations
import os, re
from typing import Any
from flask import Flask, Response, jsonify, redirect, request
from markupsafe import escape

app = Flask(__name__)
app.secret_key = "lab-xss-secure-key"
_comments: list[dict[str, str]] = []
_NAME_RE = re.compile(r"^[\w\s\-'.,!?]{1,64}$")
_CSP = "default-src 'self'; script-src 'none'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"

PAGE = """ + repr(xss_secure) + """

def _make_resp(html: str, status: int = 200) -> Response:
    r = Response(html, mimetype="text/html", status=status)
    r.headers["Content-Security-Policy"] = _CSP
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    return r

@app.route("/")
def index() -> Any:
    return _make_resp(PAGE)

@app.route("/api/comment", methods=["POST"])
def api_add() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    name = str(data.get("name", "")).strip()
    comment = str(data.get("comment", "")).strip()
    if not name or not comment:
        return jsonify({"error": "champs requis"}), 400
    if not _NAME_RE.match(name):
        return jsonify({"error": "Nom contient des caractères invalides"}), 400
    if len(comment) > 500:
        return jsonify({"error": "Commentaire trop long"}), 400
    _comments.append({"name": name, "comment": comment})
    return jsonify({"status": "ok", "total": len(_comments)})

@app.route("/api/comments")
def api_comments() -> Any:
    return jsonify(_comments)

@app.route("/api/last")
def api_last() -> Any:
    if _comments: return jsonify(_comments[-1])
    return jsonify({}), 404

@app.route("/clear")
def clear() -> Any:
    _comments.clear()
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
