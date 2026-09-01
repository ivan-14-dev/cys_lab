"""SSRF Lab — Secure | CWE-918 | OWASP A10:2021"""
from __future__ import annotations
import os
from typing import Any
from urllib.parse import urlparse
from flask import Flask, jsonify, request
import requests as http_client
import ipaddress

app = Flask(__name__)
app.secret_key = "lab-ssrf-sec"

_ALLOWED_HOSTS = {"example.com", "httpbin.org", "api.github.com"}

PAGE = '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>SSRF Lab — Secure</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em}.bn.s{background:#238636}.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:monospace}.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}.btg{background:#238636;color:#fff}.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #3fb950;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}pre.out{background:#0d1117;color:#3fb950;border:1px solid #30363d;border-radius:5px;padding:14px;font-size:.8em;line-height:1.5;white-space:pre-wrap;max-height:400px;overflow-y:auto;margin-top:10px}</style></head><body><div class="bn s"><i class="fa-solid fa-shield-halved"></i> SSRF — SÉCURISÉ <span>| CWE-918 | OWASP A10:2021</span></div><div class="ctr"><h1>URL Preview Service (Sécurisé)</h1><div class="mt"><span class="bge bgrn">Sécurisé</span><span class="bge bcwe">CWE-918</span></div><div class="cd"><h2 style="font-size:.97em;color:#3fb950;margin-bottom:8px">URL Fetcher — Domaines autorisés uniquement</h2><div class="fg"><label>URL (example.com, httpbin.org, api.github.com)</label><input id="fu" value="http://example.com"></div><button class="btn btg" onclick="doFetch()"><i class="fa-solid fa-globe"></i> Fetch</button></div><div class="cd"><h2 style="font-size:.97em;color:#3fb950;margin-bottom:8px">Protection appliquée</h2><div class="co">parsed = urlparse(url)\nif parsed.hostname not in _ALLOWED_HOSTS:\n    return "Domaine non autorisé", 403\nif _is_private_ip(parsed.hostname):\n    return "IP privée bloquée", 403</div><div class="bx s"><i class="fa-solid fa-check-circle"></i> Allowlist stricte + blocage IP privées + validation URL.</div></div><pre id="out" class="out"></pre></div><script>function doFetch(){var u=document.getElementById("fu").value;if(!u)return;document.getElementById("out").textContent="Fetching...";fetch("/api/fetch?url="+encodeURIComponent(u)).then(r=>r.json()).then(d=>{document.getElementById("out").textContent=JSON.stringify(d,null,2)}).catch(e=>{document.getElementById("out").textContent="Erreur: "+e})}</script></body></html>'


def _is_private_ip(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False


@app.route("/")
def index() -> Any:
    return PAGE


@app.route("/api/fetch")
def api_fetch() -> Any:
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        parsed = urlparse(url)
    except Exception:
        return jsonify({"error": "Invalid URL", "blocked": True}), 400
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "Only http/https allowed", "blocked": True}), 403
    if not parsed.hostname:
        return jsonify({"error": "No hostname", "blocked": True}), 400
    if parsed.hostname not in _ALLOWED_HOSTS:
        return jsonify({"error": f"Domain '{parsed.hostname}' not in allowlist", "blocked": True, "allowed": list(_ALLOWED_HOSTS)}), 403
    if _is_private_ip(parsed.hostname):
        return jsonify({"error": "Private IP blocked", "blocked": True}), 403
    try:
        resp = http_client.get(url, timeout=5, allow_redirects=False)
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:2000]
        return jsonify({"url": url, "status": resp.status_code, "body": body, "blocked": False})
    except Exception as e:
        return jsonify({"url": url, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
