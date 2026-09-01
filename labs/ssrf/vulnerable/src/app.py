"""SSRF Lab — Vulnerable | CWE-918 | OWASP A10:2021
INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY
"""
from __future__ import annotations
import os
from typing import Any
from flask import Flask, jsonify, request
import requests as http_client

app = Flask(__name__)
app.secret_key = "lab-ssrf-vuln"

_INTERNAL_SECRET = os.environ.get("LAB_FLAG", "FLAG{ssrf_internal_service_access}")

PAGE = '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>SSRF Lab</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em}.bn.v{background:#da3633}.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}h2{font-size:.97em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.bo{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.br{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}.tb{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.87em;border-bottom:2px solid transparent;margin-bottom:-2px}.tb.a{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tp{display:none}.tp.a{display:block}.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:monospace}.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}.btr{background:#da3633;color:#fff}.btg{background:#238636;color:#fff}.btgr{background:#21262d;border:1px solid #30363d;color:#e6edf3}.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}.co.g{border-left-color:#3fb950}.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}.bx.d{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bx.w{background:#3d1f00;border:1px solid #d29922;color:#d29922}.bx.i{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:660px){.g2{grid-template-columns:1fr}}.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px;margin-bottom:7px;cursor:pointer}.pl:hover{border-color:#58a6ff}.pl .lb{font-size:.74em;color:#58a6ff;font-weight:700;margin-bottom:2px}.pl .pc{font-family:monospace;font-size:.77em;margin-bottom:3px;word-break:break-all}.pl .pd{font-size:.76em;color:#8b949e}pre.out{background:#0d1117;color:#3fb950;border:1px solid #30363d;border-radius:5px;padding:14px;font-size:.8em;line-height:1.5;white-space:pre-wrap;max-height:400px;overflow-y:auto;margin-top:10px}.pl.adv{border:1px solid #da3633}.pl.adv .lb{color:#f85149}</style></head><body><div class="bn v"><i class="fa-solid fa-triangle-exclamation"></i> SSRF — VULNÉRABLE <span>| Server-Side Request Forgery | CWE-918 | OWASP A10:2021 | Sécurisé : localhost:5024</span></div><div class="ctr"><h1>URL Preview Service</h1><div class="mt"><span class="bge br">Vulnérable</span><span class="bge bcwe">CWE-918</span><span class="bge bo">OWASP A10:2021</span></div><div class="tabs"><button class="tb a" onclick="st(\'demo\',this)">Demo</button><button class="tb" onclick="st(\'theory\',this)">Théorie</button><button class="tb" onclick="st(\'code\',this)">Code</button><button class="tb" onclick="st(\'fix\',this)">Fix</button></div><div id="t-demo" class="tp a"><div class="cd"><h2>URL Fetcher</h2><div class="fg"><label>URL à récupérer</label><input id="fu" value="http://example.com" placeholder="http://..."></div><button class="btn btr" onclick="doFetch()"><i class="fa-solid fa-globe"></i> Fetch</button><button class="btn btgr" onclick="document.getElementById(\'out\').textContent=\'\'">Clear</button></div><h2>Payloads</h2><div class="g2"><div><div class="pl" onclick="f(\'http://example.com\')"><div class="lb">Payload 1 — Normal</div><div class="pc">http://example.com</div><div class="pd">Requête légitime vers un site externe.</div></div><div class="pl" onclick="f(\'http://localhost:5000/internal/metadata\')"><div class="lb">Payload 2 — Accès métadonnées</div><div class="pc">http://localhost:5000/internal/metadata</div><div class="pd">Accède au endpoint interne du serveur.</div></div><div class="pl" onclick="f(\'http://127.0.0.1:5000/internal/metadata\')"><div class="lb">Payload 3 — Bypass via 127.0.0.1</div><div class="pc">http://127.0.0.1:5000/internal/metadata</div><div class="pd">Même effet avec IP au lieu de hostname.</div></div></div><div><div class="pl adv" onclick="f(\'http://0x7f000001:5000/internal/metadata\')"><div class="lb">☠ Payload 4 — Hex IP bypass</div><div class="pc">http://0x7f000001:5000/internal/metadata</div><div class="pd">Contourne les filtres avec IP hexadécimale.</div></div><div class="pl adv" onclick="f(\'http://localhost:5000/internal/flag\')"><div class="lb">☠ Payload 5 — Flag extraction</div><div class="pc">http://localhost:5000/internal/flag</div><div class="pd">Accède au secret interne via SSRF.</div></div></div></div><pre id="out" class="out"></pre></div><div id="t-theory" class="tp"><div class="cd"><h2>Qu\'est-ce que le SSRF ?</h2><p style="color:#8b949e;font-size:.88em;line-height:1.6">Le Server-Side Request Forgery (SSRF) se produit quand une application web effectue des requêtes HTTP côté serveur en utilisant des URL fournies par l\'utilisateur sans validation adéquate. L\'attaquant peut ainsi accéder à des services internes, des endpoints de métadonnées cloud, ou d\'autres ressources réseau normalement inaccessibles.</p><div class="bx d"><i class="fa-solid fa-skull"></i> <strong>Impact :</strong> Accès aux services internes, vol de credentials cloud, scan de ports, pivot réseau.</div></div></div><div id="t-code" class="tp"><div class="cd"><h2>Code vulnérable</h2><div class="co">@app.route("/api/fetch")\ndef api_fetch():\n    url = request.args.get("url", "")\n    # VULNÉRABLE: aucune validation de l\'URL\n    resp = requests.get(url, timeout=5)\n    return resp.text</div></div></div><div id="t-fix" class="tp"><div class="cd"><h2>Correction sécurisée</h2><div class="co g">from urllib.parse import urlparse\n\n_ALLOWED = {"example.com", "api.github.com"}\n\n@app.route("/api/fetch")\ndef api_fetch():\n    url = request.args.get("url", "")\n    parsed = urlparse(url)\n    if parsed.hostname not in _ALLOWED:\n        return "Domaine non autorisé", 403\n    resp = requests.get(url, timeout=5)\n    return resp.text</div><div class="bx s"><i class="fa-solid fa-shield-halved"></i> <strong>Défenses :</strong> Allowlist de domaines, blocage des IP privées, validation URL stricte, réseau isolé pour les requêtes sortantes.</div></div></div></div><script>function st(n,b){document.querySelectorAll(".tp").forEach(p=>p.classList.remove("a"));document.querySelectorAll(".tb").forEach(t=>t.classList.remove("a"));document.getElementById("t-"+n).classList.add("a");b.classList.add("a")}function f(v){document.getElementById("fu").value=v}function doFetch(){var u=document.getElementById("fu").value;if(!u){return}document.getElementById("out").textContent="Fetching...";fetch("/api/fetch?url="+encodeURIComponent(u)).then(r=>r.json()).then(d=>{document.getElementById("out").textContent=JSON.stringify(d,null,2)}).catch(e=>{document.getElementById("out").textContent="Erreur: "+e})}</script></body></html>'


@app.route("/")
def index() -> Any:
    return PAGE


@app.route("/internal/metadata")
def internal_metadata() -> Any:
    return jsonify({
        "service": "internal-metadata",
        "hostname": os.environ.get("HOSTNAME", "unknown"),
        "env_vars": {k: v for k, v in os.environ.items() if k.startswith(("FLASK", "LAB_"))},
        "internal": True,
    })


@app.route("/internal/flag")
def internal_flag() -> Any:
    return jsonify({"flag": _INTERNAL_SECRET, "message": "You found the internal secret via SSRF!"})


@app.route("/api/fetch")
def api_fetch() -> Any:
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        resp = http_client.get(url, timeout=5, allow_redirects=False)
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:2000]
        return jsonify({"url": url, "status": resp.status_code, "body": body})
    except Exception as e:
        return jsonify({"url": url, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
