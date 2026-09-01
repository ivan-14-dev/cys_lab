"""Path Traversal Lab — Secure | CWE-22 | OWASP A01:2021"""
from __future__ import annotations
import os
from typing import Any
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-pt-sec"

_FILES_DIR = "/app/files"

PAGE = '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Path Traversal — Secure</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em}.bn.s{background:#238636}.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:monospace}.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}.btg{background:#238636;color:#fff}.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #3fb950;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}pre.out{background:#0d1117;color:#3fb950;border:1px solid #30363d;border-radius:5px;padding:14px;font-size:.8em;line-height:1.5;white-space:pre-wrap;max-height:400px;overflow-y:auto;margin-top:10px}</style></head><body><div class="bn s"><i class="fa-solid fa-shield-halved"></i> PATH TRAVERSAL — SÉCURISÉ <span>| CWE-22 | OWASP A01:2021</span></div><div class="ctr"><h1>Document Viewer (Sécurisé)</h1><div class="mt"><span class="bge bgrn">Sécurisé</span><span class="bge bcwe">CWE-22</span></div><div class="cd"><h2 style="font-size:.97em;color:#3fb950;margin-bottom:8px">Lecteur — Chemin validé</h2><div class="fg"><label>Nom du fichier</label><input id="fu" value="report-q1.txt"></div><button class="btn btg" onclick="doRead()"><i class="fa-solid fa-file"></i> Lire</button></div><div class="cd"><h2 style="font-size:.97em;color:#3fb950;margin-bottom:8px">Protection appliquée</h2><div class="co">safe = os.path.basename(filename)\nreal = os.path.realpath(os.path.join(DIR, safe))\nif not real.startswith(DIR):\n    return "Accès refusé", 403</div><div class="bx s"><i class="fa-solid fa-check-circle"></i> basename() + realpath() + vérification du préfixe.</div></div><pre id="out" class="out"></pre></div><script>function doRead(){var fn=document.getElementById("fu").value;if(!fn)return;fetch("/api/read?file="+encodeURIComponent(fn)).then(r=>r.json()).then(d=>{document.getElementById("out").textContent=JSON.stringify(d,null,2)}).catch(e=>{document.getElementById("out").textContent="Erreur: "+e})}</script></body></html>'


@app.route("/")
def index() -> Any:
    return PAGE


@app.route("/api/read")
def api_read() -> Any:
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "file parameter required"}), 400
    safe_name = os.path.basename(filename)
    path = os.path.realpath(os.path.join(_FILES_DIR, safe_name))
    if not path.startswith(os.path.realpath(_FILES_DIR)):
        return jsonify({"error": "Path traversal blocked", "blocked": True}), 403
    try:
        with open(path) as fh:
            content = fh.read(10000)
        return jsonify({"file": safe_name, "content": content, "blocked": False})
    except FileNotFoundError:
        return jsonify({"file": safe_name, "error": "File not found", "blocked": True}), 404
    except Exception as e:
        return jsonify({"file": safe_name, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
