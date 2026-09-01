"""Path Traversal Lab — Vulnerable | CWE-22 | OWASP A01:2021
INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY
"""
from __future__ import annotations
import os
from typing import Any
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-pt-vuln"

_FILES_DIR = "/app/files"
_FLAG = os.environ.get("LAB_FLAG", "FLAG{path_traversal_file_read}")

PAGE = '<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Path Traversal Lab</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em}.bn.v{background:#da3633}.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}h2{font-size:.97em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.bo{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.br{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}.tb{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.87em;border-bottom:2px solid transparent;margin-bottom:-2px}.tb.a{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tp{display:none}.tp.a{display:block}.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:monospace}.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}.btr{background:#da3633;color:#fff}.btg{background:#238636;color:#fff}.btgr{background:#21262d;border:1px solid #30363d;color:#e6edf3}.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}.co.g{border-left-color:#3fb950}.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}.bx.d{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bx.w{background:#3d1f00;border:1px solid #d29922;color:#d29922}.bx.i{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:660px){.g2{grid-template-columns:1fr}}.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px;margin-bottom:7px;cursor:pointer}.pl:hover{border-color:#58a6ff}.pl .lb{font-size:.74em;color:#58a6ff;font-weight:700;margin-bottom:2px}.pl .pc{font-family:monospace;font-size:.77em;margin-bottom:3px;word-break:break-all}.pl .pd{font-size:.76em;color:#8b949e}pre.out{background:#0d1117;color:#3fb950;border:1px solid #30363d;border-radius:5px;padding:14px;font-size:.8em;line-height:1.5;white-space:pre-wrap;max-height:400px;overflow-y:auto;margin-top:10px}.pl.adv{border:1px solid #da3633}.pl.adv .lb{color:#f85149}</style></head><body><div class="bn v"><i class="fa-solid fa-triangle-exclamation"></i> PATH TRAVERSAL — VULNÉRABLE <span>| Directory Traversal | CWE-22 | OWASP A01:2021 | Sécurisé : localhost:5028</span></div><div class="ctr"><h1>Document Viewer</h1><div class="mt"><span class="bge br">Vulnérable</span><span class="bge bcwe">CWE-22</span><span class="bge bo">OWASP A01:2021</span></div><div class="tabs"><button class="tb a" onclick="st(\'demo\',this)">Demo</button><button class="tb" onclick="st(\'theory\',this)">Théorie</button><button class="tb" onclick="st(\'code\',this)">Code</button><button class="tb" onclick="st(\'fix\',this)">Fix</button></div><div id="t-demo" class="tp a"><div class="cd"><h2>Lecteur de fichiers</h2><div class="fg"><label>Nom du fichier</label><input id="fu" value="report-q1.txt" placeholder="filename.txt"></div><button class="btn btr" onclick="doRead()"><i class="fa-solid fa-file"></i> Lire</button><button class="btn btgr" onclick="doList()"><i class="fa-solid fa-list"></i> Fichiers disponibles</button></div><h2>Payloads</h2><div class="g2"><div><div class="pl" onclick="f(\'report-q1.txt\')"><div class="lb">Payload 1 — Fichier normal</div><div class="pc">report-q1.txt</div><div class="pd">Lecture légitime d\'un rapport.</div></div><div class="pl" onclick="f(\'../src/app.py\')"><div class="lb">Payload 2 — Code source</div><div class="pc">../src/app.py</div><div class="pd">Remonte d\'un niveau pour lire le code source.</div></div><div class="pl" onclick="f(\'../../../../etc/passwd\')"><div class="lb">Payload 3 — /etc/passwd</div><div class="pc">../../../../etc/passwd</div><div class="pd">Traversée classique pour lire les utilisateurs système.</div></div></div><div><div class="pl adv" onclick="f(\'../../../../etc/hostname\')"><div class="lb">☠ Payload 4 — Hostname</div><div class="pc">../../../../etc/hostname</div><div class="pd">Identifie le conteneur Docker.</div></div><div class="pl adv" onclick="f(\'../../../../proc/self/environ\')"><div class="lb">☠ Payload 5 — Variables d\'env</div><div class="pc">../../../../proc/self/environ</div><div class="pd">Lit les variables d\'environnement (contient le FLAG).</div></div><div class="pl adv" onclick="f(\'../flag.txt\')"><div class="lb">☠ Payload 6 — Flag direct</div><div class="pc">../flag.txt</div><div class="pd">Accède au fichier flag créé au démarrage.</div></div></div></div><pre id="out" class="out"></pre></div><div id="t-theory" class="tp"><div class="cd"><h2>Qu\'est-ce que le Path Traversal ?</h2><p style="color:#8b949e;font-size:.88em;line-height:1.6">Le Path Traversal (Directory Traversal) se produit quand une application utilise une entrée utilisateur pour construire un chemin de fichier sans le valider. L\'attaquant utilise des séquences <code>../</code> pour remonter dans l\'arborescence et accéder à des fichiers en dehors du répertoire prévu.</p><div class="bx d"><i class="fa-solid fa-skull"></i> <strong>Impact :</strong> Lecture de fichiers sensibles (/etc/passwd, code source, clés privées, variables d\'environnement).</div></div></div><div id="t-code" class="tp"><div class="cd"><h2>Code vulnérable</h2><div class="co">@app.route("/api/read")\ndef api_read():\n    filename = request.args.get("file", "")\n    # VULNÉRABLE: aucune validation du chemin\n    path = os.path.join(FILES_DIR, filename)\n    with open(path) as f:\n        return f.read()</div></div></div><div id="t-fix" class="tp"><div class="cd"><h2>Correction sécurisée</h2><div class="co g">import os\n\n@app.route("/api/read")\ndef api_read():\n    filename = request.args.get("file", "")\n    safe = os.path.basename(filename)\n    path = os.path.join(FILES_DIR, safe)\n    real = os.path.realpath(path)\n    if not real.startswith(FILES_DIR):\n        return "Accès refusé", 403\n    with open(real) as f:\n        return f.read()</div><div class="bx s"><i class="fa-solid fa-shield-halved"></i> <strong>Défenses :</strong> os.path.basename(), realpath() + vérification prefix, allowlist de fichiers, chroot/sandbox.</div></div></div></div><script>function st(n,b){document.querySelectorAll(".tp").forEach(p=>p.classList.remove("a"));document.querySelectorAll(".tb").forEach(t=>t.classList.remove("a"));document.getElementById("t-"+n).classList.add("a");b.classList.add("a")}function f(v){document.getElementById("fu").value=v}function doRead(){var fn=document.getElementById("fu").value;if(!fn)return;fetch("/api/read?file="+encodeURIComponent(fn)).then(r=>r.json()).then(d=>{document.getElementById("out").textContent=JSON.stringify(d,null,2)}).catch(e=>{document.getElementById("out").textContent="Erreur: "+e})}function doList(){fetch("/api/files").then(r=>r.json()).then(d=>{document.getElementById("out").textContent=JSON.stringify(d,null,2)}).catch(e=>{document.getElementById("out").textContent="Erreur: "+e})}</script></body></html>'


@app.route("/")
def index() -> Any:
    return PAGE


@app.route("/api/files")
def api_files() -> Any:
    try:
        files = os.listdir(_FILES_DIR)
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/read")
def api_read() -> Any:
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "file parameter required"}), 400
    # VULNERABLE: no path validation — directory traversal possible
    path = os.path.join(_FILES_DIR, filename)
    try:
        with open(path) as fh:
            content = fh.read(10000)
        return jsonify({"file": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"file": filename, "error": "File not found"}), 404
    except PermissionError:
        return jsonify({"file": filename, "error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"file": filename, "error": str(e)}), 500


# Write flag at import time (flask run skips __main__)
try:
    with open("/tmp/flag.txt", "w") as _fh:
        _fh.write(_FLAG + "\n")
except OSError:
    pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
