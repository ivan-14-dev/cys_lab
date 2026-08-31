"""Command Injection Lab — Secure | CWE-78 | OWASP A03:2021"""
from __future__ import annotations
import ipaddress, os, re, subprocess
from typing import Any
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-cmd-secure-key"
_ALLOWED = frozenset({"127.0.0.1", "localhost"})

PAGE = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Command Injection — Sécurisé</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em}.bn.v{background:#da3633}.bn.s{background:#238636}.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}h2{font-size:.97em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.bo{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.br{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}.tb{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.87em;border-bottom:2px solid transparent;margin-bottom:-2px}.tb.a{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tp{display:none}.tp.a{display:block}.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}.fg input,.fg textarea{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:inherit}.fg textarea{height:68px;resize:vertical}.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}.btr{background:#da3633;color:#fff}.btg{background:#238636;color:#fff}.btgr{background:#21262d;border:1px solid #30363d;color:#e6edf3}.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}.co.g{border-left-color:#3fb950}.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}.bx.d{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bx.w{background:#3d1f00;border:1px solid #d29922;color:#d29922}.bx.i{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.gd{display:grid;grid-template-columns:255px 1fr;gap:14px}@media(max-width:660px){.g2,.gd{grid-template-columns:1fr}}.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px;margin-bottom:7px}.pl .lb{font-size:.74em;color:#58a6ff;font-weight:700;margin-bottom:2px}.pl .pc{font-family:monospace;font-size:.77em;margin-bottom:3px;word-break:break-all}.pl .pd{font-size:.76em;color:#8b949e;margin-bottom:4px}.term{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:14px;margin-top:10px;font-family:monospace;font-size:.82em;color:#00ff00;min-height:80px;white-space:pre-wrap}.res{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:12px;margin-top:10px;min-height:48px}table{width:100%;border-collapse:collapse;font-size:.81em}th,td{padding:7px 9px;border:1px solid #21262d}th{background:#161b22;color:#8b949e}code{background:#0d1117;padding:1px 4px;border-radius:2px;font-size:.84em;font-family:monospace}p{margin-bottom:5px;line-height:1.55;font-size:.87em;color:#8b949e}ul{padding-left:17px;color:#8b949e;font-size:.87em;line-height:1.85}</style></head><body>
<div class="bn s"><i class="fa-solid fa-circle-check"></i> COMMAND INJECTION — SÉCURISÉ
<span>| liste args + allowlist | CWE-78 | OWASP A03:2021 | Vulnérable: localhost:5003</span></div>
<div class="ctr">
<h1>Command Injection — Sécurisé</h1>
<div class="mt"><span class="bge bgrn">Sécurisé</span><span class="bge bcwe">CWE-78</span><span class="bge bo">OWASP A03:2021</span></div>
<div class="tabs">
<button class="tb a" onclick="st('demo',this)"><i class="fa-solid fa-flask"></i> Démonstration</button>
<button class="tb" onclick="st('theory',this)"><i class="fa-solid fa-book"></i> Théorie</button>
<button class="tb" onclick="st('code',this)"><i class="fa-solid fa-code"></i> Code</button>
<button class="tb" onclick="st('fix',this)"><i class="fa-solid fa-shield-halved"></i> Correction</button>
</div>
<div id="t-demo" class="tp a">
<div class="gd">
<div><div class="cd"><h2><i class="fa-solid fa-crosshairs"></i> Testez les payloads</h2>
<div class="bx s"><i class="fa-solid fa-circle-check"></i> Les payloads d'injection sont <strong>bloqués par l'allowlist</strong>. Seules les cibles autorisées fonctionnent.</div>
<div class="pl"><div class="lb">Test 1 — Cible valide</div><div class="pc">127.0.0.1</div><div class="pd">Dans l'allowlist → ping autorisé.</div><button class="btn btgr" onclick="f('127.0.0.1')"><i class="fa-solid fa-play"></i> Tester</button></div>
<div class="pl"><div class="lb">Test 2 — Injection (bloqué)</div><div class="pc">127.0.0.1; echo INJECTION</div><div class="pd">Non dans l'allowlist → rejeté avant exécution.</div><button class="btn btgr" onclick="f('127.0.0.1; echo INJECTION')"><i class="fa-solid fa-play"></i> Tester</button></div>
<div class="pl"><div class="lb">Test 3 — IP externe (bloqué)</div><div class="pc">8.8.8.8</div><div class="pd">Non dans l'allowlist → rejeté.</div><button class="btn btgr" onclick="f('8.8.8.8')"><i class="fa-solid fa-play"></i> Tester</button></div>
<div class="pl"><div class="lb">Test 4 — Métacaractère (bloqué)</div><div class="pc">$(id)</div><div class="pd">Non dans l'allowlist → rejeté.</div><button class="btn btgr" onclick="f('$(id)')"><i class="fa-solid fa-play"></i> Tester</button></div>
</div></div>
<div><div class="cd"><h2><i class="fa-solid fa-circle-check"></i> Outil de ping sécurisé</h2>
<div class="bx s"><i class="fa-solid fa-shield-halved"></i> <strong>Défenses :</strong> subprocess liste (shell=False) | Allowlist: 127.0.0.1, localhost | Validation d'entrée</div>
<div class="fg"><label>Cible (autorisées: 127.0.0.1, localhost)</label><input id="ft" value="127.0.0.1" placeholder="127.0.0.1 ou localhost"></div>
<button class="btn btg" onclick="doPing()"><i class="fa-solid fa-satellite-dish"></i> Exécuter ping</button>
</div>
<div class="term" id="term-output">$ En attente...</div>
<div class="bx i" style="margin-top:8px"><i class="fa-solid fa-magnifying-glass"></i>
Essayez <code>127.0.0.1; echo INJECTED</code> — rejeté par l'allowlist avant même l'exécution.
Comparez avec <a href="http://localhost:5003" style="color:#58a6ff">localhost:5003</a>.</div>
</div></div></div>
<div id="t-theory" class="tp">
<div class="g2"><div><div class="cd">
<h2><i class="fa-solid fa-shield-halved"></i> Pourquoi cette version est sécurisée</h2>
<p>La défense repose sur deux mécanismes complémentaires :</p>
<p><strong>1. Liste d'arguments (pas de shell)</strong></p>
<div class="co g">subprocess.run(["ping", "-c", "2", target], shell=False)
# Pas de shell → pas d'interprétation des métacaractères
# "127.0.0.1; id" → ping reçoit la chaîne littérale
# → Échec DNS, pas d'injection</div>
<p><strong>2. Allowlist stricte</strong></p>
<div class="co g">ALLOWED = frozenset({"127.0.0.1", "localhost"})
if target not in ALLOWED:
    return error("Cible non autorisée")</div>
</div></div>
<div><div class="cd">
<h2><i class="fa-solid fa-list-check"></i> Défenses en couches</h2>
<ul>
<li><strong>Allowlist</strong> — rejette toute cible non prévue</li>
<li><strong>shell=False</strong> — supprime l'interpréteur shell</li>
<li><strong>Liste d'args</strong> — sépare commande et données</li>
<li><strong>Timeout</strong> — limite les ressources</li>
<li><strong>Non-root</strong> — limite l'impact si compromis</li>
</ul>
<h2><i class="fa-solid fa-book-open"></i> Références</h2>
<div class="bx i">CWE-78 — OS Command Injection<br>OWASP A03:2021 — Injection</div>
</div></div></div></div>
<div id="t-code" class="tp"><div class="g2">
<div><div class="cd"><h2 style="color:#3fb950"><i class="fa-solid fa-circle-check"></i> Code sécurisé (ici)</h2>
<div class="co g">ALLOWED = frozenset({"127.0.0.1", "localhost"})

target = request.get_json()["target"]
if target not in ALLOWED:
    return error("Non autorisé")

# Liste — target est un élément, pas une commande
result = subprocess.run(
    ["ping", "-c", "2", target],
    shell=False,
    capture_output=True, text=True, timeout=10
)</div></div></div>
<div><div class="cd"><h2 style="color:#f85149"><i class="fa-solid fa-triangle-exclamation"></i> Code vulnérable (:5003)</h2>
<div class="co">target = request.get_json()["target"]
command = f"ping -c 2 {target}"
result = subprocess.run(
    command,
    shell=True  # ← shell interprète tout
)</div></div></div>
</div></div>
<div id="t-fix" class="tp"><div class="g2">
<div><div class="cd"><h2><i class="fa-solid fa-arrows-left-right"></i> Comparaison</h2>
<table>
<tr><th>Entrée</th><th style="color:#f85149">Vulnérable :5003</th><th style="color:#3fb950">Sécurisé ici</th></tr>
<tr><td><code>127.0.0.1</code></td><td>Ping OK</td><td>Ping OK</td></tr>
<tr><td><code>127.0.0.1; echo X</code></td><td style="color:#f85149">Ping + X exécuté</td><td style="color:#3fb950">Rejeté (allowlist)</td></tr>
<tr><td><code>$(id)</code></td><td style="color:#f85149">id exécuté</td><td style="color:#3fb950">Rejeté</td></tr>
</table></div></div>
<div><div class="cd"><h2><i class="fa-solid fa-circle-check"></i> Résumé</h2>
<div class="bx s">shell=False + liste d'args = pas d'interpréteur shell<br>Allowlist = seules les cibles prévues sont autorisées<br>Ensemble : aucun payload d'injection ne peut passer.</div>
</div></div></div></div>
</div>
<script>function st(n,b){document.querySelectorAll('.tp').forEach(p=>p.classList.remove('a'));document.querySelectorAll('.tb').forEach(x=>x.classList.remove('a'));document.getElementById('t-'+n).classList.add('a');if(b)b.classList.add('a');}
function f(v){document.getElementById('ft').value=v;}
function doPing(){
  const target=document.getElementById('ft').value;
  const out=document.getElementById('term-output');
  out.style.color='#00ff00';out.textContent='$ ping -c 2 '+target+'\n[exécution...]';
  fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})})
    .then(r=>r.json()).then(d=>{
      if(d.blocked){out.style.color='#3fb950';out.textContent='[BLOQUÉ] '+d.error;}
      else{out.textContent='$ ping -c 2 '+target+'\n\n'+d.output;}
    });
}
</script></body></html>"""


@app.route("/")
def index() -> Any:
    return PAGE

@app.route("/api/ping", methods=["POST"])
def api_ping() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    target = str(data.get("target", "")).strip()
    if target not in _ALLOWED:
        return jsonify({"error": f"Cible '{target}' non autorisée (autorisées: {sorted(_ALLOWED)})", "blocked": True}), 400
    try:
        result = subprocess.run(["ping", "-c", "2", target], shell=False, capture_output=True, text=True, timeout=10)
        return jsonify({"output": result.stdout + result.stderr, "blocked": False})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "Timeout.", "blocked": False})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
