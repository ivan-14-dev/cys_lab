"""Command Injection Lab — Vulnerable | CWE-78 | OWASP A03:2021"""
from __future__ import annotations
import os, subprocess
from typing import Any
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-cmd-vuln-key"
FA = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"

PAGE = """<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Command Injection — Vulnérable</title>
<link rel="stylesheet" href=\"""" + r"""https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css""" + r"""\">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}
.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em;background:#da3633}
.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}
h2{font-size:.97em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}
.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}
.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.bo{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.br{background:#4a0d0d;border:1px solid #da3633;color:#f85149}
.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}.tb{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.87em;border-bottom:2px solid transparent;margin-bottom:-2px}
.tb.a{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tp{display:none}.tp.a{display:block}
.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}
.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}
.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em;font-family:monospace}
.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}
.btr{background:#da3633;color:#fff}.btgr{background:#21262d;border:1px solid #30363d;color:#e6edf3}
.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}
.co.g{border-left-color:#3fb950}
.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}
.bx.d{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.bx.w{background:#3d1f00;border:1px solid #d29922;color:#d29922}
.bx.i{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.gd{display:grid;grid-template-columns:255px 1fr;gap:14px}
@media(max-width:660px){.g2,.gd{grid-template-columns:1fr}}
.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px;margin-bottom:7px}
.pl .lb{font-size:.74em;color:#58a6ff;font-weight:700;margin-bottom:2px}.pl .pc{font-family:monospace;font-size:.77em;margin-bottom:3px;word-break:break-all}
.pl .pd{font-size:.76em;color:#8b949e;margin-bottom:4px}
.term{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:14px;margin-top:10px;font-family:monospace;font-size:.82em;color:#00ff00;min-height:80px;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font-size:.81em}th,td{padding:7px 9px;border:1px solid #21262d}th{background:#161b22;color:#8b949e}
code{background:#0d1117;padding:1px 4px;border-radius:2px;font-size:.84em;font-family:monospace}
p{margin-bottom:5px;line-height:1.55;font-size:.87em;color:#8b949e}ul{padding-left:17px;color:#8b949e;font-size:.87em;line-height:1.85}
</style></head><body>
<div class="bn"><i class="fa-solid fa-triangle-exclamation"></i> COMMAND INJECTION — VULNÉRABLE
<span>| shell=True + concaténation | CWE-78 | OWASP A03:2021 | Sécurisé: localhost:5004</span><button id="lang-btn" onclick="toggleLang()" style="margin-left:auto;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4);color:#fff;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.8em;font-weight:600">EN</button></div>
<div class="ctr">
<h1>Command Injection — Outil de diagnostic réseau</h1>
<div class="mt"><span class="bge br">Vulnérable</span><span class="bge bcwe">CWE-78</span><span class="bge bo">OWASP A03:2021</span></div>
<div class="tabs">
<button class="tb a" onclick="st('demo',this)"><i class="fa-solid fa-flask"></i> Démonstration</button>
<button class="tb" onclick="st('theory',this)"><i class="fa-solid fa-book"></i> Théorie</button>
<button class="tb" onclick="st('code',this)"><i class="fa-solid fa-code"></i> Code</button>
<button class="tb" onclick="st('fix',this)"><i class="fa-solid fa-shield-halved"></i> Correction</button>
</div>

<div id="t-demo" class="tp a">
<div class="gd">
<div><div class="cd"><h2><i class="fa-solid fa-crosshairs"></i> Payloads d'injection</h2>
<div class="bx d"><i class="fa-solid fa-triangle-exclamation"></i> Ces payloads exécutent des <strong>commandes supplémentaires</strong> sur le serveur via <code>shell=True</code>.</div>
<div class="pl">
  <div class="lb">Payload 1 — Ping normal</div>
  <div class="pc">127.0.0.1</div>
  <div class="pd">Commande normale. Référence de comparaison.</div>
  <button class="btn btgr" onclick="f('127.0.0.1')"><i class="fa-solid fa-play"></i> Normal</button>
</div>
<div class="pl">
  <div class="lb">Payload 2 — Injection par point-virgule</div>
  <div class="pc">127.0.0.1; echo INJECTION_DETECTED</div>
  <div class="desc pd">Le shell exécute ping ET echo. Le séparateur <code>;</code> chaîne les commandes.</div>
  <button class="btn btgr" onclick="f('127.0.0.1; echo INJECTION_DETECTED')"><i class="fa-solid fa-play"></i> Injecter</button>
</div>
<div class="pl">
  <div class="lb">Payload 3 — Calcul prouvant l'exécution</div>
  <div class="pc">127.0.0.1; echo CALC=$(expr 7 * 7)</div>
  <div class="desc pd">Calcule 7×7=49 via le shell. Prouve l'exécution de code arbitraire.</div>
  <button class="btn btgr" onclick="f('127.0.0.1; echo CALC=$(expr 7 \\* 7)')"><i class="fa-solid fa-play"></i> Injecter</button>
</div>
<div class="pl">
  <div class="lb">Payload 4 — Lecture fichier lab</div>
  <div class="pc">127.0.0.1; cat /app/data/lab-secret.txt</div>
  <div class="desc pd">Lit un fichier créé spécialement pour cette démonstration.</div>
  <button class="btn btgr" onclick="f('127.0.0.1; cat /app/data/lab-secret.txt')"><i class="fa-solid fa-play"></i> Injecter</button>
</div>
</div></div>
<div><div class="cd"><h2><i class="fa-solid fa-terminal"></i> Outil de ping vulnérable</h2>
<div class="bx d"><i class="fa-solid fa-triangle-exclamation"></i> La commande est construite par <strong>concaténation de chaînes</strong> avec <code>shell=True</code>. Tout ce qui suit le point-virgule s'exécute.</div>
<div class="fg"><label>Cible (IP ou hostname + payload)</label><input id="ft" value="127.0.0.1" placeholder="127.0.0.1 ou 127.0.0.1; echo INJECTED"></div>
<div style="font-size:.79em;color:#6e7681;margin-bottom:8px">Commande construite : <code id="cmd-preview">ping -c 2 127.0.0.1</code></div>
<button class="btn btr" onclick="doPing()"><i class="fa-solid fa-satellite-dish"></i> Exécuter ping</button>
</div>
<div class="term" id="term-output">$ En attente...</div>
<div class="bx i" style="margin-top:8px"><i class="fa-solid fa-magnifying-glass"></i>
Observez la sortie — si <strong>INJECTION_DETECTED</strong> apparaît après le résultat du ping, la commande injectée s'est exécutée.
Comparez avec <a href="http://localhost:5004" style="color:#58a6ff">localhost:5004</a> (sécurisé).</div>
</div>
</div>
</div>

<div id="t-theory" class="tp">
<div class="g2">
<div><div class="cd">
<h2><i class="fa-solid fa-circle-question"></i> Qu'est-ce que l'injection de commandes ?</h2>
<p>L'injection de commandes OS survient quand une entrée utilisateur est intégrée dans une commande shell sans être correctement neutralisée. L'attaquant peut alors exécuter des commandes arbitraires sur le serveur.</p>
<h2><i class="fa-solid fa-diagram-project"></i> Mécanisme</h2>
<div class="co">
Développeur pense construire :
  ping -c 2 127.0.0.1

L'attaquant entre :
  127.0.0.1; cat /etc/passwd

Commande réellement exécutée :
  ping -c 2 127.0.0.1; cat /etc/passwd

Le shell ( /bin/sh -c ) interprète le ; comme
un séparateur de commandes.
Résultat : ping s'exécute, PUIS cat s'exécute.
</div>
<h2><i class="fa-solid fa-bolt"></i> Séparateurs de commandes shell</h2>
<table>
<tr><th>Séparateur</th><th>Comportement</th></tr>
<tr><td><code>;</code></td><td>Exécute toujours la 2e commande</td></tr>
<tr><td><code>&&</code></td><td>Exécute si la 1ère réussit</td></tr>
<tr><td><code>||</code></td><td>Exécute si la 1ère échoue</td></tr>
<tr><td><code>`cmd`</code></td><td>Substitution de commande</td></tr>
<tr><td><code>$(cmd)</code></td><td>Substitution de commande</td></tr>
<tr><td><code>|</code></td><td>Pipe vers la 2e commande</td></tr>
</table>
</div></div>
<div><div class="cd">
<h2><i class="fa-solid fa-bolt"></i> Impact</h2>
<div class="bx d"><ul>
<li>Lecture de fichiers système (<code>/etc/passwd</code>)</li>
<li>Exfiltration de données sensibles</li>
<li>Création/modification de fichiers</li>
<li>Reverse shell (prise de contrôle totale)</li>
<li>Mouvement latéral dans le réseau</li>
<li>Destruction de données</li>
</ul></div>
<h2><i class="fa-solid fa-exclamation"></i> Cause racine</h2>
<p>L'utilisation de <code>shell=True</code> active l'interpréteur shell qui traite les métacaractères. Combiné à la concaténation de chaînes, tout input devient potentiellement du code.</p>
<div class="co">
# Python — la commande devient :
cmd = "ping -c 2 " + user_input
subprocess.run(cmd, shell=True)
# /bin/sh -c "ping -c 2 USER_INPUT"
# Le shell interprète tous les métacaractères
</div>
<h2><i class="fa-solid fa-book-open"></i> Références</h2>
<div class="bx i">CWE-78 — OS Command Injection<br>OWASP A03:2021 — Injection<br>OWASP OS Command Injection Cheat Sheet</div>
</div></div>
</div>
</div>

<div id="t-code" class="tp">
<div class="g2">
<div><div class="cd">
<h2 style="color:#f85149"><i class="fa-solid fa-triangle-exclamation"></i> Code vulnérable (ici)</h2>
<div class="co">
target = request.form.get("target", "")

# VULNÉRABLE — concaténation + shell=True
command = f"ping -c 2 {target}"
result = subprocess.run(
    command,
    shell=True,      # ← DANGEREUX
    capture_output=True,
    text=True
)
# shell=True → /bin/sh -c "ping -c 2 {target}"
# "127.0.0.1; id" → ping ET id s'exécutent
</div>
</div></div>
<div><div class="cd">
<h2 style="color:#3fb950"><i class="fa-solid fa-circle-check"></i> Code sécurisé (localhost:5004)</h2>
<div class="co g">
# Allowlist des cibles autorisées
ALLOWED = frozenset({"127.0.0.1", "localhost"})

target = request.form.get("target", "")

# Validation stricte
if target not in ALLOWED:
    return error("Cible non autorisée")

# Liste d'arguments — pas de shell
result = subprocess.run(
    ["ping", "-c", "2", target],  # liste !
    shell=False,                   # ← SÉCURISÉ
    capture_output=True,
    text=True
)
# Le shell n'est jamais impliqué
# "127.0.0.1; id" → ping reçoit la chaîne
# littérale comme hostname → échec DNS
</div>
</div></div>
</div>
</div>

<div id="t-fix" class="tp">
<div class="g2">
<div><div class="cd">
<h2><i class="fa-solid fa-arrows-left-right"></i> Comparaison</h2>
<table>
<tr><th>Test</th><th style="color:#f85149">Vulnérable</th><th style="color:#3fb950">Sécurisé</th></tr>
<tr><td><code>127.0.0.1</code></td><td>Ping normal</td><td>Ping normal</td></tr>
<tr><td><code>127.0.0.1; echo INJECTED</code></td><td style="color:#f85149">Ping + INJECTED affiché</td><td style="color:#3fb950">Rejeté (allowlist)</td></tr>
<tr><td><code>8.8.8.8</code></td><td style="color:#f85149">Ping externe autorisé</td><td style="color:#3fb950">Rejeté (non dans allowlist)</td></tr>
<tr><td><code>$(id)</code></td><td style="color:#f85149">Exécute id</td><td style="color:#3fb950">Rejeté</td></tr>
</table>
</div></div>
<div><div class="cd">
<h2><i class="fa-solid fa-circle-check"></i> Règles de correction</h2>
<div class="bx s">
1. Toujours utiliser une <strong>liste d'arguments</strong><br>
2. Toujours <code>shell=False</code> (défaut Python)<br>
3. Valider l'entrée par <strong>allowlist stricte</strong><br>
4. Utiliser <code>shlex.quote()</code> si shell=True est inévitable<br>
5. Exécuter avec un utilisateur <strong>non-root</strong>
</div>
</div></div>
</div>
</div>

</div>
<script>
function st(n,b){document.querySelectorAll('.tp').forEach(p=>p.classList.remove('a'));document.querySelectorAll('.tb').forEach(x=>x.classList.remove('a'));document.getElementById('t-'+n).classList.add('a');if(b)b.classList.add('a');}
function f(v){document.getElementById('ft').value=v;updatePreview();}
function updatePreview(){document.getElementById('cmd-preview').textContent='ping -c 2 '+document.getElementById('ft').value;}
document.getElementById('ft').addEventListener('input',updatePreview);
function doPing(){
  const target=document.getElementById('ft').value;
  const out=document.getElementById('term-output');
  out.textContent='$ ping -c 2 '+target+'\n[exécution en cours...]';
  fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})})
    .then(r=>r.json()).then(d=>{
      out.textContent='$ '+d.command+'\n\n'+d.output;
      if(d.output.includes('INJECTION_DETECTED')||d.output.includes('CALC='))
        out.style.color='#f85149';
      else out.style.color='#00ff00';
    }).catch(e=>{out.textContent='Erreur: '+e;});
}

var LANG='fr';var TXT={fr:{demo:'Démonstration',theory:'Théorie',code:'Code',fix:'Correction',langLabel:'EN'},en:{demo:'Demonstration',theory:'Theory',code:'Code',fix:'Defense',langLabel:'FR'}};
function toggleLang(){LANG=LANG==='fr'?'en':'fr';var b=document.getElementById('lang-btn');if(b)b.textContent=TXT[LANG].langLabel;document.querySelectorAll('[data-key]').forEach(function(el){var k=el.getAttribute('data-key');if(TXT[LANG][k])el.textContent=TXT[LANG][k];});}
function setPayload(btn){var u=btn.getAttribute('data-u');var p=btn.getAttribute('data-p');var v=btn.getAttribute('data-v');if(document.getElementById('fu')&&u!==null)document.getElementById('fu').value=u;if(document.getElementById('fp')&&p!==null)document.getElementById('fp').value=p;if(document.getElementById('fname')&&v!==null)document.getElementById('fname').value=v;if(document.getElementById('ft')&&v!==null)document.getElementById('ft').value=v;if(document.getElementById('fe')&&v!==null)document.getElementById('fe').value=v;if(typeof updatePreview==='function')updatePreview();if(typeof updateQ==='function')updateQ();}
</script>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    return PAGE


@app.route("/api/ping", methods=["POST"])
def api_ping() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target:
        return jsonify({"error": "cible requise"}), 400
    command = f"ping -c 2 {target}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Timeout."
    except Exception as e:
        output = str(e)
    return jsonify({"command": command, "output": output})


if __name__ == "__main__":
    os.makedirs("/app/data", exist_ok=True)
    if not os.path.exists("/app/data/lab-secret.txt"):
        with open("/app/data/lab-secret.txt", "w") as f:
            f.write("LAB_FLAG: COMMAND_INJECTION_DEMONSTRATED\nFichier créé pour la démonstration uniquement.\n")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
