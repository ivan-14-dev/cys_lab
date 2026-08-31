"""SSTI Lab — Vulnerable | CWE-94 | OWASP A03:2021"""
from __future__ import annotations
import os
from typing import Any
from flask import Flask, jsonify, request
from jinja2 import Environment

app = Flask(__name__)
app.secret_key = "lab-ssti-vuln-key"

FA = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">'
CSS = "*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}" ".banner{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;background:#da3633}" ".container{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.4em;margin-bottom:4px}" "h2{font-size:1em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}" ".meta{color:#8b949e;font-size:.85em;margin-bottom:16px}.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600;margin-right:4px}" ".badge-cwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}.badge-owasp{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.badge-red{background:#4a0d0d;border:1px solid #da3633;color:#f85149}" ".tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:20px}.tab-btn{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.88em;border-bottom:2px solid transparent;margin-bottom:-2px}" ".tab-btn.active{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tab-pane{display:none}.tab-pane.active{display:block}" ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin-bottom:14px}" ".fg{margin-bottom:10px}.fg label{display:block;font-size:.82em;color:#8b949e;margin-bottom:3px}" ".fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.88em}" ".btn{padding:9px 18px;border-radius:5px;cursor:pointer;font-size:.88em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}" ".btn-red{background:#da3633;color:#fff}.btn-gray{background:#21262d;border:1px solid #30363d;color:#e6edf3}" ".code{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.82em;line-height:1.6;margin:6px 0;white-space:pre-wrap}" ".code.good{border-left-color:#3fb950}" ".box{border-radius:6px;padding:11px 14px;font-size:.85em;margin:8px 0;line-height:1.5}" ".box.danger{background:#4a0d0d;border:1px solid #da3633;color:#f85149}.box.warn{background:#3d1f00;border:1px solid #d29922;color:#d29922}" ".box.info{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}.box.success{background:#0d4a1e;border:1px solid #238636;color:#3fb950}" ".g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.gd{display:grid;grid-template-columns:260px 1fr;gap:14px}" "@media(max-width:660px){.g2,.gd{grid-template-columns:1fr}}" ".pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:10px;margin-bottom:8px}" ".pl .lbl{font-size:.75em;color:#58a6ff;font-weight:700;margin-bottom:3px}.pl .cd{font-family:monospace;font-size:.78em;margin-bottom:4px}" ".pl .desc{font-size:.77em;color:#8b949e;margin-bottom:5px}" ".result-box{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:14px;margin-top:10px}" ".result-value{font-size:1.4em;font-weight:700;color:#3fb950;margin-top:6px;font-family:monospace}" "table{width:100%;border-collapse:collapse;font-size:.82em}th,td{padding:7px 10px;border:1px solid #21262d}th{background:#161b22;color:#8b949e}" "p{margin-bottom:6px;line-height:1.55;font-size:.88em;color:#8b949e}ul{padding-left:18px;color:#8b949e;font-size:.88em;line-height:1.9}"

PAGE = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>SSTI Lab — Vulnérable</title>{FA}<style>{CSS}</style></head><body>
<div class="banner"><i class="fa-solid fa-triangle-exclamation"></i> SSTI LAB — VULNÉRABLE <span>| Server-Side Template Injection | CWE-94 | OWASP A03:2021 | Sécurisé : localhost:5006</span></div>
<div class="container">
<h1>Server-Side Template Injection (SSTI)</h1>
<div class="meta"><span class="badge badge-red">Vulnérable</span><span class="badge badge-cwe">CWE-94</span><span class="badge badge-owasp">OWASP A03:2021</span></div>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('demo',this)"><i class="fa-solid fa-flask"></i> Démonstration</button>
  <button class="tab-btn" onclick="showTab('theory',this)"><i class="fa-solid fa-book"></i> Théorie</button>
  <button class="tab-btn" onclick="showTab('code',this)"><i class="fa-solid fa-code"></i> Code</button>
  <button class="tab-btn" onclick="showTab('fix',this)"><i class="fa-solid fa-shield-halved"></i> Correction</button>
</div>

<div id="tab-demo" class="tab-pane active">
<div class="gd">
<div>
<div class="card"><h2><i class="fa-solid fa-crosshairs"></i> Payloads SSTI</h2>
<div class="box danger"><i class="fa-solid fa-triangle-exclamation"></i> Ces expressions sont <strong>évaluées par Jinja2</strong> côté serveur.</div>
<div class="pl"><div class="lbl">Payload 1 — Calcul mathématique</div><div class="cd">{{{{7*7}}}}</div><div class="desc">Preuve : le moteur évalue l'expression. Résultat attendu : 49</div><button class="btn btn-gray" onclick="fillP('{{{{7*7}}}}')"><i class="fa-solid fa-play"></i> Essayer</button></div>
<div class="pl"><div class="lbl">Payload 2 — Multiplication de chaîne</div><div class="cd">{{{{"SSTI "*5}}}}</div><div class="desc">Opération sur string. Résultat : SSTI SSTI SSTI SSTI SSTI</div><button class="btn btn-gray" onclick="fillP('{{{{\'SSTI \'*5}}}}')"><i class="fa-solid fa-play"></i> Essayer</button></div>
<div class="pl"><div class="lbl">Payload 3 — Accès à l'objet config</div><div class="cd">{{{{config}}}}</div><div class="desc">Accès à l'objet Flask config — révèle la configuration.</div><button class="btn btn-gray" onclick="fillP('{{{{config}}}}')"><i class="fa-solid fa-play"></i> Essayer</button></div>
<div class="pl"><div class="lbl">Référence — Nom normal</div><div class="cd">Alice</div><div class="desc">Entrée saine. Résultat attendu : Hello Alice!</div><button class="btn btn-gray" onclick="fillP('Alice')"><i class="fa-solid fa-play"></i> Essayer</button></div>
</div>
</div>
<div>
<div class="card"><h2><i class="fa-solid fa-triangle-exclamation"></i> Service de salutation vulnérable</h2>
<div class="box danger"><i class="fa-solid fa-triangle-exclamation"></i> L'entrée utilisateur est utilisée comme <strong>source du template Jinja2</strong>. Les expressions <code>{{{{...}}}}</code> sont évaluées.</div>
<div class="fg"><label>Votre nom (essayez un payload Jinja2)</label><input id="fname" placeholder="ex: Alice ou {{{{7*7}}}}"></div>
<button class="btn btn-red" onclick="doGreet()"><i class="fa-solid fa-paper-plane"></i> Saluer</button>
</div>
<div class="result-box">
  <div style="font-size:.82em;color:#8b949e">Résultat du serveur :</div>
  <div class="result-value" id="result-output">—</div>
  <div style="font-size:.75em;color:#6e7681;margin-top:8px" id="result-meta"></div>
</div>
<div class="box warn" style="margin-top:10px"><i class="fa-solid fa-magnifying-glass"></i>
  Si vous entrez <code>{{{{7*7}}}}</code>, le serveur retourne <strong>"Hello 49!"</strong> — Jinja2 a calculé 7×7=49.
  Cela prouve que le template a été évalué côté serveur.</div>
</div>
</div>
</div>

<div id="tab-theory" class="tab-pane">
<div class="g2">
<div><div class="card">
<h2><i class="fa-solid fa-circle-question"></i> Qu'est-ce que le SSTI ?</h2>
<p>Le <strong>Server-Side Template Injection</strong> survient quand une donnée utilisateur est directement incorporée dans la <strong>source</strong> d'un template, plutôt que d'être passée comme <strong>variable</strong>.</p>
<p>Le moteur de template (Jinja2, Twig, Freemarker...) évalue alors le code injecté avec les privilèges du serveur.</p>
<h2><i class="fa-solid fa-diagram-project"></i> Mécanisme</h2>
<div class="code">
# VULNÉRABLE — l'entrée DEVIENT le template
name = request.args.get("name")
template = f"Hello {{name}}!"        # f-string Python
env = Environment()
result = env.from_string(template).render()

# Si name = "{{{{7*7}}}}" alors template = "Hello {{7*7}}!"
# Jinja2 évalue : 7*7 = 49
# Résultat : "Hello 49!"
</div>
<h2><i class="fa-solid fa-bolt"></i> Impact</h2>
<div class="box danger"><ul>
<li>Exécution de code arbitraire</li>
<li>Lecture de fichiers système</li>
<li>Accès aux variables d'environnement</li>
<li>Compromission totale du serveur</li>
</ul></div>
</div></div>
<div><div class="card">
<h2><i class="fa-solid fa-gears"></i> Fonctionnement Jinja2</h2>
<p>Jinja2 utilise <code>{{{{ }}}}</code> pour les expressions et <code>{{{{ config }}}}</code> pour accéder aux objets Flask.</p>
<div class="code">
# Chaîne d'accès aux classes Python :
# (payload avancé — non démontré dans ce lab)
# {{{{ ''.__class__.__mro__[1].__subclasses__() }}}}
# Permet d'atteindre les classes système
</div>
<h2><i class="fa-solid fa-book-open"></i> Références</h2>
<div class="box info">
  CWE-94 — Improper Control of Generation of Code<br>
  OWASP A03:2021 — Injection<br>
  PortSwigger SSTI Research
</div>
<h2><i class="fa-solid fa-shield-halved"></i> Prévention</h2>
<p>La correction fondamentale : l'entrée utilisateur doit être une <strong>variable</strong>, jamais une <strong>source de template</strong>.</p>
<div class="code good">
# SÉCURISÉ — template FIXE, entrée = variable
TEMPLATE = "Hello {{ name }}!"
t = Environment().from_string(TEMPLATE)
result = t.render(name=user_input)
</div>
</div></div>
</div>
</div>

<div id="tab-code" class="tab-pane">
<div class="g2">
<div><div class="card"><h2 style="color:#f85149"><i class="fa-solid fa-triangle-exclamation"></i> Code vulnérable (ici)</h2>
<div class="code">
# L'entrée devient la SOURCE du template
name = request.args.get("name", "World")

# La f-string Python intègre l'entrée dans le template
template_string = f"Hello {{name}}!"

# Jinja2 exécute ce template — y compris les expressions
env = Environment(autoescape=False)
template = env.from_string(template_string)
result = template.render()

# Input : {{{{7*7}}}}  →  template : "Hello {{7*7}}!"
# Jinja2 évalue 7*7 = 49
# Output : "Hello 49!"
</div></div></div>
<div><div class="card"><h2 style="color:#3fb950"><i class="fa-solid fa-circle-check"></i> Code sécurisé (localhost:5006)</h2>
<div class="code good">
# Template FIXE défini par le développeur
TEMPLATE = "Hello {{ name }}!"
template = Environment().from_string(TEMPLATE)

# L'entrée est passée comme VALEUR, pas comme template
result = template.render(name=user_input)

# Input : {{{{7*7}}}}  →  name = "{{7*7}}" (chaîne)
# Jinja2 affiche la valeur de name = "{{7*7}}"
# Output : "Hello {{7*7}}!"  (texte brut, non évalué)
</div></div></div>
</div>
</div>

<div id="tab-fix" class="tab-pane">
<div class="g2">
<div><div class="card">
<h2><i class="fa-solid fa-arrows-left-right"></i> Comparaison</h2>
<table>
<tr><th>Entrée</th><th style="color:#f85149">:5005 Vulnérable</th><th style="color:#3fb950">:5006 Sécurisé</th></tr>
<tr><td><code>Alice</code></td><td>Hello Alice!</td><td>Hello Alice!</td></tr>
<tr><td><code>{{{{7*7}}}}</code></td><td style="color:#f85149">Hello 49! (évalué!)</td><td style="color:#3fb950">Hello {{{{7*7}}}}! (texte)</td></tr>
<tr><td><code>{{{{config}}}}</code></td><td style="color:#f85149">Config Flask exposée</td><td style="color:#3fb950">Rejeté (validation)</td></tr>
</table>
</div></div>
<div><div class="card">
<h2><i class="fa-solid fa-circle-check"></i> Règle</h2>
<div class="box success">
  Toujours utiliser un <strong>template fixe</strong> avec des <strong>variables nommées</strong> :<br><br>
  <code>template.render(name=user_input)</code><br><br>
  Jamais :<br>
  <code>Template(f"Hello {{user_input}}!").render()</code>
</div>
</div></div>
</div>
</div>

</div>
<script>
function showTab(n,b){{document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+n).classList.add('active');if(b)b.classList.add('active');}}
function fillP(v){{document.getElementById('fname').value=v;}}
function doGreet(){{
  const name=document.getElementById('fname').value||'World';
  fetch('/api/greet?name='+encodeURIComponent(name)).then(r=>r.json()).then(d=>{{
    document.getElementById('result-output').textContent=d.output||d.error||'—';
    document.getElementById('result-meta').textContent='Entrée : '+d.input;
    if(d.error)document.getElementById('result-output').style.color='#f85149';
    else document.getElementById('result-output').style.color='#3fb950';
  }});
}}
</script>
</body></html>"""


@app.route("/", methods=["GET"])
@app.route("/greet", methods=["GET"])
def greet() -> Any:
    return PAGE


@app.route("/api/greet", methods=["GET"])
def api_greet() -> Any:
    name = request.args.get("name", "World")
    template_string = f"Hello {name}!"
    try:
        env = Environment(autoescape=False)
        result = env.from_string(template_string).render()
        return jsonify({"input": name, "output": result})
    except Exception as e:
        return jsonify({"input": name, "error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
