"""SSTI Lab — Secure | CWE-94 | OWASP A03:2021"""
from __future__ import annotations
import os, re
from typing import Any
from flask import Flask, jsonify, request
from jinja2 import Environment, select_autoescape

app = Flask(__name__)
app.secret_key = "lab-ssti-secure-key"
_NAME_RE = re.compile(r"^[\w\s\-\'.,!?]{1,80}$")
_TEMPLATE = "Hello {{ name }}!"
_env = Environment(autoescape=select_autoescape())
_tmpl = _env.from_string(_TEMPLATE)

PAGE = """<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"UTF-8\"><title>SSTI Secure</title>\n<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css\"><style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}
.bn{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.93em;background:#238636}
.ctr{max-width:1100px;margin:0 auto;padding:20px}h1{font-size:1.35em;margin-bottom:4px}
h2{font-size:.97em;margin:14px 0 6px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}
.mt{color:#8b949e;font-size:.84em;margin-bottom:16px}
.bge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.74em;font-weight:600;margin-right:4px}
.bcwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}
.bowasp{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}
.bgrn{background:#0d4a1e;border:1px solid #238636;color:#3fb950}
.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}
.tb{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.87em;border-bottom:2px solid transparent;margin-bottom:-2px}
.tb.a{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}.tp{display:none}.tp.a{display:block}
.cd{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:12px}
.fg{margin-bottom:10px}.fg label{display:block;font-size:.81em;color:#8b949e;margin-bottom:3px}
.fg input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.87em}
.btn{padding:8px 16px;border-radius:5px;cursor:pointer;font-size:.87em;font-weight:600;border:none;margin-right:6px}.btn:hover{opacity:.85}
.bg{background:#238636;color:#fff}.bgr{background:#21262d;border:1px solid #30363d;color:#e6edf3}
.co{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:monospace;font-size:.79em;line-height:1.6;margin:6px 0;white-space:pre-wrap}
.co.g{border-left-color:#3fb950}
.bx{border-radius:6px;padding:10px 13px;font-size:.84em;margin:7px 0;line-height:1.5}
.bx.d{background:#4a0d0d;border:1px solid #da3633;color:#f85149}
.bx.s{background:#0d4a1e;border:1px solid #238636;color:#3fb950}
.bx.i{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.gd{display:grid;grid-template-columns:255px 1fr;gap:14px}
@media(max-width:660px){.g2,.gd{grid-template-columns:1fr}}
.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:9px;margin-bottom:7px}
.pl .lb{font-size:.74em;color:#58a6ff;font-weight:700;margin-bottom:2px}
.pl .pc{font-family:monospace;font-size:.77em;margin-bottom:3px;word-break:break-all}
.pl .pd{font-size:.76em;color:#8b949e;margin-bottom:4px}
.res{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:12px;margin-top:10px;min-height:48px}
table{width:100%;border-collapse:collapse;font-size:.81em}th,td{padding:7px 9px;border:1px solid #21262d}
th{background:#161b22;color:#8b949e}
code{background:#0d1117;padding:1px 4px;border-radius:2px;font-size:.84em;font-family:monospace}
p{margin-bottom:5px;line-height:1.55;font-size:.87em;color:#8b949e}
ul{padding-left:17px;color:#8b949e;font-size:.87em;line-height:1.85}
</style></head><body>
<div class="bn"><i class="fa-solid fa-circle-check"></i> SSTI LAB — SÉCURISÉ
<span>| Template fixe + Variable binding | CWE-94 | OWASP A03:2021 | Vulnérable: localhost:5005</span></div>
<div class="ctr">
<h1>SSTI — Version Sécurisée</h1>
<div class="mt"><span class="bge bgrn">Sécurisé</span><span class="bge bcwe">CWE-94</span><span class="bge bowasp">OWASP A03:2021</span></div>
<div class="tabs">
<button class="tb a" onclick="st(\'demo\',this)"><i class="fa-solid fa-flask"></i> Démonstration</button>
<button class="tb" onclick="st(\'theory\',this)"><i class="fa-solid fa-book"></i> Théorie</button>
<button class="tb" onclick="st(\'code\',this)"><i class="fa-solid fa-code"></i> Code</button>
<button class="tb" onclick="st(\'fix\',this)"><i class="fa-solid fa-shield-halved"></i> Correction</button>
</div>
<div id="t-demo" class="tp a">
<div class="gd">
<div><div class="cd"><h2><i class="fa-solid fa-crosshairs"></i> Testez les payloads SSTI</h2>
<div class="bx s"><i class="fa-solid fa-circle-check"></i> Les expressions Jinja2 sont traitées comme du <strong>texte brut</strong>, non évaluées.</div>
<div class="pl"><div class="lb">Payload 1 — Expression mathématique</div><div class="pc">{{7*7}}</div><div class="pd">Doit s'afficher littéralement, pas "49".</div><button class="btn bgr" onclick="f(\'{{7*7}}\')"><i class="fa-solid fa-play"></i> Tester</button></div>
<div class="pl"><div class="lb">Payload 2 — Accès config</div><div class="pc">{{config}}</div><div class="pd">Rejeté par la validation d\'entrée.</div><button class="btn bgr" onclick="f(\'{{config}}\')"><i class="fa-solid fa-play"></i> Tester</button></div>
<div class="pl"><div class="lb">Entrée normale</div><div class="pc">Alice</div><div class="pd">Résultat attendu : Hello Alice!</div><button class="btn bgr" onclick="f(\'Alice\')"><i class="fa-solid fa-play"></i> Tester</button></div>
</div></div>
<div><div class="cd"><h2><i class="fa-solid fa-circle-check"></i> Service de salutation sécurisé</h2>
<div class="bx s"><i class="fa-solid fa-shield-halved"></i> <strong>Défenses :</strong> Template fixe | Entrée = variable | Validation allowlist | Autoescape</div>
<div class="fg"><label>Votre nom (testez un payload)</label><input id="fn" placeholder="Alice, ou {{7*7}}, ou {{config}}"></div>
<button class="btn bg" onclick="g()"><i class="fa-solid fa-paper-plane"></i> Saluer</button>
</div>
<div class="res">
<div style="font-size:.82em;color:#8b949e;margin-bottom:6px">Résultat :</div>
<div id="ro" style="font-size:1.3em;font-weight:700;color:#3fb950">—</div>
<div id="rm" style="font-size:.75em;color:#6e7681;margin-top:6px"></div>
</div>
<div class="bx i" style="margin-top:10px"><i class="fa-solid fa-magnifying-glass"></i>
Comparez avec <a href="http://localhost:5005" style="color:#58a6ff">localhost:5005</a> :
même entrée <code>{{7*7}}</code> → 49 là-bas, texte ici.</div>
</div></div></div>
<div id="t-theory" class="tp">
<div class="g2">
<div><div class="cd">
<h2><i class="fa-solid fa-shield-halved"></i> Principe de correction</h2>
<p>La défense fondamentale : l\'entrée utilisateur doit être une <strong>variable</strong>, jamais une <strong>source de template</strong>.</p>
<div class="co g">
# Template FIXE défini par le développeur
TEMPLATE = "Hello {{ name }}!"
tmpl = Environment().from_string(TEMPLATE)

# L\'entrée est une VALEUR passée au template
result = tmpl.render(name=user_input)

# Input: {{7*7}}  →  name = "{{7*7}}" (string)
# Jinja2 affiche la valeur de {{ name }} = "{{7*7}}"
# Output: Hello {{7*7}}!  (texte, non évalué)
</div>
</div></div>
<div><div class="cd">
<h2><i class="fa-solid fa-list-check"></i> Défenses en profondeur</h2>
<ul>
<li><strong>Template fixe</strong> — jamais depuis user input</li>
<li><strong>Variable binding</strong> — render(name=input)</li>
<li><strong>Autoescape</strong> — encode HTML par défaut</li>
<li><strong>Validation d\'entrée</strong> — allowlist de caractères</li>
<li><strong>Sandboxing</strong> — SandboxedEnvironment Jinja2</li>
</ul>
<h2><i class="fa-solid fa-book-open"></i> Références</h2>
<div class="bx i">CWE-94 — Code Generation<br>OWASP A03:2021 — Injection<br>PortSwigger SSTI Lab</div>
</div></div>
</div></div>
<div id="t-code" class="tp">
<div class="g2">
<div><div class="cd">
<h2 style="color:#f85149"><i class="fa-solid fa-triangle-exclamation"></i> Code vulnérable (:5005)</h2>
<div class="co">
name = request.args.get("name")
# L\'entrée est intégrée dans le template
template_str = f"Hello {name}!"
env = Environment()
result = env.from_string(template_str).render()
# input {{7*7}} → template "Hello {{7*7}}!" → évalué → 49
</div></div></div>
<div><div class="cd">
<h2 style="color:#3fb950"><i class="fa-solid fa-circle-check"></i> Code sécurisé (ici)</h2>
<div class="co g">
# Template FIXE — jamais depuis user input
TEMPLATE = "Hello {{ name }}!"
tmpl = Environment(autoescape=True).from_string(TEMPLATE)

# Validation entrée
if not re.match(r"^[\w\s]{1,80}$", name):
    return error("Caractères invalides")

# Entrée = variable, jamais source de template
result = tmpl.render(name=name)
</div></div></div>
</div></div>
<div id="t-fix" class="tp">
<div class="g2">
<div><div class="cd">
<h2><i class="fa-solid fa-arrows-left-right"></i> Comparaison</h2>
<table>
<tr><th>Entrée</th><th style="color:#f85149">Vulnérable :5005</th><th style="color:#3fb950">Sécurisé ici</th></tr>
<tr><td><code>Alice</code></td><td>Hello Alice!</td><td>Hello Alice!</td></tr>
<tr><td><code>{{7*7}}</code></td><td style="color:#f85149">Hello 49! ← EXÉCUTÉ</td><td style="color:#3fb950">Hello {{7*7}}! (texte)</td></tr>
<tr><td><code>{{config}}</code></td><td style="color:#f85149">Config exposée</td><td style="color:#3fb950">Rejeté (validation)</td></tr>
</table>
</div></div>
<div><div class="cd">
<h2><i class="fa-solid fa-circle-check"></i> Règle fondamentale</h2>
<div class="bx s">Toujours passer les données utilisateur comme <strong>variables</strong> au template :<br><br><code>template.render(name=user_input)</code><br><br>Jamais construire la source du template depuis user input.</div>
</div></div>
</div></div>
</div>
<script>
function st(n,b){document.querySelectorAll(".tp").forEach(p=>p.classList.remove("a"));document.querySelectorAll(".tb").forEach(x=>x.classList.remove("a"));document.getElementById("t-"+n).classList.add("a");if(b)b.classList.add("a");}
function f(v){document.getElementById("fn").value=v;}
function g(){
  const name=document.getElementById("fn").value||"World";
  fetch("/api/greet?name="+encodeURIComponent(name)).then(r=>r.json()).then(d=>{
    const ro=document.getElementById("ro");
    const rm=document.getElementById("rm");
    if(d.blocked){ro.textContent="[BLOQUÉ] "+d.error;ro.style.color="#d29922";}
    else{ro.textContent=d.output;ro.style.color="#3fb950";}
    rm.textContent="Entrée : "+d.input;
  });
}
</script>
</body></html>"""


@app.route("/")
@app.route("/greet")
def greet() -> Any:
    return PAGE


@app.route("/api/greet")
def api_greet() -> Any:
    name = request.args.get("name", "World")
    if not _NAME_RE.match(name):
        return jsonify({"input": name, "error": "Caractères non autorisés ({{, }}, etc.)", "blocked": True}), 400
    result = _tmpl.render(name=name)
    return jsonify({"input": name, "output": result, "blocked": False})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
