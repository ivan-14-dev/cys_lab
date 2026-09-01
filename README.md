# Injection Security Lab

> **Educational and isolated cybersecurity laboratory for studying injection vulnerabilities.**

> ⚠️ EDUCATIONAL USE ONLY — LOCAL SANDBOX ONLY — DO NOT EXPOSE TO THE INTERNET

---

## Dashboard

![Dashboard](docs/screenshots/dashboard.png)

---

## Quick Start

```bash
cp .env.example .env
make build
make up
# Open http://localhost:8080
```

---

## Labs — 14 types de vulnérabilités, 145 points

| Lab                | Points | Difficulty | Port vuln | Port secure | OWASP    |
|--------------------|--------|------------|-----------|-------------|----------|
| XSS                | 10     | Easy       | 5001      | 5002        | A03:2021 |
| Command Injection  | 15     | Medium     | 5003      | 5004        | A03:2021 |
| SSTI               | 15     | Medium     | 5005      | 5006        | A03:2021 |
| NoSQL Injection    | 10     | Medium     | 5007      | 5008        | A03:2021 |
| LDAP Injection     | 10     | Medium     | 5009      | 5010        | A03:2021 |
| XPath Injection    | 10     | Medium     | 5011      | 5012        | A03:2021 |
| CSV Injection      | 5      | Easy       | 5013      | 5014        | A03:2021 |
| Log Injection      | 5      | Easy       | 5015      | 5016        | A09:2021 |
| Header Injection   | 5      | Easy       | 5017      | 5018        | A03:2021 |
| Expression Inject. | 10     | Medium     | 5019      | 5020        | A03:2021 |
| SQL Injection      | 15     | Medium     | 5021      | 5022        | A03:2021 |
| SSRF               | 15     | Hard       | 5023      | 5024        | A10:2021 |
| IDOR               | 10     | Easy       | 5025      | 5026        | A01:2021 |
| Path Traversal     | 10     | Medium     | 5027      | 5028        | A01:2021 |

**Total: 145 points**

---

## Screenshots des labs

Chaque lab propose une interface avec **4 onglets** : Démonstration · Théorie · Code · Correction.

---

### 1. Cross-Site Scripting (XSS) · CWE-79

L'entrée utilisateur est rendue sans encodage HTML → les scripts s'exécutent dans le navigateur.

| Vulnérable (`:5001`) | Sécurisé (`:5002`) |
|---|---|
| ![XSS Vulnerable](docs/screenshots/xss-vulnerable.png) | ![XSS Secure](docs/screenshots/xss-secure.png) |

**Payload demo :** `<img src=x onerror="document.title='XSS_PWNED'">` → titre de l'onglet change  
**Correction :** Jinja2 auto-escaping + Content-Security-Policy `script-src 'none'`

---

### 2. Command Injection · CWE-78

`shell=True` + concaténation de chaînes → l'OS shell exécute les commandes injectées.

| Vulnérable (`:5003`) | Sécurisé (`:5004`) |
|---|---|
| ![Command Vulnerable](docs/screenshots/command-injection-vulnerable.png) | ![Command Secure](docs/screenshots/command-injection-secure.png) |

**Payload demo :** `127.0.0.1; echo INJECTION_DETECTED` → commande exécutée après le ping  
**Correction :** `subprocess.run(["ping", target], shell=False)` + allowlist

---

### 3. Server-Side Template Injection (SSTI) · CWE-94

L'entrée utilisateur devient la source du template Jinja2 → les expressions sont évaluées.

| Vulnérable (`:5005`) | Sécurisé (`:5006`) |
|---|---|
| ![SSTI Vulnerable](docs/screenshots/ssti-vulnerable.png) | ![SSTI Secure](docs/screenshots/ssti-secure.png) |

**Payload demo :** `{{7*7}}` → retourne `Hello 49!` (calculé par Jinja2)  
**Correction :** Template fixe `"Hello {{ name }}!"`, entrée passée comme variable

---

### 4. NoSQL Injection · CWE-943

Les objets opérateurs MongoDB (`$ne`, `$gt`) acceptés comme valeurs de filtre bypassent l'auth.

| Vulnérable (`:5007`) | Sécurisé (`:5008`) |
|---|---|
| ![NoSQL Vulnerable](docs/screenshots/nosql-vulnerable.png) | ![NoSQL Secure](docs/screenshots/nosql-secure.png) |

**Payload demo :** `{"password": {"$ne": null}}` → authentifié sans mot de passe  
**Correction :** Pydantic enforce `str` pour tous les champs de login

---

### 5. LDAP Injection · CWE-90

Les caractères spéciaux LDAP non échappés modifient la logique du filtre de recherche.

| Vulnérable (`:5009`) | Sécurisé (`:5010`) |
|---|---|
| ![LDAP Vulnerable](docs/screenshots/ldap-vulnerable.png) | ![LDAP Secure](docs/screenshots/ldap-secure.png) |

**Payload demo :** `*` → retourne tous les utilisateurs  
**Correction :** Allowlist + échappement RFC 4515 (`* → \2a`)

---

### 6. XPath Injection · CWE-643

La concaténation dans les requêtes XPath modifie la logique d'accès aux données XML.

| Vulnérable (`:5011`) | Sécurisé (`:5012`) |
|---|---|
| ![XPath Vulnerable](docs/screenshots/xpath-vulnerable.png) | ![XPath Secure](docs/screenshots/xpath-secure.png) |

**Payload demo :** `' or '1'='1` → retourne tous les utilisateurs  
**Correction :** Validation allowlist `^[a-zA-Z0-9_-]{1,32}$`

---

### 7. CSV Injection · CWE-1236

Les formules non sanitisées dans les cellules CSV s'exécutent à l'ouverture du fichier.

| Vulnérable (`:5013`) | Sécurisé (`:5014`) |
|---|---|
| ![CSV Vulnerable](docs/screenshots/csv-vulnerable.png) | ![CSV Secure](docs/screenshots/csv-secure.png) |

**Payload demo :** `=SUM(1+1)*10` comme nom → formule active dans le CSV exporté  
**Correction :** Préfixer les cellules commençant par `= + - @` avec un tab

---

### 8. Log Injection · CWE-117

Les caractères `\n \r` dans les messages de log créent de fausses entrées d'audit.

| Vulnérable (`:5015`) | Sécurisé (`:5016`) |
|---|---|
| ![Log Vulnerable](docs/screenshots/log-vulnerable.png) | ![Log Secure](docs/screenshots/log-secure.png) |

**Payload demo :** `alice\nINFO [INFO] Login SUCCESS for: root` → fausse ligne de log  
**Correction :** Logging structuré `logger.info("msg", extra={"username": u})`

---

### 9. HTTP Header / CRLF Injection · CWE-113

Les séquences `\r\n` dans les valeurs de headers injectent de nouveaux headers HTTP.

| Vulnérable (`:5017`) | Sécurisé (`:5018`) |
|---|---|
| ![Header Vulnerable](docs/screenshots/header-vulnerable.png) | ![Header Secure](docs/screenshots/header-secure.png) |

**Payload demo :** `en%0d%0aX-Injected: CRLF_DETECTED` → header injecté dans la réponse  
**Correction :** Rejet de `\r \n \x00` + allowlist des valeurs autorisées

---

### 10. Expression / Code Injection · CWE-94

`eval()` sur l'entrée utilisateur permet l'exécution d'expressions Python arbitraires.

| Vulnérable (`:5019`) | Sécurisé (`:5020`) |
|---|---|
| ![Expression Vulnerable](docs/screenshots/expression-vulnerable.png) | ![Expression Secure](docs/screenshots/expression-secure.png) |

**Payload demo :** `"injection"*3` → retourne une chaîne (pas un nombre !)  
**Correction :** Parser AST avec allowlist de nœuds math uniquement

---

### 11. SQL Injection · CWE-89

La concaténation de chaînes dans les requêtes SQL permet bypass d'auth et extraction de données.

| Vulnérable (`:5021`) | Sécurisé (`:5022`) |
|---|---|
| ![SQL Vulnerable](docs/screenshots/sql-vulnerable.png) | ![SQL Secure](docs/screenshots/sql-secure.png) |

**Payloads demo :**
- `' OR '1'='1` → bypass (retourne le premier utilisateur)
- `admin'--` → bypass ciblé admin (MDP ignoré via commentaire SQL)
- `' UNION SELECT 1,'vol','data','admin'--` → injection UNION, extraction arbitraire

**Correction :** Requêtes paramétrées `cursor.execute("WHERE id = ?", (id,))`

---

### 12. SSRF — Server-Side Request Forgery · CWE-918

Le serveur effectue des requêtes HTTP avec des URLs non validées → accès aux services internes.

| Vulnérable (`:5023`) | Sécurisé (`:5024`) |
|---|---|
| ![SSRF Vulnerable](docs/screenshots/ssrf-vulnerable.png) | ![SSRF Secure](docs/screenshots/ssrf-secure.png) |

**Payload demo :** `http://localhost:5000/internal/flag` → flag interne exposé via SSRF  
**Correction :** Allowlist de domaines + blocage des IPs privées

---

### 13. IDOR — Insecure Direct Object Reference · CWE-639

Les IDs utilisateur ne sont pas vérifiés → accès aux profils d'autres utilisateurs.

| Vulnérable (`:5025`) | Sécurisé (`:5026`) |
|---|---|
| ![IDOR Vulnerable](docs/screenshots/idor-vulnerable.png) | ![IDOR Secure](docs/screenshots/idor-secure.png) |

**Payload demo :** `/api/user/3` → profil admin exposé sans autorisation  
**Correction :** Vérification d'autorisation par requête

---

### 14. Path Traversal · CWE-22

Les séquences `../` dans les noms de fichiers permettent de lire des fichiers hors du répertoire autorisé.

| Vulnérable (`:5027`) | Sécurisé (`:5028`) |
|---|---|
| ![Path Traversal Vulnerable](docs/screenshots/pathtraversal-vulnerable.png) | ![Path Traversal Secure](docs/screenshots/pathtraversal-secure.png) |

**Payload demo :** `../../../../tmp/flag.txt` → fichier flag lu via traversée  
**Correction :** `os.path.basename()` + `os.path.realpath()` + vérification de préfixe

---

## Architecture

```
HOST MACHINE
  localhost:8080         →  Dashboard (portail central)
  localhost:5001/5002    →  XSS (vuln/secure)
  localhost:5003/5004    →  Command Injection
  localhost:5005/5006    →  SSTI
  localhost:5007/5008    →  NoSQL Injection
  localhost:5009/5010    →  LDAP Injection
  localhost:5011/5012    →  XPath Injection
  localhost:5013/5014    →  CSV Injection
  localhost:5015/5016    →  Log Injection
  localhost:5017/5018    →  Header Injection
  localhost:5019/5020    →  Expression Injection
  localhost:5021/5022    →  SQL Injection
  localhost:5023/5024    →  SSRF
  localhost:5025/5026    →  IDOR
  localhost:5027/5028    →  Path Traversal

  [ lab-network: internal only, no external internet access ]
```

---

## Commands

```bash
make build       # Build all containers
make up          # Start the lab  →  http://localhost:8080
make down        # Stop the lab
make test        # Run all 93 tests
make clean       # Remove containers and volumes

# Individual labs
make lab-xss
make lab-command
make lab-ssti
make lab-nosql
make lab-ldap
make lab-xpath
make lab-csv
make lab-log
make lab-header
make lab-expression
make lab-sql
make lab-ssrf
make lab-idor
make lab-pathtraversal
```

---

## Documentation

- [Introduction](docs/introduction.md)
- [Injection Types](docs/injection-types.md)
- [Threat Model](docs/threat-model.md)
- [Defenses](docs/defenses.md)
- [SQL Injection Theory](docs/sql-injection-theory.md)
- [Presentation](docs/presentation.md)
- [Demo Script](docs/demo-script.md)
- [Final Security Review](docs/final-security-review.md)
- [ADR](docs/adr/)

---

## Security Warning

This sandbox **must** be run on a **dedicated lab machine** or **isolated VM**.

- **Never** expose lab ports to the internet
- Docker is NOT a security boundary
- See [SECURITY.md](SECURITY.md)

---

## License

MIT — Educational use only. See [LICENSE](LICENSE).
