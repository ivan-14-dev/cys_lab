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

## Closing Summary

| Lab | Vulnerability | Proof | Fix |
|-----|--------------|-------|-----|
| XSS | Raw HTML output | Script executed | Jinja2 auto-escape |
| Command | shell=True + concat | Extra command ran | List args, no shell |
| SSTI | User as template | `{{7*7}}` = 49 | Fixed template |
| NoSQL | No type check | `$ne` bypasses auth | Pydantic schema |
| Log | String concat | Fake log entry | Structured logging |
| Expression | eval() | `"x"*3` works | AST math parser |

> **Core message:** The fix is always to separate data from code.
> Use APIs designed for this separation, not string concatenation.
