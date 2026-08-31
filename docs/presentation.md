# Injection Security Lab — Presentation

## 1. Introduction

This presentation covers injection vulnerabilities — one of the most critical and
persistent categories in application security.

**Context:**
- OWASP Top 10 A03:2021 — Injection (includes XSS, SSTI, Command, LDAP, XPath, etc.)
- Present in the OWASP Top 10 since its inception in 2003
- Still responsible for thousands of real-world breaches

---

## 2. Definition of an Injection

An **injection** occurs when an attacker provides hostile data to an interpreter,
and that data is processed as code instead of as data.

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  User Input  │────►│   Application   │────►│   Interpreter    │
└──────────────┘     └─────────────────┘     └──────────────────┘
                              ▲                       ▲
                         "trusted"              SQL Engine
                            code                OS Shell
                                               Template Engine
                                               Browser (XSS)
```

The fundamental confusion: **data is mistaken for code**.

---

## 3. Principle of Functioning

### Normal operation (expected)

```
User input: "alice"
Query: SELECT * FROM users WHERE username='alice'
Result: User record for alice
```

### Injected operation (unexpected)

```
User input: "' OR '1'='1"
Query: SELECT * FROM users WHERE username='' OR '1'='1'
Result: ALL user records
```

The interpreter (database) sees both strings as part of the same instruction.

---

## 4. Why Injections Exist

Root causes:

1. **Mixing code and data** — building queries/commands by concatenating strings
2. **Trusting user input** — assuming input will be "reasonable"
3. **Lack of abstraction** — not using parameterized APIs that separate code from data
4. **Legacy code** — old patterns before secure APIs existed
5. **Copy-paste** — insecure examples perpetuated without security review

The pattern is always:
```python
# VULNERABLE — concatenation
query = "SELECT * FROM t WHERE id=" + user_id

# SECURE — separation
cursor.execute("SELECT * FROM t WHERE id=?", (user_id,))
```

---

## 5. Types of Injections

| Type | Interpreter | Classic Vector |
|------|------------|----------------|
| SQL | Database | String query building |
| XSS | Browser | HTML output without encoding |
| Command | OS Shell | subprocess with shell=True |
| SSTI | Template Engine | User-controlled template string |
| NoSQL | MongoDB | Operator objects in JSON query |
| LDAP | LDAP Server | Unescaped filter characters |
| XPath | XML Engine | Dynamic XPath construction |
| CSV | Spreadsheet | Formula starters in cells |
| Log | Log Viewer | Newlines in log messages |
| Header/CRLF | HTTP Client | CRLF in response headers |
| Expression | Eval Engine | eval() on user input |

---

## 6. Consequences

| Impact | Example |
|--------|---------|
| **Authentication bypass** | Log in without knowing password |
| **Data exfiltration** | Extract entire database |
| **Remote Code Execution** | Run OS commands on server |
| **Session hijacking** | Steal user cookies via XSS |
| **Privilege escalation** | Access admin functions |
| **Data tampering** | Modify production data |
| **Log forgery** | Erase or falsify audit trail |
| **Phishing** | Inject fake content into pages |

---

## 7. Detection

### Manual Testing

- Insert special characters: `'`, `"`, `;`, `|`, `&&`, `\n`, `{{`, `<`, `>`
- Observe error messages, unexpected output, or behavior changes
- Compare expected vs. actual response

### Automated Testing

- Static Analysis (Semgrep, Bandit)
- DAST (OWASP ZAP, Burp Suite)
- Dependency scanning (pip-audit, npm audit)
- Linting rules (ruff, eslint)

---

## 8. Prevention

### Universal principle

```
Never concatenate user input into code/command/query strings.
Always use APIs that keep code and data separate.
```

### Specific defenses

| Injection | Defense |
|-----------|---------|
| SQL | Prepared statements, ORM |
| XSS | Output encoding, CSP, Jinja2 auto-escape |
| Command | subprocess list args, shell=False |
| SSTI | Fixed templates, user input as variables |
| NoSQL | Schema validation (Pydantic), type checking |
| LDAP | escape_filter_chars() |
| XPath | Value escaping, allowlist |
| CSV | Sanitize formula starters |
| Log | Structured logging, strip control chars |
| Header | Strip CRLF, allowlist values |
| Expression | AST-based parser, never eval() |

---

## 9. Secure Coding

### Defense in Depth

```
1. Input Validation   — reject bad input at the boundary
2. Safe APIs          — parameterized queries, list args
3. Output Encoding    — encode for the output context
4. Least Privilege    — minimal permissions
5. Error Handling     — no sensitive info in errors
6. Monitoring         — detect and alert on injection attempts
```

### Code Review Checklist

```
[ ] No string concatenation in queries
[ ] No shell=True in subprocess
[ ] No eval() on user input
[ ] No Template(user_input).render()
[ ] All HTML output through auto-escaping templates
[ ] All header values validated and CRLF-stripped
[ ] CSV values sanitized
[ ] Structured logging used
```

---

## 10. Demonstrations

See [demo-script.md](demo-script.md) for step-by-step demonstration instructions.

### Lab Summary

| Lab | Port Vuln | Port Secure | Proof of Concept |
|-----|-----------|-------------|-----------------|
| XSS | 5001 | 5002 | `<script>` → executed / text |
| Command | 5003 | 5004 | `; echo INJECTED` → output |
| SSTI | 5005 | 5006 | `{{7*7}}` → 49 / literal |
| NoSQL | 5007 | 5008 | `$ne` → auth bypass |
| LDAP | 5009 | 5010 | `*` → all users |
| XPath | 5011 | 5012 | `' or '1'='1` → all users |
| CSV | 5013 | 5014 | `=SUM(1+1)` → formula / tab |
| Log | 5015 | 5016 | `\n` → fake entry |
| Header | 5017 | 5018 | `\r\n` → injected header |
| Expression | 5019 | 5020 | `"x"*3` → string / blocked |

---

## 11. Vulnerable vs. Secure Comparison

### XSS

```
VULNERABLE                          SECURE
──────────────────────────────────  ───────────────────────────────────────
User: <script>alert(1)</script>     User: <script>alert(1)</script>
Output: <p><script>...</script></p> Output: <p>&lt;script&gt;...&lt;/script&gt;</p>
Effect: Script executes             Effect: Displayed as text
```

### Command Injection

```
VULNERABLE                          SECURE
──────────────────────────────────  ───────────────────────────────────────
cmd = "ping " + user_input          subprocess.run(["ping", user_input])
Input: 127.0.0.1; id                Input: 127.0.0.1; id
Shell: /bin/sh -c "ping 127... ; id" Shell: N/A — no shell
Effect: id command executes         Effect: ping receives literal string
```

### Expression Injection

```
VULNERABLE                          SECURE
──────────────────────────────────  ───────────────────────────────────────
result = eval(user_expr)            result = safe_eval(user_expr)
Input: "x"*3                        Input: "x"*3
Effect: Returns "xxx"               Effect: ExpressionError — not a number
```

---

## 12. Conclusion

Injection vulnerabilities persist because they are:
- Easy to introduce (convenience APIs are often unsafe)
- Hard to spot in code review
- High impact when exploited

The defense is **always conceptually the same**:
1. Never trust user input as code
2. Use APIs that separate data from commands
3. Validate at the boundary

> "All user input is potentially hostile until proven safe."
