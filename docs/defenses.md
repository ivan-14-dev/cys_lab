# Defenses Against Injection Attacks

## Universal Principles

### 1. Separate Data from Code

The root cause of all injection vulnerabilities is mixing untrusted data with
code/command/query syntax. The fix is always the same:

```
VULNERABLE:  code + data = executed_string
SECURE:      code(data) = code uses data as parameter
```

### 2. Input Validation (Allowlist)

```python
import re

# GOOD — allowlist what is expected
def validate_username(value: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', value))

# BAD — blocklist is always incomplete
def validate_username_bad(value: str) -> bool:
    return "<script>" not in value  # attacker uses <SCRIPT>, &#60;script&#62;, etc.
```

### 3. Output Encoding

Encode data for the context where it will be used:
- **HTML**: `&lt;`, `&gt;`, `&amp;`, `&quot;`
- **URL**: percent-encoding
- **JavaScript**: JSON serialization
- **SQL**: parameterized queries
- **Shell**: `shlex.quote()` or argument lists
- **LDAP**: `ldap3.utils.conv.escape_filter_chars()`
- **XPath**: value escaping

### 4. Use Safe APIs

| Context | Unsafe | Safe |
|---------|--------|------|
| SQL | string concatenation | prepared statements |
| Shell | `os.system(cmd)` / `shell=True` | `subprocess.run([...], shell=False)` |
| Template | `Template(user_input)` | `Template("...{{ var }}").render(var=input)` |
| Eval | `eval(expr)` | AST-based safe parser |
| LDAP | string filter | `escape_filter_chars()` |
| XML/XPath | string query | parameterized XPath |

### 5. Principle of Least Privilege

- Database users: only SELECT/INSERT/UPDATE needed, never DROP
- OS users: non-root, minimal capabilities
- Docker: `cap_drop: ALL`, `no-new-privileges: true`
- File system: read-only where possible

---

## Defense-in-Depth

No single control is sufficient. Layer defenses:

```
Layer 1: Input validation (allowlist)
Layer 2: Safe API / parameterization
Layer 3: Output encoding
Layer 4: Least privilege
Layer 5: Error handling (no info leakage)
Layer 6: Logging and monitoring
Layer 7: WAF (supplementary, not primary)
```

---

## Secure Coding Checklist

- [ ] No string concatenation in queries (SQL, LDAP, XPath)
- [ ] No `shell=True` in subprocess calls
- [ ] No `eval()` on user input
- [ ] No direct template rendering from user strings
- [ ] Output encoding in all HTML rendering
- [ ] CRLF stripping in HTTP headers
- [ ] CSV formula sanitization
- [ ] Structured logging (no string concatenation in logs)
- [ ] Input validation on all external inputs
- [ ] Error messages do not leak system information
