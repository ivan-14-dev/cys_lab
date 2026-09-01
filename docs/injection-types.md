# Injection Types — Reference Guide

## OWASP / CWE Mapping Table

| Injection Type      | CWE        | OWASP     | Cause                          | Impact                          | Mitigation                        |
|---------------------|------------|-----------|--------------------------------|---------------------------------|-----------------------------------|
| XSS                 | CWE-79     | A03:2021  | Unescaped output in HTML       | Session hijack, phishing        | Output encoding, CSP              |
| Command Injection   | CWE-78     | A03:2021  | shell=True + concatenation     | RCE on server                   | subprocess list, no shell         |
| SSTI                | CWE-94     | A03:2021  | User data as template string   | RCE via template engine         | Fixed templates, sandboxing       |
| SQL Injection       | CWE-89     | A03:2021  | String query concatenation     | Data breach, auth bypass        | Prepared statements, ORM          |
| NoSQL Injection     | CWE-943    | A03:2021  | Untrusted JSON as query filter | Auth bypass, data exfiltration  | Type validation, schema           |
| LDAP Injection      | CWE-90     | A03:2021  | String filter concatenation    | Auth bypass, info disclosure    | LDAP escaping, parameterization   |
| XPath Injection     | CWE-643    | A03:2021  | Dynamic XPath construction     | Auth bypass, data extraction    | Parameterized XPath               |
| CSV Injection       | CWE-1236   | A03:2021  | Raw values in CSV cells        | Formula execution in spreadsheet| Sanitize formula starters         |
| Log Injection       | CWE-117    | A09:2021  | Unsanitized log concatenation  | Log forgery, log poisoning      | Structured logging, encoding      |
| Header Injection    | CWE-113    | A03:2021  | CRLF in header values          | Response splitting, redirect    | Strip CRLF, validate header vals  |
| Expression Injection| CWE-94     | A03:2021  | eval() on user input           | RCE, sandbox escape             | Safe parser, allowlist operators  |
| SSRF                | CWE-918    | A10:2021  | Unrestricted URL fetch         | Internal service access         | URL allowlist, block private IPs  |
| IDOR                | CWE-639    | A01:2021  | No authorization on object ref | Data breach, privilege escalation| Per-request authorization check  |
| Path Traversal      | CWE-22     | A01:2021  | Unvalidated file path          | Arbitrary file read             | basename + realpath + prefix check|

---

## 1. Cross-Site Scripting (XSS)

**Type:** Output injection into HTML  
**Interpreter:** Browser HTML/JS engine  

```
User input: <script>alert('xss')</script>
Vulnerable output: <p><script>alert('xss')</script></p>  ← executed
Secure output:    <p>&lt;script&gt;alert('xss')&lt;/script&gt;</p>  ← data
```

---

## 2. Command Injection

**Type:** OS command injection  
**Interpreter:** OS shell  

```
User input: 127.0.0.1; echo INJECTED
Vulnerable: os.system("ping " + user_input)  ← shell executes INJECTED
Secure:     subprocess.run(["ping", user_input], shell=False)
```

---

## 3. Server-Side Template Injection (SSTI)

**Type:** Template engine injection  
**Interpreter:** Jinja2 / Twig / Freemarker  

```
User input: {{7*7}}
Vulnerable: template = Template(user_input); template.render()  ← returns 49
Secure:     template = Template("Hello {{ name }}"); template.render(name=user_input)
```

---

## 4. NoSQL Injection

**Type:** Query operator injection  
**Interpreter:** MongoDB query engine  

```
User input: {"$ne": null}   (as password field)
Vulnerable: db.users.find({"user": u, "pass": json_body["pass"]})  ← bypasses auth
Secure:     validate type is string, not object
```

---

## 5. LDAP Injection

**Type:** LDAP filter injection  
**Interpreter:** LDAP server  

```
User input: *)(uid=*))(|(uid=*
Vulnerable: f"(uid={user_input})"  ← filter logic altered
Secure:     escape_filter_chars(user_input)
```

---

## 6. XPath Injection

**Type:** XPath query injection  
**Interpreter:** XML query engine  

```
User input: ' or '1'='1
Vulnerable: f"//user[name='{user_input}']"  ← returns all users
Secure:     parameterized XPath or schema validation
```

---

## 7. CSV Injection

**Type:** Formula injection in spreadsheet cells  
**Interpreter:** Spreadsheet application (Excel, LibreOffice)  

```
User input: =HYPERLINK("http://attacker.com","click")
Vulnerable: writer.writerow([name, email, company])  ← formula active
Secure:     sanitize cells starting with =, +, -, @
```

---

## 8. Log Injection

**Type:** Log entry manipulation  
**Interpreter:** Log viewer / SIEM  

```
User input: admin\nINFO 2024-01-01 Logged in as: root
Vulnerable: logger.info("Login attempt: " + username)  ← fake log entry injected
Secure:     logger.info("Login attempt", extra={"username": username})
```

---

## 9. HTTP Header / CRLF Injection

**Type:** HTTP response header injection  
**Interpreter:** HTTP client / browser  

```
User input: value\r\nSet-Cookie: session=hijacked
Vulnerable: response.headers["X-User"] = user_input  ← cookie injected
Secure:     strip \r\n from all header values
```

---

## 10. Expression / Code Injection

**Type:** Dynamic code evaluation  
**Interpreter:** Python eval() / JavaScript eval()  

```
User input: __import__('os').system('id')
Vulnerable: eval(user_input)  ← system command executed
Secure:     AST-based math parser, allowlist of operators
```

---

## 11. SQL Injection

**Type:** SQL query injection  
**Interpreter:** SQL database engine  

```
User input: ' OR '1'='1
Vulnerable: f"SELECT * FROM users WHERE user='{user_input}'"  ← returns all rows
Secure:     cursor.execute("SELECT * FROM users WHERE user=?", (user_input,))
```

---

## 12. Server-Side Request Forgery (SSRF)

**Type:** URL injection into server-side HTTP requests  
**Interpreter:** HTTP client library  

```
User input: http://localhost:5000/internal/flag
Vulnerable: requests.get(user_url)  ← fetches internal service
Secure:     validate URL against allowlist, block private IPs
```

---

## 13. Insecure Direct Object Reference (IDOR)

**Type:** Authorization bypass via predictable identifiers  
**Interpreter:** Application access control logic  

```
User input: /api/user/3  (admin's ID)
Vulnerable: return db.get_user(uid)  ← no ownership check
Secure:     if uid != current_user.id: return 403
```

---

## 14. Path Traversal

**Type:** File path manipulation  
**Interpreter:** OS filesystem  

```
User input: ../../../../etc/passwd
Vulnerable: open(os.path.join(base_dir, user_input))  ← escapes base directory
Secure:     os.path.basename(user_input)  → strips directory traversal
```
