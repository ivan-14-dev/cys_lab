# SQL Injection — Theory

> **SQL Injection is intentionally excluded from the practical labs.**
>
> This document covers the theory, principles, and defenses.
> Practical demonstrations are available for all other injection types.

---

## Definition

SQL Injection (SQLi) is a vulnerability where an attacker inserts or "injects"
malicious SQL code into a query that an application sends to its database.

When successful, the attacker can:
- Read sensitive data from the database
- Modify or delete database data
- Execute administrative operations
- Bypass authentication
- In some configurations, execute OS commands

---

## Principle

### Vulnerable Pattern

```python
# VULNERABLE — NEVER DO THIS
username = request.form["username"]
password = request.form["password"]

query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
db.execute(query)
```

### Attack Example (Conceptual)

```
Normal query:
  SELECT * FROM users WHERE username='alice' AND password='secret'

Injected username: admin'--
Result query:
  SELECT * FROM users WHERE username='admin'--' AND password='anything'
  -- Everything after -- is a comment → password check is skipped
```

---

## Attack Categories

| Type | Technique | Impact |
|------|-----------|--------|
| Classic / In-band | UNION, comment tricks | Direct data retrieval |
| Blind Boolean | True/false conditions | Infer data bit by bit |
| Blind Time-based | SLEEP(), WAITFOR | Infer data by timing |
| Out-of-band | DNS exfiltration | Data via side channel |
| Error-based | Trigger DB errors | Info disclosure |

---

## Consequences

- **Authentication bypass** — Log in without knowing the password
- **Data exfiltration** — Extract all users, passwords, sensitive records
- **Data manipulation** — INSERT, UPDATE, DELETE arbitrary records
- **Schema enumeration** — Discover table and column names
- **Privilege escalation** — Execute as DBA in some configurations
- **OS command execution** — Via `xp_cmdshell` (SQL Server) or similar

---

## Prevention

### 1. Prepared Statements (Parameterized Queries)

```python
# SECURE — Python + sqlite3
cursor.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password)
)

# SECURE — Python + psycopg2
cursor.execute(
    "SELECT * FROM users WHERE username = %s AND password = %s",
    (username, password)
)
```

The database driver handles quoting. User data is **never** part of the SQL string.

### 2. Parameterized Queries (ORM)

```python
# SECURE — SQLAlchemy ORM
user = session.query(User).filter_by(username=username, password=hashed_password).first()

# SECURE — SQLAlchemy Core
stmt = select(User).where(User.username == username)
```

### 3. Input Validation

```python
# Allowlist validation
import re
if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
    raise ValueError("Invalid username format")
```

Validation is **not a substitute** for parameterized queries — always use both.

### 4. Stored Procedures

When stored procedures use parameterized inputs, they are safe:
```sql
-- SECURE stored procedure
CREATE PROCEDURE GetUser
    @username NVARCHAR(50),
    @password NVARCHAR(50)
AS
    SELECT * FROM users WHERE username = @username AND password = @password;
```

### 5. ORM Usage

Modern ORMs (SQLAlchemy, Django ORM, Hibernate) use parameterization by default.
Avoid raw query methods (`raw()`, `execute()`) with string concatenation.

### 6. Principle of Least Privilege

```sql
-- Application DB user should NOT have DROP, CREATE, or admin rights
GRANT SELECT, INSERT, UPDATE ON app_schema.* TO 'app_user'@'localhost';
```

---

## Defenses Summary

| Defense | Effectiveness | Notes |
|---------|---------------|-------|
| Prepared statements | ★★★★★ | Primary defense |
| ORM with parameterization | ★★★★★ | Safest for application code |
| Input validation | ★★★ | Defense-in-depth only |
| WAF (Web Application Firewall) | ★★ | Can be bypassed, not primary |
| Stored procedures | ★★★★ | Only if parameterized |
| Least privilege | ★★★★ | Limits blast radius |
| Error handling | ★★★ | Prevents info disclosure |

---

## OWASP / CWE References

- **OWASP Top 10 A03:2021** — Injection
- **CWE-89** — Improper Neutralization of Special Elements in SQL Commands
- **OWASP SQL Injection Prevention Cheat Sheet**:
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **OWASP Query Parameterization Cheat Sheet**:
  https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
