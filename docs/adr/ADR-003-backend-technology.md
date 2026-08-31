# ADR-003: Backend Technology Choices

**Date:** 2024-01-01  
**Status:** Accepted

---

## Context

Each lab needs a backend to demonstrate vulnerabilities. The technology must:
- Be simple to understand for learners
- Have clear vulnerable/secure patterns
- Support all required injection types
- Allow for reproducible demos

---

## Decision

**Primary backend: Python + Flask**

Rationale:
- Widely known in security community
- Clear, readable code
- Jinja2 natively demonstrates SSTI
- subprocess demonstrates command injection clearly
- lxml handles XPath
- pymongo handles NoSQL injection
- ldap3 handles LDAP

**Testing: pytest**

**Linting: ruff**

**Frontend: Plain HTML/CSS/JavaScript** served by Flask templates.
Dashboard uses slightly more structure but remains HTML/JS (no framework required).

---

## Technology per Lab

| Lab               | Technology                    |
|-------------------|-------------------------------|
| XSS               | Flask + Jinja2 + HTML         |
| Command Injection | Python subprocess             |
| SSTI              | Flask + Jinja2                |
| NoSQL Injection   | Flask + pymongo + MongoDB     |
| LDAP Injection    | Flask + ldap3 + OpenLDAP      |
| XPath Injection   | Flask + lxml                  |
| CSV Injection     | Flask + csv module            |
| Log Injection     | Flask + logging module        |
| Header Injection  | Flask + HTTP response headers |
| Expression Inj.   | Flask + custom AST parser     |

---

## Alternatives Considered

| Option | Decision |
|--------|----------|
| FastAPI | Flask chosen for simpler HTML rendering |
| Node.js | Python more familiar in security context |
| Java Spring | Too heavy for educational containers |
| React frontend | Plain HTML is sufficient and simpler |

---

## Consequences

- All backends are Python 3.11+
- Each lab has its own requirements.txt
- Common test utilities are in shared/test-utils/
- Flask debug mode is OFF in containers (FLASK_DEBUG=0)
