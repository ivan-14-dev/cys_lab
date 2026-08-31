# ADR-004: Security Model

**Date:** 2024-01-01  
**Status:** Accepted

---

## Context

This lab contains intentionally vulnerable code. We must define a clear security model
that separates "intentional lab vulnerability" from "unintentional lab infrastructure risk".

---

## Decision

### Threat Model Boundaries

```
INSIDE LAB (intentional)        OUTSIDE LAB (never allowed)
─────────────────────────       ────────────────────────────
XSS in comment form         vs  XSS targeting real users
Command injection in ping   vs  Reverse shell to internet
SSTI in template render     vs  File system destruction
NoSQL operator injection     vs  Data exfiltration outside lab
LDAP filter manipulation    vs  Attack on real LDAP server
```

### Proof-of-Concept Constraints

All demonstrations must use only:
- Display of a message (e.g., `INJECTION_DETECTED`)
- Simple computation (e.g., `7 * 7 = 49`)
- Read of a **lab-created** file (not system files)
- Display of an environment variable that is not sensitive
- Modification of lab test data

### Explicitly Forbidden Payloads

- `rm -rf` or any destructive filesystem commands
- Reverse shell or bind shell
- `/etc/passwd` or `/etc/shadow` reads
- Network port scanning
- Any payload targeting the host or external systems

---

## Consequences

- All exploit payloads in documentation use sanitized examples
- Documentation marks dangerous patterns clearly
- Tests verify both vulnerability AND safety boundaries
- Lab data is entirely fictional
- No real credentials anywhere in the project
