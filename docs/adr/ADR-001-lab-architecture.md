# ADR-001: Lab Architecture

**Date:** 2024-01-01  
**Status:** Accepted

---

## Context

We need to build an educational cybersecurity lab demonstrating multiple injection
vulnerability types. The architecture must:

- Support 10+ independent labs
- Allow vulnerable and secure versions to run simultaneously
- Be portable and reproducible
- Be completely isolated from external networks
- Be usable for live presentations

---

## Decision

Use **Docker Compose** with one container per lab variant (vulnerable/secure).

Each lab follows a standard structure:
```
labs/<lab-name>/
  vulnerable/      — intentionally vulnerable app
  secure/          — patched implementation
  tests/           — automated tests for both versions
  README.md        — lab documentation
```

A central **dashboard** at port 8080 links all labs.

---

## Alternatives Considered

| Option | Pros | Cons |
|--------|------|------|
| Single monolithic app | Simple | Hard to isolate, hard to demonstrate |
| VM per lab | Strong isolation | Too heavy, slow to start |
| Docker Compose (chosen) | Portable, fast, isolated networking | Docker not a true security boundary |
| Kubernetes | Production-realistic | Overkill for educational lab |

---

## Consequences

- Each lab is independently buildable and startable
- Labs share a Docker internal network (`lab-network`)
- No container reaches the internet
- Standard structure makes it easy to add new labs
- Ports are only exposed to localhost
