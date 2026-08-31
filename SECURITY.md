# Security Policy — Injection Security Lab

## Educational Context

This repository contains **intentionally vulnerable** code created for educational purposes.
It is a cybersecurity laboratory designed to demonstrate injection vulnerabilities in a
**controlled, isolated environment**.

---

## Scope

All vulnerabilities in this project are:

- **Intentional** — created to demonstrate security concepts
- **Isolated** — contained within Docker containers on a local network
- **Inoffensive** — demonstrations use only local, harmless proof-of-concepts
- **Reversible** — no persistent changes to the host system

---

## Mandatory Rules for Lab Users

### DO

- Run on a dedicated lab machine or isolated VM
- Use only on a trusted local network
- Keep Docker updated
- Run with non-root host user when possible
- Study and understand the vulnerabilities before exploiting

### DO NOT

- Expose any lab port to the internet (`0.0.0.0` binding is localhost only)
- Connect lab services to real production systems
- Use lab payloads against real targets
- Mount real host files into containers
- Use real credentials or personal data in the lab
- Share lab instances publicly

---

## Docker Security Limitations

Docker containers are **NOT** a security boundary. This lab implements:

```yaml
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
```

These measures **reduce** attack surface but do not guarantee isolation.
Docker escape techniques exist — see references below.

> Container escape is intentionally excluded from lab demonstrations.
> If needed for research, consult: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout

---

## Network Isolation

```yaml
networks:
  lab-network:
    internal: true
```

The `internal: true` flag prevents containers from reaching the internet.
However, host network access patterns may vary by OS and Docker version.

---

## No Real Secrets

This project contains:
- No real API keys
- No real passwords
- No real credentials
- No personal data
- Only fictional/generated test data

All credentials in `.env.example` are fictitious lab values.

---

## Responsible Use

This lab is distributed under MIT license with the explicit condition that it be used
**only for educational purposes** in **isolated environments**.

Any use of these techniques against systems without explicit written authorization
is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.).

---

## Reporting Security Issues

If you discover a security issue in the **lab infrastructure itself** (not the
intentional vulnerabilities), open an issue with tag `[INFRA-SECURITY]`.

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE: https://cwe.mitre.org/
- Docker Security: https://docs.docker.com/engine/security/
