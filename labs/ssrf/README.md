# SSRF Lab — Server-Side Request Forgery

## 01 — Introduction

Server-Side Request Forgery (SSRF) tricks the server into making HTTP requests
to internal services or arbitrary URLs on behalf of the attacker.

## 02 — Objective

Demonstrate that an unrestricted URL fetcher allows access to internal-only services.

## 03 — Architecture

- Flask backend with an `/api/fetch` endpoint that fetches user-supplied URLs
- Internal endpoints (`/internal/metadata`, `/internal/flag`) not meant for external access
- Vulnerable: no URL validation — any URL is fetched
- Secure: allowlist of permitted domains + private IP blocking

## 04 — Vulnerability

**CWE-918** — Server-Side Request Forgery  
**OWASP A10:2021** — Server-Side Request Forgery

Cause: The server makes HTTP requests using URLs provided by the user without
validating the destination.

## 05 — Code Vulnerable

```python
# VULNERABLE — fetches any URL without validation
resp = http_client.get(url, timeout=5, allow_redirects=False)
```

## 06 — Demonstration

Access `http://localhost:5023` and use the URL fetcher:

**Payload 1 — Access internal metadata:**
```
http://localhost:5000/internal/metadata
```
Observe: environment variables and hostname exposed.

**Payload 2 — Steal the flag:**
```
http://localhost:5000/internal/flag
```
Observe: internal secret returned through the SSRF proxy.

## 07 — Analysis

The server acts as a proxy. Internal services that are not exposed externally
become reachable through the SSRF. In cloud environments, this can expose
instance metadata (AWS 169.254.169.254), secrets, and credentials.

## 08 — Code Sécurisé

```python
# SECURE — allowlist + private IP check
if parsed.hostname not in _ALLOWED_HOSTS:
    return jsonify({"error": "Domain not in allowlist", "blocked": True}), 403
if _is_private_ip(parsed.hostname):
    return jsonify({"error": "Private IP blocked", "blocked": True}), 403
```

## 09 — Test After Fix

Same payload `http://localhost:5000/internal/flag` is blocked with "Domain not in allowlist".

## 10 — Protection Measures

- URL allowlist (only permitted external domains)
- Block private/loopback IP ranges
- Disable HTTP redirects
- Network segmentation (internal services unreachable)

## 11 — OWASP Mapping

- OWASP Top 10: **A10:2021 — Server-Side Request Forgery**
- CWE: **CWE-918**
- OWASP SSRF Prevention Cheat Sheet

## 12 — Summary

| | Vulnerable | Secure |
|--|-----------|--------|
| URL validation | None | Allowlist |
| Internal access | Open | Blocked |
| Private IPs | Allowed | Rejected |

---

## Running This Lab

```bash
make lab-ssrf
# Vulnerable: http://localhost:5023
# Secure:     http://localhost:5024
```

## Tests

```bash
cd labs/ssrf && python -m pytest tests/ -v
```
