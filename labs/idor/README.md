# IDOR Lab — Insecure Direct Object Reference

## 01 — Introduction

Insecure Direct Object Reference (IDOR) occurs when an application exposes
internal object identifiers (user IDs, file names) without verifying that
the requesting user is authorized to access them.

## 02 — Objective

Demonstrate that sequential user IDs without authorization checks allow
accessing other users' private data.

## 03 — Architecture

- Flask backend serving user profiles by numeric ID
- Vulnerable: `/api/user/<id>` returns any user's data without auth check
- Secure: compares requested ID against the authenticated user's ID

## 04 — Vulnerability

**CWE-639** — Authorization Bypass Through User-Controlled Key  
**OWASP A01:2021** — Broken Access Control

Cause: The API returns user data based solely on the ID parameter without
verifying that the requester owns that resource.

## 05 — Code Vulnerable

```python
# VULNERABLE — no authorization check
@app.route("/api/user/<int:uid>")
def get_user(uid):
    user = _USERS.get(uid)
    return jsonify(user)  # anyone can access any user
```

## 06 — Demonstration

Access `http://localhost:5025`:

**Step 1 — View your own profile:**
```
GET /api/user/1
```
Returns alice's profile (expected).

**Step 2 — Access admin's profile:**
```
GET /api/user/3
```
Observe: admin's private notes (including the flag) are returned.

**Step 3 — Enumerate users:**
```
GET /api/users
```
Returns a list of all user IDs, enabling targeted IDOR.

## 07 — Analysis

The application trusts the user-supplied ID without verifying ownership.
An attacker can enumerate all IDs (1, 2, 3...) and access every user's
private data including admin secrets.

## 08 — Code Sécurisé

```python
# SECURE — authorization check
@app.route("/api/user/<int:uid>")
def get_user(uid):
    if uid != _CURRENT_USER_ID:
        return jsonify({"error": "Access denied", "blocked": True}), 403
    return jsonify(_USERS.get(uid))
```

## 09 — Test After Fix

`GET /api/user/3` returns 403 "Access denied — you can only view your own profile".

## 10 — Protection Measures

- Authorization checks on every resource access
- Use indirect references (UUIDs instead of sequential IDs)
- Row-level security in the database
- Automated access control testing

## 11 — OWASP Mapping

- OWASP Top 10: **A01:2021 — Broken Access Control**
- CWE: **CWE-639**
- OWASP Access Control Cheat Sheet

## 12 — Summary

| | Vulnerable | Secure |
|--|-----------|--------|
| Auth check | None | Per-request |
| `/api/user/3` | Returns admin data | 403 Forbidden |
| Enumeration | Possible | Blocked |

---

## Running This Lab

```bash
make lab-idor
# Vulnerable: http://localhost:5025
# Secure:     http://localhost:5026
```

## Tests

```bash
cd labs/idor && python -m pytest tests/ -v
```
