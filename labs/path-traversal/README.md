# Path Traversal Lab — Directory Traversal

## 01 — Introduction

Path Traversal (Directory Traversal) exploits insufficient file path validation
to read files outside the intended directory using `../` sequences.

## 02 — Objective

Demonstrate that unvalidated file paths allow reading arbitrary files on the server.

## 03 — Architecture

- Flask backend serving a document viewer with `/api/read?file=...`
- Sample documents in `/app/files/`
- Flag file at `/tmp/flag.txt` (outside the allowed directory)
- Vulnerable: `os.path.join()` without path validation
- Secure: `os.path.basename()` + `os.path.realpath()` + prefix check

## 04 — Vulnerability

**CWE-22** — Improper Limitation of a Pathname to a Restricted Directory  
**OWASP A01:2021** — Broken Access Control

Cause: The filename parameter is passed directly to `os.path.join()` without
stripping `../` sequences or validating the resolved path.

## 05 — Code Vulnerable

```python
# VULNERABLE — no path validation
path = os.path.join(_FILES_DIR, filename)  # ../../../etc/passwd works
with open(path) as fh:
    content = fh.read()
```

## 06 — Demonstration

Access `http://localhost:5027`:

**Step 1 — Normal file read:**
```
GET /api/read?file=report-q1.txt
```
Returns the Q1 report (expected).

**Step 2 — Path traversal to read the flag:**
```
GET /api/read?file=../../../../tmp/flag.txt
```
Observe: flag file content returned.

**Step 3 — Read system files:**
```
GET /api/read?file=../../../../etc/passwd
```
Observe: system user list exposed.

## 07 — Analysis

`os.path.join("/app/files", "../../../../tmp/flag.txt")` resolves to `/tmp/flag.txt`.
The application reads any file the process has permission to access.

## 08 — Code Sécurisé

```python
# SECURE — basename + realpath + prefix check
safe_name = os.path.basename(filename)        # strips ../
path = os.path.realpath(os.path.join(_FILES_DIR, safe_name))
if not path.startswith(os.path.realpath(_FILES_DIR)):
    return jsonify({"error": "Path traversal blocked"}), 403
```

## 09 — Test After Fix

`GET /api/read?file=../../../../tmp/flag.txt` strips to `flag.txt` → "File not found" (only files in `/app/files/` are accessible).

## 10 — Protection Measures

- `os.path.basename()` to strip directory components
- `os.path.realpath()` to resolve symlinks
- Verify resolved path starts with the allowed directory
- Chroot / container isolation as defense in depth

## 11 — OWASP Mapping

- OWASP Top 10: **A01:2021 — Broken Access Control**
- CWE: **CWE-22**
- OWASP Path Traversal Prevention

## 12 — Summary

| | Vulnerable | Secure |
|--|-----------|--------|
| Path validation | None | basename + realpath |
| `../` sequences | Traverses filesystem | Stripped |
| `/etc/passwd` | Readable | Blocked |

---

## Running This Lab

```bash
make lab-pathtraversal
# Vulnerable: http://localhost:5027
# Secure:     http://localhost:5028
```

## Tests

```bash
cd labs/path-traversal && python -m pytest tests/ -v
```
