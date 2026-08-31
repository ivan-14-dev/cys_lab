# XSS Lab — Cross-Site Scripting

## 01 — Introduction

Cross-Site Scripting (XSS) is an injection attack where malicious scripts are
injected into web pages viewed by other users. The browser interprets the injected
content as code rather than data.

## 02 — Objective

Demonstrate that unsanitized HTML output allows browser code execution.

## 03 — Architecture

- Flask backend serving HTML templates
- Comment board storing user-submitted messages
- Vulnerable: raw HTML output
- Secure: Jinja2 auto-escaping + Content-Security-Policy

## 04 — Vulnerability

**CWE-79** — Improper Neutralization of Input During Web Page Generation  
**OWASP A03:2021** — Injection

Cause: User input is rendered directly into HTML without encoding.

## 05 — Code Vulnerable

```python
# VULNERABLE — renders comment without escaping
return f"<p>{comment}</p>"  # browser may execute this as code
```

## 06 — Demonstration

Access `http://localhost:5001` and submit:

**Payload 1 — Alert:**
```
<img src=x onerror="document.title='XSS_PROOF'">
```
Observe: page title changes → script was executed.

**Payload 2 — DOM manipulation:**
```
<b style="color:red">INJECTION DETECTED</b>
```
Observe: styled text rendered as HTML.

## 07 — Analysis

The browser receives raw HTML and executes embedded scripts.
An attacker could steal session cookies, redirect users, or load external scripts.

## 08 — Code Sécurisé

```python
# SECURE — Jinja2 auto-escaping encodes special characters
return render_template("comments.html", comment=comment)
# <script> becomes &lt;script&gt; — displayed as text, not executed
```

## 09 — Test After Fix

Same payload `<img src=x onerror="...">` is now displayed as literal text.

## 10 — Protection Measures

- Jinja2 auto-escaping (enabled by default)
- Content-Security-Policy header
- HttpOnly cookies
- Input validation (allowlist)

## 11 — OWASP Mapping

- OWASP Top 10: **A03:2021 — Injection**
- CWE: **CWE-79**
- OWASP XSS Prevention Cheat Sheet

## 12 — Summary

| | Vulnerable | Secure |
|--|-----------|--------|
| Rendering | Raw HTML | HTML-encoded |
| `<script>` | Executes | Displayed as text |
| CSP | None | Restrictive |

---

## Running This Lab

```bash
make lab-xss
# Vulnerable: http://localhost:5001
# Secure:     http://localhost:5002
```

## Tests

```bash
cd labs/xss && python -m pytest tests/ -v
```
