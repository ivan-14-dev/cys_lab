# Introduction — Injection Security Lab

## What is an Injection?

An **injection vulnerability** occurs when untrusted data is sent to an interpreter as part
of a command or query. The attacker's hostile data tricks the interpreter into executing
unintended commands or accessing unauthorized data.

```
[User Input] ──► [Application] ──► [Interpreter]
                                        │
                   Untrusted data ──────┘
                   interpreted as code = INJECTION
```

## Why Do Injections Exist?

Injections exist because of a fundamental confusion between **data** and **code**.

When an application:
- Concatenates user input directly into a query → SQL/NoSQL/LDAP/XPath Injection
- Passes user input to a shell command → Command Injection
- Renders user input as HTML → XSS
- Uses user input as a template → SSTI
- Evaluates user input as an expression → Expression Injection
- Places user input in log entries → Log Injection
- Uses user input in HTTP headers → Header/CRLF Injection
- Writes user input to CSV without sanitization → CSV Injection

## The Core Principle

> **Never trust user input. Always treat it as data, never as code.**

The fix is always the same conceptually:
1. Separate code from data
2. Validate, sanitize, or encode the boundary between them

## Lab Structure

Each lab demonstrates:

```
VULNERABLE VERSION          SECURE VERSION
─────────────────           ──────────────
User input → code      vs   User input → data
Unexpected behavior    vs   Expected behavior
Attack demonstrated    vs   Attack blocked
```

## OWASP Context

Injection vulnerabilities map to:
- **OWASP Top 10 A03:2021** — Injection
- **OWASP Top 10 A09:2021** — Security Logging Failures (Log Injection)
- Multiple **CWE** entries (see individual lab documentation)
