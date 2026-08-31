# Injection Security Lab

Educational and isolated cybersecurity laboratory for studying injection vulnerabilities.

> ⚠️ EDUCATIONAL USE ONLY — LOCAL SANDBOX ONLY — DO NOT EXPOSE TO THE INTERNET

## Purpose

Controlled, isolated environment for learning injection vulnerabilities.  
Every vulnerability is **intentionally created** for educational purposes.

## Covered Vulnerabilities

| Lab                | Points | Difficulty | OWASP    |
|--------------------|--------|------------|----------|
| XSS                | 10     | Easy       | A03:2021 |
| Command Injection  | 15     | Medium     | A03:2021 |
| SSTI               | 15     | Medium     | A03:2021 |
| NoSQL Injection    | 10     | Medium     | A03:2021 |
| LDAP Injection     | 10     | Medium     | A03:2021 |
| XPath Injection    | 10     | Medium     | A03:2021 |
| CSV Injection      | 5      | Easy       | A03:2021 |
| Log Injection      | 5      | Easy       | A09:2021 |
| Header Injection   | 5      | Easy       | A03:2021 |
| Expression Inject. | 10     | Medium     | A03:2021 |

**Total: 95 points** — SQL Injection: theory only → [`docs/sql-injection-theory.md`](docs/sql-injection-theory.md)

## Quick Start

```bash
cp .env.example .env
make build
make up
# Open http://localhost:8080
```

## Port Map

```
localhost:8080  →  Dashboard
localhost:5001/5002  →  XSS (vuln/secure)
localhost:5003/5004  →  Command Injection
localhost:5005/5006  →  SSTI
localhost:5007/5008  →  NoSQL Injection
localhost:5009/5010  →  LDAP Injection
localhost:5011/5012  →  XPath Injection
localhost:5013/5014  →  CSV Injection
localhost:5015/5016  →  Log Injection
localhost:5017/5018  →  Header Injection
localhost:5019/5020  →  Expression Injection
[ lab-network: internal only, no external internet access ]
```

## Security Warning

Run only on a **dedicated lab machine** or **isolated VM**.
Never expose lab ports to the internet. See [SECURITY.md](SECURITY.md).

## Commands

```bash
make build    # Build all containers
make up       # Start the lab
make down     # Stop the lab
make test     # Run all tests
make clean    # Remove containers and volumes
```

## License

MIT — Educational use only. See [LICENSE](LICENSE).
