# HTTP Header / CRLF Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Facile |
| **Points** | 5 |
| **CWE** | CWE-113 |
| **OWASP** | A03:2021 |
| **Composant** | Headers HTTP Flask |
| **Port vulnérable** | 5017 |
| **Port sécurisé** | 5018 |

## Description

Les séquences CRLF dans les valeurs de headers HTTP injectent de nouveaux headers.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d header-injection-vulnerable header-injection-secure

# Accès
open http://localhost:5017   # Vulnérable
open http://localhost:5018  # Sécurisé
```

## Payloads de démonstration

  - `en%0d%0aX-Injected: CRLF`
  - `en%0d%0aSet-Cookie: session=hijacked`

## Correction

Rejet des \r \n + allowlist des valeurs autorisées

## Structure

```
header-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_header_injection.py
└── README.md
```

## Tests

```bash
cd labs/header-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-113** — Voir [CWE](https://cwe.mitre.org/data/definitions/113.html)
