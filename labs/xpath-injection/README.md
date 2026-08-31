# XPath Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 10 |
| **CWE** | CWE-643 |
| **OWASP** | A03:2021 |
| **Composant** | Moteur XPath (lxml) |
| **Port vulnérable** | 5011 |
| **Port sécurisé** | 5012 |

## Description

La concaténation dans les expressions XPath permet de modifier la logique de requête XML.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d xpath-injection-vulnerable xpath-injection-secure

# Accès
open http://localhost:5011   # Vulnérable
open http://localhost:5012  # Sécurisé
```

## Payloads de démonstration

  - `' or '1'='1  → tous les users`
  - `alice' or '1'='1`

## Correction

Validation allowlist (a-z 0-9 _-) + échappement des apostrophes

## Structure

```
xpath-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_xpath_injection.py
└── README.md
```

## Tests

```bash
cd labs/xpath-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-643** — Voir [CWE](https://cwe.mitre.org/data/definitions/643.html)
