# SQL Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 15 |
| **CWE** | CWE-89 |
| **OWASP** | A03:2021 |
| **Composant** | SQLite (base de données relationnelle) |
| **Port vulnérable** | 5021 |
| **Port sécurisé** | 5022 |

## Description

La concaténation de chaînes dans les requêtes SQL permet le bypass d'authentification et l'extraction de données.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d sql-injection-vulnerable sql-injection-secure

# Accès
open http://localhost:5021   # Vulnérable
open http://localhost:5022  # Sécurisé
```

## Payloads de démonstration

  - `' OR '1'='1  → bypass (retourne 1er user)`
  - `admin'-- → bypass admin (MDP ignoré)`
  - `' UNION SELECT 1,'vol','data','admin'-- → injection UNION`

## Correction

Requêtes paramétrées SQLite (?) + séparation code/données

## Structure

```
sql-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_sql_injection.py
└── README.md
```

## Tests

```bash
cd labs/sql-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-89** — Voir [CWE](https://cwe.mitre.org/data/definitions/89.html)
