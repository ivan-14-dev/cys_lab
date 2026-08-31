# NoSQL Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 10 |
| **CWE** | CWE-943 |
| **OWASP** | A03:2021 |
| **Composant** | MongoDB / Requêtes JSON |
| **Port vulnérable** | 5007 |
| **Port sécurisé** | 5008 |

## Description

Les objets opérateurs MongoDB ($ne, $gt) acceptés comme valeurs de filtre bypassent l'authentification.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d nosql-injection-vulnerable nosql-injection-secure

# Accès
open http://localhost:5007   # Vulnérable
open http://localhost:5008  # Sécurisé
```

## Payloads de démonstration

  - `{"password": {"$ne": null}}`
  - `{"password": {"$gt": ""}}`

## Correction

Validation Pydantic enforce le type string pour tous les champs

## Structure

```
nosql-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_nosql_injection.py
└── README.md
```

## Tests

```bash
cd labs/nosql-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-943** — Voir [CWE](https://cwe.mitre.org/data/definitions/943.html)
