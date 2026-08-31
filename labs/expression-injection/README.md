# Expression / Code Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 10 |
| **CWE** | CWE-94 |
| **OWASP** | A03:2021 |
| **Composant** | Évaluateur d'expressions Python |
| **Port vulnérable** | 5019 |
| **Port sécurisé** | 5020 |

## Description

eval() sur l'entrée utilisateur permet l'exécution d'expressions Python arbitraires.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d expression-injection-vulnerable expression-injection-secure

# Accès
open http://localhost:5019   # Vulnérable
open http://localhost:5020  # Sécurisé
```

## Payloads de démonstration

  - `"injection"*3`
  - `__import__('os').environ.get('FLASK_ENV')`

## Correction

Parser AST avec allowlist de nœuds math uniquement

## Structure

```
expression-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_expression_injection.py
└── README.md
```

## Tests

```bash
cd labs/expression-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-94** — Voir [CWE](https://cwe.mitre.org/data/definitions/94.html)
