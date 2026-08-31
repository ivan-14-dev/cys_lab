# CSV Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Facile |
| **Points** | 5 |
| **CWE** | CWE-1236 |
| **OWASP** | A03:2021 |
| **Composant** | Export CSV / Tableurs |
| **Port vulnérable** | 5013 |
| **Port sécurisé** | 5014 |

## Description

Les formules non sanitisées dans les cellules CSV s'exécutent dans les tableurs.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d csv-injection-vulnerable csv-injection-secure

# Accès
open http://localhost:5013   # Vulnérable
open http://localhost:5014  # Sécurisé
```

## Payloads de démonstration

  - `=SUM(1+1)*10`
  - `+INJECTION_CSV`
  - `@SUM(A1:A10)`

## Correction

Préfixer les valeurs commençant par = + - @ avec un tab

## Structure

```
csv-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_csv_injection.py
└── README.md
```

## Tests

```bash
cd labs/csv-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-1236** — Voir [CWE](https://cwe.mitre.org/data/definitions/1236.html)
