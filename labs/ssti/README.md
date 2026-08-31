# SSTI (Server-Side Template Injection)

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 15 |
| **CWE** | CWE-94 |
| **OWASP** | A03:2021 |
| **Composant** | Moteur de template Jinja2 |
| **Port vulnérable** | 5005 |
| **Port sécurisé** | 5006 |

## Description

L'entrée utilisateur utilisée comme source de template Jinja2 permet l'évaluation d'expressions côté serveur.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d ssti-vulnerable ssti-secure

# Accès
open http://localhost:5005   # Vulnérable
open http://localhost:5006  # Sécurisé
```

## Payloads de démonstration

  - `{{7*7}} → 49`
  - `{{'injection'*3}}`

## Correction

Template fixe défini par le développeur, entrée passée comme variable

## Structure

```
ssti/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_ssti.py
└── README.md
```

## Tests

```bash
cd labs/ssti
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-94** — Voir [CWE](https://cwe.mitre.org/data/definitions/94.html)
