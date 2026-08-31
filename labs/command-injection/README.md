# Command Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 15 |
| **CWE** | CWE-78 |
| **OWASP** | A03:2021 |
| **Composant** | OS Shell (subprocess) |
| **Port vulnérable** | 5003 |
| **Port sécurisé** | 5004 |

## Description

L'utilisation de shell=True avec concaténation de chaînes permet l'exécution de commandes OS arbitraires.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d command-injection-vulnerable command-injection-secure

# Accès
open http://localhost:5003   # Vulnérable
open http://localhost:5004  # Sécurisé
```

## Payloads de démonstration

  - `127.0.0.1; echo INJECTION_DETECTED`
  - `127.0.0.1; cat /app/data/lab-secret.txt`

## Correction

subprocess avec liste d'arguments + shell=False + allowlist des cibles

## Structure

```
command-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_command_injection.py
└── README.md
```

## Tests

```bash
cd labs/command-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-78** — Voir [CWE](https://cwe.mitre.org/data/definitions/78.html)
