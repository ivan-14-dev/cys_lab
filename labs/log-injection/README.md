# Log Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Facile |
| **Points** | 5 |
| **CWE** | CWE-117 |
| **OWASP** | A09:2021 |
| **Composant** | Système de logging Python |
| **Port vulnérable** | 5015 |
| **Port sécurisé** | 5016 |

## Description

Les caractères de contrôle (\n, \r) dans les messages de log créent de fausses entrées.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d log-injection-vulnerable log-injection-secure

# Accès
open http://localhost:5015   # Vulnérable
open http://localhost:5016  # Sécurisé
```

## Payloads de démonstration

  - `alice\nFAKE SUCCESS for root`
  - `bob\r\n[SECURITY] Bypass`

## Correction

Logging structuré (extra dict) + validation allowlist

## Structure

```
log-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_log_injection.py
└── README.md
```

## Tests

```bash
cd labs/log-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A09:2021** — Injection
- **CWE-117** — Voir [CWE](https://cwe.mitre.org/data/definitions/117.html)
