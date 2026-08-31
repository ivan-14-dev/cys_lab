# LDAP Injection

## Informations

| Attribut | Valeur |
|----------|--------|
| **Difficulté** | Moyen |
| **Points** | 10 |
| **CWE** | CWE-90 |
| **OWASP** | A03:2021 |
| **Composant** | Annuaire LDAP (OpenLDAP) |
| **Port vulnérable** | 5009 |
| **Port sécurisé** | 5010 |

## Description

Les caractères spéciaux LDAP non échappés modifient la logique du filtre de recherche.

## Démarrage rapide

```bash
# Depuis la racine du projet
docker compose up -d ldap-injection-vulnerable ldap-injection-secure

# Accès
open http://localhost:5009   # Vulnérable
open http://localhost:5010  # Sécurisé
```

## Payloads de démonstration

  - `*  → tous les utilisateurs`
  - `*)(uid=*))(|(uid=*  → bypass filtre`

## Correction

Validation allowlist + échappement RFC 4515

## Structure

```
ldap-injection/
├── vulnerable/
│   ├── src/app.py      — Application vulnérable
│   ├── Dockerfile
│   └── requirements.txt
├── secure/
│   ├── src/app.py      — Application sécurisée
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── test_ldap_injection.py
└── README.md
```

## Tests

```bash
cd labs/ldap-injection
python -m pytest tests/ -v
```

## OWASP / CWE

- **A03:2021** — Injection
- **CWE-90** — Voir [CWE](https://cwe.mitre.org/data/definitions/90.html)
