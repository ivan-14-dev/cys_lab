# Threat Model — Injection Security Lab

## Portée

Ce document modélise les menaces **dans le contexte du laboratoire éducatif**, pas dans un contexte de production.

---

## Acteurs

| Acteur | Rôle | Niveau de confiance |
|--------|------|---------------------|
| Étudiant | Utilisateur du lab, apprend les attaques | Zéro confiance sur les inputs |
| Dashboard | Portail central | Interne, fiable |
| Labs vulnérables | Applications intentionnellement cassées | Untrusted inputs attendus |
| Labs sécurisés | Applications corrigées | Idem, inputs untrusted |
| SQLite / MongoDB / LDAP | Stores de données de lab | Internes, données fictives |

---

## Flux de données

```
[Browser Étudiant]
        │
        ▼ HTTP (localhost seulement)
[Lab Vulnérable :500X]  ←→  [Store de données (SQLite/MongoDB/LDAP)]
        │
        ▼ (même réseau lab-network)
[Lab Sécurisé :500Y]
```

---

## Frontières de confiance

```
HÔTE (machine physique)
  └─ Docker lab-network (interne)
       ├─ Containers vulnérables  ← payloads attendus ici
       ├─ Containers sécurisés
       └─ Stores de données
```

**Règle :** aucun trafic ne sort de `lab-network` vers Internet.

---

## Menaces identifiées

### Dans le lab (intentionnelles)

| ID | Menace | Lab | Impact lab | Mitigation démontrée |
|----|--------|-----|-----------|---------------------|
| T-01 | XSS stocké | XSS | Script exécuté dans browser | Output encoding, CSP |
| T-02 | Command Injection | CMD | Commandes OS | shell=False, allowlist |
| T-03 | SSTI | SSTI | Évaluation expression | Template fixe |
| T-04 | NoSQL Operator Injection | NoSQL | Bypass auth | Pydantic schema |
| T-05 | LDAP Filter Injection | LDAP | Enum annuaire | Escaping RFC 4515 |
| T-06 | XPath Injection | XPath | Extraction XML | Allowlist |
| T-07 | CSV Formula Injection | CSV | Formule tableur | Prefix tab |
| T-08 | Log Injection | Log | Forge d'audit | Structured logging |
| T-09 | CRLF Header Injection | Header | Headers injectés | Strip CRLF |
| T-10 | Expression Injection | Expr | eval() arbitrary | AST parser |
| T-11 | SQL Injection | SQL | Bypass + extraction | Requêtes paramétrées |

### Hors portée (non démontrées)

| Menace | Raison d'exclusion |
|--------|--------------------|
| Container escape | Docker n'est pas une frontière de sécurité parfaite — à étudier séparément |
| Réseau réel | `internal: true` + pas d'exposition externe |
| Secrets réels | Aucun secret réel dans le projet |
| DoS / déni de service | Hors périmètre éducatif |

---

## Mesures de protection infrastructure

| Contrôle | Statut | Notes |
|---------|--------|-------|
| Réseau interne | ✅ | `internal: true` sur lab-network |
| Ports localhost seulement | ✅ | `127.0.0.1:XXXX:5000` |
| cap_drop: ALL | ✅ | Appliqué à tous les containers |
| no-new-privileges | ✅ | security_opt sur tous |
| read_only filesystem | ✅ | Containers en lecture seule |
| Non-root user | ✅ | labuser uid=1000 |
| Limites ressources | ✅ | 256m RAM, 0.5 CPU |
| Données fictives | ✅ | Aucune donnée réelle |
| Pas de secrets réels | ✅ | Credentials de lab uniquement |

---

## Risque résiduel

Docker n'est **pas** une frontière de sécurité parfaite.
Des techniques d'évasion de conteneur existent.

**Ce lab doit être exécuté uniquement sur :**
- Une machine dédiée au lab
- Une VM isolée
- Un réseau sans accès à des systèmes sensibles

Voir [SECURITY.md](../SECURITY.md) pour les règles complètes.
