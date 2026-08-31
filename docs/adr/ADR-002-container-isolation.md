# ADR-002: Container Isolation Strategy

**Date:** 2024-01-01  
**Status:** Accepted

---

## Context

The lab runs intentionally vulnerable applications. Container isolation must minimize
the risk of accidental harm while still allowing the vulnerabilities to be demonstrated.

---

## Decision

Apply the following Docker security settings to all lab containers:

```yaml
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
user: "1000:1000"
mem_limit: "256m"
cpus: "0.5"
```

Use an **internal Docker network**:
```yaml
networks:
  lab-network:
    internal: true
```

**Never** use:
- `privileged: true`
- `network_mode: host`
- `/var/run/docker.sock` mount
- Mounts of `/etc`, `/root`, `/`
- `CAP_SYS_ADMIN`

---

## Alternatives Considered

| Option | Decision |
|--------|----------|
| `privileged: true` | Rejected — full host access |
| `network_mode: host` | Rejected — breaks network isolation |
| No capability dropping | Rejected — unnecessary privileges |
| gVisor/Kata | Overkill for educational context |

---

## Consequences

- Containers cannot escalate privileges
- Containers cannot reach the internet
- Containers cannot write to host filesystem
- Some lab demonstrations require tmpfs for writable /tmp
- read_only may require explicit tmpfs mounts for writable paths

### Known Limitation

Docker is **not a security boundary**. Container escape techniques exist.
This lab must only be run on a dedicated machine or isolated VM.

> Container escape is intentionally excluded from demonstrations.
> Reference for research: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout
