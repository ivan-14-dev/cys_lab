# ADR-005: Testing Strategy

**Date:** 2024-01-01  
**Status:** Accepted

---

## Context

Each lab needs automated tests that:
1. Confirm the vulnerable version IS vulnerable (demonstrates the problem)
2. Confirm the secure version is NOT vulnerable (demonstrates the fix)
3. Run quickly in CI/CD without external dependencies

---

## Decision

Use **pytest** for all automated tests.

### Test Structure per Lab

```
tests/
  test_vulnerable.py    — confirms vulnerable behavior exists
  test_secure.py        — confirms secure behavior blocks it
  test_validation.py    — input validation edge cases
  conftest.py           — shared fixtures
```

### Test Categories

```python
def test_vulnerable_behavior():
    """Confirms the vulnerability is reproducible."""

def test_secure_behavior():
    """Confirms the fix blocks the vulnerability."""

def test_input_validation():
    """Edge cases for input handling."""

def test_encoding():
    """For XSS: output encoding verification."""

def test_no_shell():
    """For Command Injection: shell=False enforcement."""

def test_expected_response():
    """Normal inputs return expected results."""
```

### Test Execution

Tests run against the **Flask test client** (no running container required).
This makes them fast and container-independent.

For container-level integration tests, use `pytest` with `requests` against
the running containers.

---

## Consequences

- Tests are fast (no Docker required for unit tests)
- Each lab's tests are self-contained
- `make test` runs all labs' tests sequentially
- Tests serve as documentation of expected behavior
- Failing tests indicate a lab is broken or security was accidentally removed
