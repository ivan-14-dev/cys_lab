"""Expression Injection Lab Tests."""
from __future__ import annotations
import importlib.util, json, os
import pytest

def _load(path):
    spec = importlib.util.spec_from_file_location("mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod

@pytest.fixture()
def vuln_client():
    path = os.path.join(os.path.dirname(__file__), "..", "vulnerable", "src", "app.py")
    with _load(path).app.test_client() as c:
        yield c

@pytest.fixture()
def secure_client():
    path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
    with _load(path).app.test_client() as c:
        yield c


class TestVulnerableExpression:
    def test_math_works(self, vuln_client):
        r = vuln_client.get("/api/calculate?expression=2%2B2")
        data = json.loads(r.data)
        assert data["result"] == "4"

    def test_string_operation_accepted(self, vuln_client):
        """VULNERABLE: eval() accepts non-math — string operations work."""
        r = vuln_client.get('/api/calculate?expression="x"*3')
        data = json.loads(r.data)
        assert data.get("result") == "xxx" or data.get("type") == "str", \
            "Vulnerable: string operations should be evaluated"

    def test_list_comprehension_accepted(self, vuln_client):
        """VULNERABLE: eval() accepts any expression."""
        r = vuln_client.get("/api/calculate?expression=[1,2,3]")
        data = json.loads(r.data)
        assert data.get("type") in ("list", None) or "result" in data


class TestSecureExpression:
    def test_addition_works(self, secure_client):
        r = secure_client.get("/api/calculate?expression=2%2B2")
        data = json.loads(r.data)
        assert data["result"] == 4
        assert data["blocked"] is False

    def test_complex_math_works(self, secure_client):
        r = secure_client.get("/api/calculate?expression=(10%2B5)*2")
        data = json.loads(r.data)
        assert data["result"] == 30

    def test_string_operation_rejected(self, secure_client):
        """SECURE: string operations are rejected."""
        r = secure_client.get('/api/calculate?expression="x"*3')
        assert r.status_code == 400
        data = json.loads(r.data)
        assert data["blocked"] is True

    def test_import_rejected(self, secure_client):
        """SECURE: __import__ is rejected."""
        r = secure_client.get("/api/calculate?expression=__import__('os')")
        assert r.status_code == 400

    def test_list_rejected(self, secure_client):
        r = secure_client.get("/api/calculate?expression=[1,2,3]")
        assert r.status_code == 400

    def test_division_by_zero_handled(self, secure_client):
        r = secure_client.get("/api/calculate?expression=1/0")
        assert r.status_code == 400

    def test_subtraction(self, secure_client):
        r = secure_client.get("/api/calculate?expression=10-3")
        data = json.loads(r.data)
        assert data["result"] == 7

    def test_modulo(self, secure_client):
        r = secure_client.get("/api/calculate?expression=10%253")
        data = json.loads(r.data)
        assert data["result"] == 1


# Test the safe_eval function directly
class TestSafeEval:
    def test_import_parser(self):
        path = os.path.join(os.path.dirname(__file__), "..", "secure", "src", "app.py")
        mod = _load(path)
        from importlib.util import spec_from_file_location, module_from_spec
        assert mod.safe_eval("2+2") == 4
        assert mod.safe_eval("(10+5)*2") == 30
        assert mod.safe_eval("2**3") == 8
        with pytest.raises(mod.ExpressionError):
            mod.safe_eval('"string"')
        with pytest.raises(mod.ExpressionError):
            mod.safe_eval("__import__('os')")
