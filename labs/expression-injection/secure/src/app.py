"""
Expression Injection Lab — Secure Version
✅ SECURE IMPLEMENTATION

Defenses applied:
- AST-based safe math parser (no eval())
- Strict allowlist of operators and literals
- Rejects any non-math constructs
"""
from __future__ import annotations

import ast
import operator
import os
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)
app.secret_key = "lab-expr-secure-key"

# Allowed AST node types — math only
_ALLOWED_NODES = (
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd,
)

_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

_MAX_EXPRESSION_LENGTH = 128
_MAX_RESULT = 1e15  # Prevent huge exponentiation


class ExpressionError(ValueError):
    """Raised when expression is invalid or unsafe."""


def _eval_node(node: ast.AST) -> float | int:
    """Recursively evaluate an AST node — only math allowed."""
    if not isinstance(node, _ALLOWED_NODES):
        raise ExpressionError(f"Unsafe node type: {type(node).__name__}")

    if isinstance(node, ast.Constant):
        if not isinstance(node.value, (int, float)):
            raise ExpressionError("Only numeric literals are allowed.")
        return node.value

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _OPERATORS:
            raise ExpressionError(f"Operator not allowed: {op_type.__name__}")
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        # Guard against division by zero and huge exponents
        if op_type == ast.Div and right == 0:
            raise ExpressionError("Division by zero.")
        if op_type == ast.Pow and abs(right) > 20:
            raise ExpressionError("Exponent too large (max 20).")
        result = _OPERATORS[op_type](left, right)
        if abs(result) > _MAX_RESULT:
            raise ExpressionError("Result out of allowed range.")
        return result

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _OPERATORS:
            raise ExpressionError(f"Unary operator not allowed: {op_type.__name__}")
        operand = _eval_node(node.operand)
        return _OPERATORS[op_type](operand)

    raise ExpressionError(f"Unexpected node: {type(node).__name__}")


def safe_eval(expression: str) -> float | int:
    """
    Safely evaluate a math expression using AST parsing.
    Only allows: numbers, +, -, *, /, %, ** and parentheses.
    Raises ExpressionError for anything else.
    """
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ExpressionError(f"Expression too long (max {_MAX_EXPRESSION_LENGTH} chars).")
    if not expression.strip():
        raise ExpressionError("Empty expression.")

    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as e:
        raise ExpressionError(f"Syntax error: {e}") from e

    return _eval_node(tree.body)


_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Expression Injection Lab — Secure</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
.lab-banner {{ background: #28a745; color: white; padding: 10px; border-radius: 4px; }}
.defense-box {{ background: #d4edda; border: 1px solid #28a745; padding: 12px; margin: 16px 0; }}
.result {{ background: #f8f9fa; border: 2px solid #28a745; padding: 16px; font-size: 1.4em; margin: 16px 0; border-radius: 4px; font-family: monospace; }}
.error {{ background: #f8d7da; border: 2px solid #dc3545; }}
form {{ margin: 20px 0; }}
input {{ padding: 8px; width: 400px; }}
button {{ background: #28a745; color: white; padding: 10px 20px; border: none; cursor: pointer; }}
</style></head>
<body>
<div class="lab-banner">✅ EXPRESSION INJECTION LAB — SECURE — AST Math Parser Applied</div>
<h1>Calculator</h1>
<div class="defense-box">
<strong>🛡 Defenses:</strong> AST-based parser | Math-only node allowlist | No eval()
<br><small>Try <code>__import__('os')</code> — rejected. Try <code>"x"*3</code> — rejected. Only math allowed.</small>
</div>
<form method="GET" action="/calculate">
  <label>Expression (math only: +, -, *, /, %, **, parentheses):</label><br>
  <input type="text" name="expression" value="{expression}" placeholder="e.g. (2+3)*4">
  <button type="submit">Calculate</button>
</form>
<div class="result {error_class}">Result: {result}</div>
</body></html>"""


@app.route("/", methods=["GET"])
@app.route("/calculate", methods=["GET"])
def calculate() -> Any:
    expression = request.args.get("expression", "")
    result_text = "Enter an expression above."
    error_class = ""

    if expression:
        try:
            value = safe_eval(expression)
            result_text = str(value)
        except ExpressionError as e:
            result_text = f"[BLOCKED] {e}"
            error_class = "error"

    from markupsafe import escape
    return _PAGE.format(
        expression=str(escape(expression)),
        result=result_text,
        error_class=error_class,
    )


@app.route("/api/calculate", methods=["GET"])
def api_calculate() -> Any:
    expression = request.args.get("expression", "")
    if not expression:
        return jsonify({"error": "expression required"}), 400
    try:
        value = safe_eval(expression)
        return jsonify({
            "expression": expression,
            "result": value,
            "blocked": False,
        })
    except ExpressionError as e:
        return jsonify({
            "expression": expression,
            "error": str(e),
            "blocked": True,
        }), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
