#!/usr/bin/env bash
# start-lab.sh — Start the Injection Security Lab
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [[ ! -f .env ]]; then
    echo "[INFO] .env not found — copying from .env.example"
    cp .env.example .env
fi

echo "============================================"
echo "  INJECTION SECURITY LAB"
echo "  Starting containers..."
echo "============================================"

docker compose --env-file .env up -d

echo ""
echo "  Lab is running."
echo ""
echo "  Dashboard:          http://localhost:8080"
echo "  XSS Vulnerable:     http://localhost:5001"
echo "  XSS Secure:         http://localhost:5002"
echo "  Command Vuln:       http://localhost:5003"
echo "  Command Secure:     http://localhost:5004"
echo "  SSTI Vulnerable:    http://localhost:5005"
echo "  SSTI Secure:        http://localhost:5006"
echo "  NoSQL Vulnerable:   http://localhost:5007"
echo "  NoSQL Secure:       http://localhost:5008"
echo "  LDAP Vulnerable:    http://localhost:5009"
echo "  LDAP Secure:        http://localhost:5010"
echo "  XPath Vulnerable:   http://localhost:5011"
echo "  XPath Secure:       http://localhost:5012"
echo "  CSV Vulnerable:     http://localhost:5013"
echo "  CSV Secure:         http://localhost:5014"
echo "  Log Vulnerable:     http://localhost:5015"
echo "  Log Secure:         http://localhost:5016"
echo "  Header Vulnerable:  http://localhost:5017"
echo "  Header Secure:      http://localhost:5018"
echo "  Expr Vulnerable:    http://localhost:5019"
  echo "  Expr Secure:        http://localhost:5020"
  echo "  SQL Vulnerable:     http://localhost:5021"
  echo "  SQL Secure:         http://localhost:5022"
  echo "  SSRF Vulnerable:    http://localhost:5023"
  echo "  SSRF Secure:        http://localhost:5024"
  echo "  IDOR Vulnerable:    http://localhost:5025"
  echo "  IDOR Secure:        http://localhost:5026"
  echo "  PathTrav Vuln:      http://localhost:5027"
  echo "  PathTrav Secure:    http://localhost:5028"
echo ""
echo "============================================"
