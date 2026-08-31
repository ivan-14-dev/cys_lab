#!/usr/bin/env bash
# stop-lab.sh — Stop the Injection Security Lab
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "============================================"
echo "  INJECTION SECURITY LAB"
echo "  Stopping containers..."
echo "============================================"

docker compose --env-file .env down

echo ""
echo "  Lab stopped."
echo "============================================"
