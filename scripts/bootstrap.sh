#!/usr/bin/env bash
# One-time local setup: virtualenv, pinned dependencies, .env template. Sends nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements-dev.txt
[ -f .env ] || cp .env.example .env
echo
echo "Done. Next: edit .env, then run:"
echo "  . .venv/bin/activate && python -m arkham check-config"
echo "  python -m arkham run --dry-run"
