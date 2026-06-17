#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install -r backend/requirements.txt

export SAFEOPS_MODE="${SAFEOPS_MODE:-real}"
export BACKEND_HOST="${BACKEND_HOST:-0.0.0.0}"
export BACKEND_PORT="${BACKEND_PORT:-8000}"

python -m uvicorn backend.app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT"

