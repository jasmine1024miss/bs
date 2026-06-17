#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/frontend"

if [ ! -d "node_modules" ]; then
  npm install
fi

export VITE_API_BASE_URL="${VITE_API_BASE_URL:-http://localhost:8000}"
npm run dev -- --host 0.0.0.0

