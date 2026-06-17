#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "== KylinSafeOps runtime install =="
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This script expects an apt-based Kylin/openKylin environment."
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  curl \
  iproute2 \
  lsof \
  procps \
  psmisc \
  python3 \
  python3-pip \
  python3-venv \
  unzip \
  nodejs \
  npm \
  nginx \
  apache2

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r backend/requirements.txt

cd frontend
npm install
cd "$ROOT_DIR"

export SAFEOPS_MODE=real
bash scripts/check_kylin_compat.sh

echo
echo "Runtime ready."
echo "Backend: SAFEOPS_MODE=real bash scripts/start_backend_kylin.sh"
echo "Frontend: bash scripts/start_frontend_kylin.sh"
