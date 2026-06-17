#!/usr/bin/env bash
set -euo pipefail

if [ "${SAFEOPS_CONFIRM_DEMO:-false}" != "true" ]; then
  echo "This script creates a demo incident by letting apache2 occupy port 80, then starting nginx so nginx fails."
  echo "Run it only inside the openKylin/KylinOS VM used for the competition demo."
  echo
  echo "Confirm with:"
  echo "  SAFEOPS_CONFIRM_DEMO=true bash scripts/kylin_prepare_nginx_conflict.sh"
  exit 2
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This script expects an apt-based Kylin/openKylin environment."
  exit 1
fi

sudo apt-get update
sudo apt-get install -y nginx apache2 iproute2 procps

sudo systemctl stop nginx || true
sudo systemctl stop apache2 || true

sudo systemctl start apache2
sudo systemctl start nginx || true

echo
echo "== nginx status =="
systemctl status nginx --no-pager || true

echo
echo "== nginx logs =="
journalctl -u nginx.service -n 80 --no-pager || true

echo
echo "== port 80 owner =="
sudo ss -lntp | grep ':80' || true

echo
echo "Demo incident is ready. Ask KylinSafeOps: 帮我看看 nginx 为什么启动失败"
