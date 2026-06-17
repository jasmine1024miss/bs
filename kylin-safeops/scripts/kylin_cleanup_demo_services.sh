#!/usr/bin/env bash
set -euo pipefail

echo "Stopping apache2 and restarting nginx..."
sudo systemctl stop apache2 || true
sudo systemctl restart nginx || true

echo
echo "== nginx status =="
systemctl status nginx --no-pager || true

echo
echo "== port 80 owner =="
sudo ss -lntp | grep ':80' || true
