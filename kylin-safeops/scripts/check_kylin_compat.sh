#!/usr/bin/env bash
set -euo pipefail

echo "== OS =="
cat /etc/os-release || true

echo
echo "== PID 1 =="
ps -p 1 -o comm= || true

echo
echo "== Tools =="
for tool in systemctl journalctl ss ps; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool: ok ($(command -v "$tool"))"
  else
    echo "$tool: missing"
  fi
done

echo
echo "== Services =="
systemctl status nginx --no-pager || true

