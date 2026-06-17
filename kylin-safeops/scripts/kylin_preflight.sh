#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPORT_DIR="${REPORT_DIR:-data}"
REPORT_PATH="${REPORT_PATH:-$REPORT_DIR/kylin_preflight_report.md}"
mkdir -p "$REPORT_DIR"

now="$(date '+%Y-%m-%d %H:%M:%S %z')"

pass() { printf "PASS"; }
warn() { printf "WARN"; }
fail() { printf "FAIL"; }

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

cmd_path() {
  if has_cmd "$1"; then
    command -v "$1"
  else
    printf "missing"
  fi
}

os_name="unknown"
os_id="unknown"
os_version="unknown"
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_name="${NAME:-unknown}"
  os_id="${ID:-unknown}"
  os_version="${VERSION_ID:-${VERSION:-unknown}}"
fi

pid1="$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ' || true)"
is_kylin="false"
case "$(printf "%s %s" "$os_name" "$os_id" | tr '[:upper:]' '[:lower:]')" in
  *kylin*) is_kylin="true" ;;
esac

systemd_ready="false"
if [ "$pid1" = "systemd" ] || [ -d /run/systemd/system ]; then
  systemd_ready="true"
fi

required_tools=(systemctl journalctl ss ps python3 node npm)
missing_tools=()
for tool in "${required_tools[@]}"; do
  if ! has_cmd "$tool"; then
    missing_tools+=("$tool")
  fi
done

real_ready="false"
if [ "$systemd_ready" = "true" ] && has_cmd systemctl && has_cmd journalctl && has_cmd ss && has_cmd ps; then
  real_ready="true"
fi

overall="PASS"
if [ "$is_kylin" != "true" ]; then
  overall="WARN"
fi
if [ "$real_ready" != "true" ] || [ "${#missing_tools[@]}" -gt 0 ]; then
  overall="FAIL"
fi

python_version="$(python3 --version 2>/dev/null || printf 'missing')"
node_version="$(node --version 2>/dev/null || printf 'missing')"
npm_version="$(npm --version 2>/dev/null || printf 'missing')"

backend_health="not_checked"
if has_cmd curl; then
  backend_health="$(curl -fsS --max-time 2 http://127.0.0.1:8000/health 2>/dev/null || printf 'not_running')"
fi

env_probe="not_checked"
if has_cmd curl; then
  env_probe="$(curl -fsS --max-time 2 http://127.0.0.1:8000/api/environment/probe 2>/dev/null | head -c 500 || printf 'not_running')"
fi

{
  echo "# KylinSafeOps Kylin/openKylin 迁移预检报告"
  echo
  echo "- 生成时间：$now"
  echo "- 项目目录：$ROOT_DIR"
  echo "- 总体结论：$overall"
  echo
  echo "## 1. 系统识别"
  echo
  echo "| 项目 | 结果 |"
  echo "| --- | --- |"
  echo "| OS Name | $os_name |"
  echo "| OS ID | $os_id |"
  echo "| Version | $os_version |"
  echo "| Kylin/openKylin 识别 | $is_kylin |"
  echo "| PID 1 | ${pid1:-unknown} |"
  echo "| systemd 就绪 | $systemd_ready |"
  echo
  echo "## 2. 必要工具"
  echo
  echo "| 工具 | 路径 | 状态 |"
  echo "| --- | --- | --- |"
  for tool in "${required_tools[@]}"; do
    if has_cmd "$tool"; then
      echo "| $tool | $(cmd_path "$tool") | $(pass) |"
    else
      echo "| $tool | missing | $(fail) |"
    fi
  done
  echo
  echo "## 3. 运行时版本"
  echo
  echo "- Python：$python_version"
  echo "- Node：$node_version"
  echo "- npm：$npm_version"
  echo
  echo "## 4. SafeOps Real Adapter 条件"
  echo
  echo "- systemd：$systemd_ready"
  echo "- systemctl/journalctl/ss/ps：$real_ready"
  echo "- 建议 SAFEOPS_MODE：$( [ "$real_ready" = "true" ] && printf 'real 或 auto' || printf 'demo，待补齐依赖后 real' )"
  echo
  echo "## 5. 服务与端口快照"
  echo
  echo '```text'
  if has_cmd systemctl; then
    systemctl status nginx --no-pager 2>&1 | sed -n '1,18p' || true
  else
    echo "systemctl missing"
  fi
  echo
  if has_cmd ss; then
    ss -lntp 2>&1 | sed -n '1,30p' || true
  else
    echo "ss missing"
  fi
  echo '```'
  echo
  echo "## 6. 后端接口检查"
  echo
  echo "- /health：$backend_health"
  echo "- /api/environment/probe 片段："
  echo
  echo '```json'
  echo "$env_probe"
  echo '```'
  echo
  echo "## 7. 迁移建议"
  echo
  if [ "$overall" = "PASS" ]; then
    echo "- 环境满足真实工具链条件，可以运行：\`SAFEOPS_MODE=real bash scripts/start_backend_kylin.sh\`。"
    echo "- 可继续执行：\`SAFEOPS_CONFIRM_DEMO=true bash scripts/kylin_prepare_nginx_conflict.sh\` 制造 nginx 端口冲突演示场景。"
  else
    echo "- 若缺少依赖，先运行：\`bash scripts/kylin_install_runtime.sh\`。"
    echo "- 若 systemd 不就绪，请使用 Kylin/openKylin 真机或完整虚拟机，不要在普通容器内做最终验收。"
    echo "- 依赖补齐后重新运行：\`bash scripts/kylin_preflight.sh\`。"
  fi
} > "$REPORT_PATH"

cat "$REPORT_PATH"
echo
echo "Report written to: $REPORT_PATH"
