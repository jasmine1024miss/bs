import re

from backend.app.execution.environment import probe_environment
from backend.app.tools.base import run_command


def get_attack_surface() -> dict:
    env = probe_environment()
    if env["effective_mode"] == "real" and env["real_mode_ready"]:
        return _real_surface()
    return _demo_surface(env["effective_mode"])


def _demo_surface(mode: str) -> dict:
    items = [
        {"port": 22, "service": "sshd", "process": "sshd", "bind": "0.0.0.0", "risk": "medium", "reason": "SSH 对外监听"},
        {"port": 80, "service": "httpd", "process": "httpd", "bind": "0.0.0.0", "risk": "high", "reason": "与 nginx 目标端口冲突"},
        {"port": 3306, "service": "mysqld", "process": "mysqld", "bind": "127.0.0.1", "risk": "low", "reason": "仅本地监听"},
    ]
    return {
        "mode": mode,
        "items": items,
        "summary": "demo 攻击面快照：发现 3 个监听端口，其中 80 端口为高风险。",
        "evolution": {
            "previous_ports": [22, 80],
            "current_ports": [22, 80, 3306],
            "new_ports": [3306],
            "risk_change": "新增 MySQL 本地监听，风险轻微上升。",
        },
    }


def _real_surface() -> dict:
    result = run_command(["ss", "-lntp"])
    items = []
    for line in result["stdout"].splitlines():
        parsed = _parse_ss_line(line)
        if parsed:
            items.append(parsed)

    return {
        "mode": "real",
        "items": items,
        "summary": f"真实攻击面快照：发现 {len(items)} 个监听端口。",
        "evolution": {
            "previous_ports": [],
            "current_ports": [item["port"] for item in items],
            "new_ports": [],
            "risk_change": "首次真实扫描，暂无历史对比。",
        },
    }


def _parse_ss_line(line: str) -> dict | None:
    if "LISTEN" not in line:
        return None
    address_match = re.search(r"(\d+\.\d+\.\d+\.\d+|\*|0\.0\.0\.0|\[::\]|::):(\d+)", line)
    if not address_match:
        return None
    bind = address_match.group(1)
    port = int(address_match.group(2))
    process_match = re.search(r'"([^"]+)"', line)
    process = process_match.group(1) if process_match else "unknown"
    risk = "high" if bind in {"0.0.0.0", "*", "::", "[::]"} and port not in {80, 443} else "medium"
    if bind in {"127.0.0.1", "::1"}:
        risk = "low"
    return {"port": port, "service": process, "process": process, "bind": bind, "risk": risk, "reason": "真实 ss 扫描"}

