import os
import platform
import shutil
import subprocess
from pathlib import Path

from backend.app.config import get_settings


SYSTEM_TOOLS = ["systemctl", "journalctl", "ss", "netstat", "lsof", "ps"]
CORE_REAL_TOOLS = ["systemctl", "journalctl", "ps"]
NETWORK_CONTEXT_TOOLS = ["ss", "netstat", "lsof"]


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}

    data: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def _pid1_name() -> str:
    if platform.system().lower() != "linux":
        return ""
    try:
        result = subprocess.run(
            ["ps", "-p", "1", "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def probe_environment() -> dict:
    settings = get_settings()
    os_release = _read_os_release()
    system_name = platform.system()
    system_lower = system_name.lower()
    os_text = " ".join(os_release.values()).lower()
    is_linux = system_lower == "linux"
    is_kylin_like = "kylin" in os_text
    tool_status = {tool: shutil.which(tool) is not None for tool in SYSTEM_TOOLS}
    pid1 = _pid1_name()
    has_systemd = is_linux and (pid1 == "systemd" or Path("/run/systemd/system").exists())

    real_mode_ready = (
        is_linux
        and has_systemd
        and all(tool_status[tool] for tool in CORE_REAL_TOOLS)
        and any(tool_status[tool] for tool in NETWORK_CONTEXT_TOOLS)
    )

    readiness = _real_readiness(is_linux, has_systemd, tool_status)

    if settings.safeops_mode == "auto":
        effective_mode = "real" if real_mode_ready else "demo"
    else:
        effective_mode = settings.safeops_mode

    adapter = _adapter_name(settings.safeops_mode, effective_mode, real_mode_ready, is_kylin_like)

    return {
        "configured_mode": settings.safeops_mode,
        "configured_mode_raw": settings.safeops_mode_raw,
        "configured_mode_valid": settings.safeops_mode_valid,
        "effective_mode": effective_mode,
        "mode_resolution": _mode_resolution(settings.safeops_mode, effective_mode, readiness),
        "system": system_name,
        "machine": platform.machine(),
        "os_release": {
            "id": os_release.get("ID", ""),
            "name": os_release.get("NAME", ""),
            "version": os_release.get("VERSION", ""),
            "version_id": os_release.get("VERSION_ID", ""),
        },
        "is_linux": is_linux,
        "is_kylin_like": is_kylin_like,
        "pid1": pid1,
        "has_systemd": has_systemd,
        "tools": tool_status,
        "real_mode_ready": real_mode_ready,
        "real_mode_blockers": readiness["blockers"],
        "adapter": adapter,
        "adapter_contract": {
            "demo": "使用可控样例数据，不读取本机 systemd 状态",
            "real": "调用受控白名单工具：systemctl/journalctl/ss/netstat/lsof/ps",
            "auto": "环境满足真实工具条件时走 real，否则走 demo",
            "selected": adapter,
        },
        "capabilities": _capabilities(tool_status, real_mode_ready),
        "deepseek": {
            "configured": bool(settings.deepseek_api_key),
            "enabled": settings.deepseek_enabled and bool(settings.deepseek_api_key),
            "base_url": settings.deepseek_base_url,
            "model": settings.deepseek_model,
        },
        "notes": _compat_notes(effective_mode, is_linux, is_kylin_like, has_systemd, tool_status, settings.safeops_mode_valid),
    }


def _adapter_name(configured_mode: str, effective_mode: str, real_mode_ready: bool, is_kylin_like: bool) -> str:
    if effective_mode == "real" and real_mode_ready:
        return "kylin-real-adapter" if is_kylin_like else "linux-real-adapter"
    if configured_mode == "real" and not real_mode_ready:
        return "real-adapter-not-ready"
    return "demo-adapter"


def _capabilities(tool_status: dict[str, bool], real_mode_ready: bool) -> list[dict]:
    return [
        {"name": "systemctl_status", "risk": "readonly", "ready": real_mode_ready and tool_status["systemctl"]},
        {"name": "journalctl_unit", "risk": "readonly", "ready": real_mode_ready and tool_status["journalctl"]},
        {"name": "ss_listen", "risk": "readonly", "ready": tool_status["ss"]},
        {"name": "netstat_listen", "risk": "readonly", "ready": tool_status["netstat"]},
        {"name": "lsof_port", "risk": "readonly", "ready": tool_status["lsof"]},
        {"name": "ps_process", "risk": "readonly", "ready": tool_status["ps"]},
        {"name": "restart_service", "risk": "medium", "ready": real_mode_ready, "requires_confirm": True},
    ]


def _real_readiness(is_linux: bool, has_systemd: bool, tool_status: dict[str, bool]) -> dict:
    blockers: list[str] = []
    if not is_linux:
        blockers.append("not_linux")
    if is_linux and not has_systemd:
        blockers.append("systemd_not_ready")
    missing = [tool for tool, ok in tool_status.items() if not ok]
    missing_core = [tool for tool in CORE_REAL_TOOLS if not tool_status.get(tool)]
    blockers.extend([f"missing_{tool}" for tool in missing_core])
    if not any(tool_status.get(tool) for tool in NETWORK_CONTEXT_TOOLS):
        blockers.append("missing_network_context_tool")
    return {"ready": not blockers, "blockers": blockers, "missing_tools": missing}


def _mode_resolution(configured_mode: str, effective_mode: str, readiness: dict) -> dict:
    if configured_mode == "auto":
        reason = "real_ready" if effective_mode == "real" else "auto_fallback_to_demo"
    elif configured_mode == "real" and not readiness["ready"]:
        reason = "real_requested_but_not_ready"
    else:
        reason = "configured_mode_selected"
    return {
        "requested": configured_mode,
        "selected": effective_mode,
        "reason": reason,
        "real_ready": readiness["ready"],
        "blockers": readiness["blockers"],
    }


def _compat_notes(effective_mode: str, is_linux: bool, is_kylin_like: bool, has_systemd: bool, tool_status: dict[str, bool], mode_valid: bool) -> list[str]:
    notes: list[str] = []
    if not mode_valid:
        notes.append("SAFEOPS_MODE 配置无效，已回退到 demo。")
    if effective_mode == "demo":
        notes.append("当前为 demo 模式，系统工具使用可控样例数据。")
    if not is_linux:
        notes.append("当前不是 Linux，真实 systemctl/journalctl 诊断不可用。")
    if is_linux and not is_kylin_like:
        notes.append("当前是 Linux 但未识别为 Kylin/openKylin，最终提交仍需麒麟环境截图或录屏。")
    if is_linux and not has_systemd:
        notes.append("未检测到完整 systemd 环境，systemctl/journalctl 行为可能受限。")

    missing = [tool for tool, ok in tool_status.items() if not ok]
    if missing:
        notes.append(f"缺少系统工具：{', '.join(missing)}。")
    return notes
