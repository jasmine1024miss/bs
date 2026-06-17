TOOL_CONTRACTS = {
    "systemctl_status": {
        "risk": "readonly",
        "allowed_args": {"service": ["nginx", "redis", "mysql", "sshd"]},
        "side_effect": False,
    },
    "journalctl_unit": {
        "risk": "readonly",
        "allowed_args": {"unit": ["nginx", "redis", "mysql", "sshd"], "max_lines": 200},
        "side_effect": False,
    },
    "ss_listen": {
        "risk": "readonly",
        "allowed_args": {"port_min": 1, "port_max": 65535},
        "side_effect": False,
    },
    "netstat_listen": {
        "risk": "readonly",
        "allowed_args": {"port_min": 1, "port_max": 65535},
        "side_effect": False,
    },
    "lsof_port": {
        "risk": "readonly",
        "allowed_args": {"port_min": 1, "port_max": 65535},
        "side_effect": False,
    },
    "ps_process": {
        "risk": "readonly",
        "allowed_args": {"pid_min": 1},
        "side_effect": False,
    },
    "restart_service": {
        "risk": "medium",
        "allowed_args": {"service": ["nginx", "redis", "mysql"]},
        "side_effect": True,
        "requires_shadow_execution": True,
        "requires_human_confirm": True,
    },
}

FORBIDDEN_PATTERNS = [";", "&&", "|", "`", "$(", "../", "/etc/shadow", "/root", "id_rsa"]


class ToolContractError(ValueError):
    pass


def validate_tool_call(tool_name: str, args: dict) -> None:
    contract = TOOL_CONTRACTS.get(tool_name)
    if contract is None:
        raise ToolContractError(f"未注册工具：{tool_name}")

    flat_values = " ".join(str(value) for value in args.values())
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in flat_values:
            raise ToolContractError(f"参数包含禁止模式：{pattern}")

    if tool_name == "systemctl_status":
        service = str(args.get("service", "")).replace(".service", "")
        if service not in contract["allowed_args"]["service"]:
            raise ToolContractError(f"服务不在允许列表：{service}")

    if tool_name == "journalctl_unit":
        unit = str(args.get("unit", "")).replace(".service", "")
        if unit not in contract["allowed_args"]["unit"]:
            raise ToolContractError(f"日志单元不在允许列表：{unit}")
        lines = int(args.get("lines", 80))
        if lines < 1 or lines > contract["allowed_args"]["max_lines"]:
            raise ToolContractError("日志行数超出允许范围")

    if tool_name in {"ss_listen", "netstat_listen", "lsof_port"}:
        port = int(args.get("port", 0))
        if port < contract["allowed_args"]["port_min"] or port > contract["allowed_args"]["port_max"]:
            raise ToolContractError(f"端口超出范围：{port}")

    if tool_name == "ps_process":
        pid = int(args.get("pid", 0))
        if pid < contract["allowed_args"]["pid_min"]:
            raise ToolContractError(f"PID 不合法：{pid}")

    if tool_name == "restart_service":
        service = str(args.get("service", "")).replace(".service", "")
        if service not in contract["allowed_args"]["service"]:
            raise ToolContractError(f"服务不允许自动重启：{service}")
