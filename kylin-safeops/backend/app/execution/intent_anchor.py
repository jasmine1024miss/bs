from backend.app.execution.tool_contract import TOOL_CONTRACTS


def check_intent_anchor(plan: dict, step: dict, args: dict) -> dict:
    tool = step.get("tool", "")
    if tool not in TOOL_CONTRACTS:
        return _blocked("unregistered_tool", f"工具 {tool} 未注册")

    services = set(plan.get("scope", {}).get("services", []))
    ports = set(plan.get("scope", {}).get("ports", []))
    logs = set(plan.get("scope", {}).get("logs", []))

    if "service" in args:
        service = str(args["service"]).replace(".service", "")
        if service not in services:
            return _blocked("service_scope_drift", f"服务 {service} 不在当前 PlanSpec 范围内")

    if "unit" in args:
        unit = str(args["unit"])
        normalized = unit if unit.endswith(".service") else f"{unit}.service"
        if normalized not in logs:
            return _blocked("log_scope_drift", f"日志单元 {normalized} 不在当前 PlanSpec 范围内")

    if "port" in args:
        port = int(args["port"])
        if port not in ports:
            return _blocked("port_scope_drift", f"端口 {port} 不在当前 PlanSpec 范围内")

    return {"decision": "pass", "type": "intent_anchor", "reason": "动作符合当前 PlanSpec 目标范围"}


def _blocked(kind: str, reason: str) -> dict:
    return {"decision": "blocked", "type": kind, "reason": reason}

