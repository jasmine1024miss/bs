from backend.app.cognition.knowledge_state import build_initial_knowledge_state
from backend.app.execution.environment import probe_environment
from backend.app.execution.planspec import build_nginx_failure_plan
from backend.app.execution.intent_anchor import check_intent_anchor
from backend.app.llm.provider import critique_diagnosis
from backend.app.storage.records import persist_diagnosis_record
from backend.app.tools.runner import run_tool


def diagnose_nginx_failure(query: str, source: dict | None = None) -> dict:
    environment = probe_environment()
    plan = build_nginx_failure_plan(query)
    source_meta = _normalize_diagnosis_source(source)
    if source_meta:
        plan["source"] = source_meta
    traces = []
    facts: dict = {}

    for step in plan["steps"]:
        args = dict(step["args"])
        if step["tool"] == "ps_process":
            pid = facts.get("pid")
            if not pid:
                traces.append({
                    "tool": step["tool"],
                    "args": args,
                    "ok": False,
                    "summary": "缺少端口占用 PID，跳过进程归属验证",
                    "mode": "skip",
                    "adapter": environment["adapter"],
                    "facts": {},
                    "duration_ms": 0,
                })
                continue
            args["pid"] = pid

        anchor = check_intent_anchor(plan, step, args)
        if anchor["decision"] != "pass":
            traces.append({
                "tool": step["tool"],
                "args": args,
                "ok": False,
                "mode": "blocked",
                "adapter": environment["adapter"],
                "summary": anchor["reason"],
                "intent_anchor": anchor,
                "facts": {},
                "duration_ms": 0,
            })
            continue

        result = run_tool(step["tool"], args)
        result["intent_anchor"] = anchor
        traces.append(result)
        facts.update({key: value for key, value in result.get("facts", {}).items() if value is not None})

    knowledge = _build_verified_knowledge(facts, source_meta)
    hypotheses = _score_hypotheses(facts)
    graph = _build_evidence_graph(facts, source_meta)
    root_cause = _root_cause(hypotheses)
    critic = critique_diagnosis(knowledge, hypotheses, traces)

    response = {
        "answer": root_cause["summary"],
        "status": "completed",
        "environment": environment,
        "plan": plan,
        "knowledge_state": knowledge,
        "hypotheses": hypotheses,
        "tool_trace": traces,
        "evidence_graph": graph,
        "root_cause": root_cause,
        "critic": critic,
        "evidence_summary": _evidence_summary(knowledge, traces),
    }
    if source_meta:
        response["diagnosis_source"] = source_meta
        response["session_type"] = "自动巡检诊断" if source_meta.get("kind") == "runtime_alert" else "攻击面联动诊断"
        response["session_target"] = source_meta.get("target") or f"{source_meta.get('service', 'nginx')} {source_meta.get('port', 80)}/TCP 联动诊断"
        response["session_risk"] = source_meta.get("risk") or "medium"
        if source_meta.get("kind") == "runtime_alert":
            response["alert_event"] = {
                "event_id": source_meta.get("event_id"),
                "source": source_meta.get("alert_source"),
                "detected_at": source_meta.get("detected_at"),
                "risk": source_meta.get("risk"),
                "label": source_meta.get("label"),
            }
    response.update(persist_diagnosis_record(response))
    response["diagnosis_contract"] = _diagnosis_contract(response)
    return response


def _normalize_diagnosis_source(source: dict | None) -> dict | None:
    if not source:
        return None
    port = int(source.get("port") or 80)
    service = source.get("service") or source.get("process") or "nginx"
    process = source.get("process") or service
    if source.get("kind") == "runtime_alert":
        return {
            "kind": "runtime_alert",
            "event_id": source.get("event_id"),
            "label": source.get("label") or f"自动巡检事件 {service}:{port}",
            "target": source.get("target") or f"{service} {port}/TCP 自动巡检诊断",
            "port": port,
            "service": service,
            "process": process,
            "bind": source.get("bind") or "0.0.0.0",
            "risk": source.get("risk") or "medium",
            "reason": source.get("reason") or "由自动巡检事件触发受控诊断",
            "alert_source": source.get("alert_source") or source.get("source"),
            "detected_at": source.get("detected_at"),
        }
    if source.get("kind") != "attack_surface_port":
        return None
    return {
        "kind": "attack_surface_port",
        "label": source.get("label") or f"攻击面地图节点 {service}:{port}",
        "target": source.get("target") or f"{service} {port}/TCP 端口风险诊断",
        "port": port,
        "service": service,
        "process": process,
        "bind": source.get("bind") or "0.0.0.0",
        "risk": source.get("risk") or "medium",
        "reason": source.get("reason") or "从攻击面地图节点发起联动诊断",
    }


def _build_verified_knowledge(facts: dict, source_meta: dict | None = None) -> dict:
    state = build_initial_knowledge_state()
    resolved = set()
    if source_meta:
        source_label = source_meta["label"]
        source_name = "runtime_alert" if source_meta.get("kind") == "runtime_alert" else "attack_surface_map"
        state["known"].append({
            "key": "diagnosis_source",
            "value": f"{source_label} 已触发受控诊断",
            "source": source_name,
        })
    if facts.get("service_state"):
        state["known"].append({"key": "service_state", "value": f"nginx {facts['service_state']}", "source": "systemctl"})
        resolved.add("service_state")
    if facts.get("error") == "address_in_use":
        state["verified"].append({"fact": "日志出现 Address already in use", "source": "journalctl"})
        resolved.add("error_log")
    if facts.get("pid"):
        state["verified"].append({"fact": f"80 端口被 PID {facts['pid']} 占用", "source": facts.get("network_source", "ss")})
        resolved.add("port_owner")
    if facts.get("netstat_confirmed"):
        state["verified"].append({"fact": "netstat 确认 80 端口处于 LISTEN 状态", "source": "netstat"})
        resolved.add("network_context")
    if facts.get("lsof_confirmed"):
        owner = facts.get("user") or "unknown"
        state["verified"].append({"fact": f"lsof 确认端口归属用户：{owner}", "source": "lsof"})
        resolved.add("lsof_process_context")
    if facts.get("process"):
        state["verified"].append({"fact": f"占用进程是 {facts['process']}", "source": "ps"})
        resolved.add("process_owner")
    state["unknown"] = [item for item in state["unknown"] if item["key"] not in resolved]
    return state


def _score_hypotheses(facts: dict) -> list[dict]:
    port_score = 0.33
    if facts.get("error") == "address_in_use":
        port_score += 0.27
    if facts.get("pid"):
        port_score += 0.20
    if facts.get("netstat_confirmed"):
        port_score += 0.04
    if facts.get("lsof_confirmed"):
        port_score += 0.04
    if facts.get("process"):
        port_score += 0.11
    port_score = min(port_score, 0.95)

    remaining = max(0.0, 1.0 - port_score)
    return [
        {"name": "port_conflict", "score": round(port_score, 2), "state": "verified" if port_score >= 0.85 else "assumed"},
        {"name": "config_error", "score": round(remaining * 0.6, 2), "state": "assumed"},
        {"name": "permission_denied", "score": round(remaining * 0.4, 2), "state": "assumed"},
    ]


def _build_evidence_graph(facts: dict, source_meta: dict | None = None) -> dict:
    nodes = [{"id": "symptom_nginx_failed", "label": "nginx 启动失败", "type": "symptom"}]
    edges: list[dict] = []

    if source_meta:
        source_node_id = "source_runtime_alert" if source_meta.get("kind") == "runtime_alert" else "source_attack_surface"
        nodes.append({
            "id": source_node_id,
            "label": f"来源：{source_meta['label']}",
            "type": "source",
        })
        edges.append({"source": source_node_id, "target": "symptom_nginx_failed", "type": "triggers"})

    if facts.get("service_state"):
        nodes.append({"id": "ev_service_state", "label": f"服务状态：{facts['service_state']}", "type": "verified"})
        edges.append({"source": "ev_service_state", "target": "symptom_nginx_failed", "type": "observes"})

    if facts.get("error") == "address_in_use":
        nodes.append({"id": "ev_log_address", "label": "日志现象：地址已被占用", "type": "verified"})
        edges.append({"source": "ev_log_address", "target": "symptom_nginx_failed", "type": "supports"})

    if facts.get("pid"):
        nodes.append({"id": "ev_port_80", "label": f"端口状态：80 被 PID {facts['pid']} 占用", "type": "verified"})
        target = "ev_log_address" if facts.get("error") == "address_in_use" else "symptom_nginx_failed"
        edges.append({"source": "ev_port_80", "target": target, "type": "explains"})

    if facts.get("netstat_confirmed"):
        nodes.append({"id": "ev_netstat", "label": "netstat：80/TCP LISTEN", "type": "verified"})
        if facts.get("pid"):
            edges.append({"source": "ev_netstat", "target": "ev_port_80", "type": "corroborates"})

    if facts.get("lsof_confirmed"):
        owner = facts.get("user") or "unknown"
        nodes.append({"id": "ev_lsof", "label": f"lsof：端口进程用户 {owner}", "type": "verified"})
        if facts.get("pid"):
            edges.append({"source": "ev_lsof", "target": "ev_port_80", "type": "corroborates"})

    if facts.get("process"):
        nodes.append({"id": "ev_process", "label": f"进程归属：{facts['process']}", "type": "verified"})
        if facts.get("pid"):
            edges.append({"source": "ev_process", "target": "ev_port_80", "type": "owns"})

    if facts.get("error") == "address_in_use" and facts.get("pid"):
        nodes.append({"id": "root_port_conflict", "label": "根因：端口占用冲突", "type": "root_cause"})
        edges.append({"source": "ev_port_80", "target": "root_port_conflict", "type": "verifies"})

        process = facts.get("process") or "占用进程"
        nodes.extend([
            {"id": "action_review_owner", "label": f"建议：确认 {process} 是否应占用 80 端口", "type": "recommendation"},
            {"id": "cf_release_80", "label": "反事实：释放 80 端口", "type": "counterfactual"},
            {"id": "cf_failure_disappears", "label": "结果推演：启动失败条件消失", "type": "counterfactual"},
        ])
        edges.extend([
            {"source": "root_port_conflict", "target": "action_review_owner", "type": "recommends"},
            {"source": "root_port_conflict", "target": "cf_release_80", "type": "counterfactual_if"},
            {"source": "cf_release_80", "target": "cf_failure_disappears", "type": "would_change"},
        ])

    return {"nodes": nodes, "edges": edges}


def _root_cause(hypotheses: list[dict]) -> dict:
    winner = max(hypotheses, key=lambda item: item["score"])
    if winner["name"] == "port_conflict" and winner["state"] == "verified":
        return {
            "name": "port_conflict",
            "summary": "已验证根因：端口冲突导致 nginx 启动失败。",
            "confidence": winner["score"],
            "counterfactual": "若释放 80 端口，nginx 的 bind 失败条件将消失。",
        }
    return {
        "name": winner["name"],
        "summary": "当前证据不足，只能给出候选根因，需要继续取证。",
        "confidence": winner["score"],
        "counterfactual": "",
    }


def _evidence_summary(knowledge_state: dict, traces: list[dict]) -> dict:
    verified = knowledge_state.get("verified", [])
    succeeded = [item for item in traces if item.get("ok")]
    blocked = [item for item in traces if item.get("mode") in {"blocked", "policy"}]
    return {
        "verified_count": len(verified),
        "tool_calls": len(traces),
        "successful_tool_calls": len(succeeded),
        "blocked_tool_calls": len(blocked),
        "all_conclusions_traceable": bool(verified) and len(succeeded) >= 3,
    }


def _diagnosis_contract(response: dict) -> dict:
    checks = {
        "planspec": bool(response.get("plan", {}).get("steps")),
        "tool_trace": bool(response.get("tool_trace")),
        "evidence_graph": bool(response.get("evidence_graph", {}).get("nodes")),
        "root_cause": bool(response.get("root_cause", {}).get("summary")),
        "audit_id": bool(response.get("audit_id")),
    }
    return {
        "complete": all(checks.values()),
        "checks": checks,
        "required_outputs": ["PlanSpec", "工具轨迹", "证据图谱", "根因结论", "审计ID"],
        "missing_outputs": [key for key, ok in checks.items() if not ok],
    }
