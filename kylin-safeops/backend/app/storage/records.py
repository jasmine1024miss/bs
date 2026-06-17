import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4

DATA_ROOT = Path("data")
AUDIT_DIR = DATA_ROOT / "audit"
REPLAY_DIR = DATA_ROOT / "replay"


def persist_diagnosis_record(record: dict) -> dict:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    REPLAY_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    record_id = f"ops_{now}_{uuid4().hex[:8]}"
    audit_id = f"audit_{record_id}"
    replay_id = f"replay_{record_id}"

    audit = _build_audit(audit_id, replay_id, record)
    replay = _build_replay(replay_id, record)

    (AUDIT_DIR / f"{audit_id}.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    (REPLAY_DIR / f"{replay_id}.json").write_text(json.dumps(replay, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "diagnosis_id": record_id,
        "audit_id": audit_id,
        "replay_id": replay_id,
        "audit_export_url": f"/api/audit/{audit_id}/export",
    }


def load_audit(audit_id: str) -> dict | None:
    path = AUDIT_DIR / f"{audit_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_replay(replay_id: str) -> dict | None:
    path = REPLAY_DIR / f"{replay_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_audits(limit: int = 30) -> dict:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(AUDIT_DIR.glob("audit_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    items = []
    for path in files[: max(1, min(limit, 100))]:
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        items.append({
            "audit": audit,
            "session": _audit_session_summary(audit),
        })
    return {"items": items, "total": len(files)}


def export_audit_markdown(audit_id: str) -> str | None:
    audit = load_audit(audit_id)
    if audit is None:
        return None

    plan = audit.get("plan", {})
    root_cause = audit.get("root_cause", {})
    knowledge_state = audit.get("knowledge_state", {})
    graph = audit.get("evidence_graph", {})
    environment = audit.get("environment", {})
    evidence_summary = audit.get("evidence_summary", {})
    diagnosis_source = audit.get("diagnosis_source") or {}
    alert_event = audit.get("alert_event") or {}
    requirement_coverage = audit.get("requirement_coverage") or _requirement_coverage(audit)
    requirement_score = _coverage_score(requirement_coverage)

    lines = [
        f"# KylinSafeOps 审计报告 {audit_id}",
        "",
        "## 基本信息",
        f"- 生成时间：{audit.get('created_at')}",
        f"- 用户问题：{audit.get('query')}",
        f"- 识别意图：{plan.get('intent')}",
        f"- 目标：{plan.get('goal')}",
        f"- 诊断来源：{diagnosis_source.get('label', '自然语言请求')}",
        f"- 告警事件：{alert_event.get('event_id', '无')}",
        f"- 告警风险：{alert_event.get('risk', '无')}",
        f"- 诊断状态：{audit.get('status', 'completed')}",
        f"- 回放编号：{audit.get('replay_id', '')}",
        "",
        "## 执行环境",
        f"- 配置模式：{environment.get('configured_mode')}",
        f"- 实际模式：{environment.get('effective_mode')}",
        f"- 工具适配器：{environment.get('adapter')}",
        f"- 系统：{environment.get('system')} / {environment.get('machine')}",
        f"- 发行版：{environment.get('os_release', {}).get('name') or 'unknown'}",
        f"- Kylin/openKylin 识别：{environment.get('is_kylin_like')}",
        f"- 真实工具就绪：{environment.get('real_mode_ready')}",
        "",
        "## 赛题要求对齐",
        f"- 合规得分：{requirement_score}/100",
        f"- 当前阶段：{_display_mode(environment.get('effective_mode', 'demo'))}",
        f"- 说明：开发阶段允许使用 demo/auto 模式，最终提交需补充 Kylin/openKylin 实机截图与演示视频。",
        "",
        "| 要求项 | 状态 | 证据 |",
        "| --- | --- | --- |",
    ]

    for item in requirement_coverage:
        lines.append(
            f"| {item.get('label')} | {_coverage_status_label(item.get('status', 'pending'))} | {item.get('evidence')} |"
        )

    lines.extend([
        "",
        "## 根因结论",
        f"- 根因：{root_cause.get('summary')}",
        f"- 置信度：{root_cause.get('confidence')}",
        f"- 反事实验证：{root_cause.get('counterfactual')}",
        f"- 已验证证据数：{evidence_summary.get('verified_count', 0)}",
        f"- 工具调用数：{evidence_summary.get('tool_calls', 0)}",
        f"- 结论可追踪：{evidence_summary.get('all_conclusions_traceable', False)}",
        "",
        "## PlanSpec",
    ])

    for step in plan.get("steps", []):
        lines.append(
            f"- `{step.get('id')}` {step.get('tool')}：{step.get('reason')} "
            f"(risk={step.get('risk')})"
        )

    lines.extend(["", "## 已验证证据"])
    for item in knowledge_state.get("verified", []):
        lines.append(f"- {item.get('fact') or item.get('value') or item.get('summary')}")

    lines.extend(["", "## 候选根因"])
    for item in audit.get("hypotheses", []):
        score = item.get("score", 0)
        lines.append(f"- {item.get('name')}：{round(score * 100)}% / {item.get('state')}")

    lines.extend(["", "## 反事实证据图"])
    for node in graph.get("nodes", []):
        lines.append(f"- 节点 `{node.get('id')}`：{node.get('label')} ({node.get('type')})")
    for edge in graph.get("edges", []):
        lines.append(f"- 边：`{edge.get('source')}` -> `{edge.get('target')}` / {edge.get('type')}")

    lines.extend(["", "## 工具轨迹"])
    for item in audit.get("tool_trace", []):
        lines.append(
            f"- `{item.get('tool')}` / {item.get('mode')} / {item.get('adapter')} / "
            f"{item.get('duration_ms', 0)}ms / {item.get('summary')}"
        )
        if item.get("command"):
            lines.append(f"  - 命令：`{item.get('command')}`")
        if item.get("raw"):
            lines.append(f"  - 原始片段：`{_clip(str(item.get('raw'))).replace('`', '')}`")

    lines.extend(["", "## 认知审查", audit.get("critic", {}).get("conclusion", "")])
    return "\n".join(lines)


def _build_audit(audit_id: str, replay_id: str, record: dict) -> dict:
    return {
        "audit_id": audit_id,
        "replay_id": replay_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": record.get("status", "completed"),
        "query": record["plan"].get("user_query"),
        "environment": record.get("environment", {}),
        "plan": record["plan"],
        "knowledge_state": record["knowledge_state"],
        "hypotheses": record["hypotheses"],
        "tool_trace": record["tool_trace"],
        "evidence_graph": record["evidence_graph"],
        "root_cause": record["root_cause"],
        "critic": record.get("critic", {}),
        "evidence_summary": record.get("evidence_summary", {}),
        "diagnosis_source": record.get("diagnosis_source"),
        "alert_event": record.get("alert_event"),
        "requirement_coverage": record.get("requirement_coverage") or _requirement_coverage(record),
        "session_type": record.get("session_type", "诊断"),
        "session_target": record.get("session_target", record["plan"].get("goal")),
        "session_risk": record.get("session_risk"),
    }


def _audit_session_summary(audit: dict) -> dict:
    plan = audit.get("plan", {})
    root = audit.get("root_cause", {})
    evidence = audit.get("evidence_summary", {})
    source = audit.get("diagnosis_source") or {}
    traces = audit.get("tool_trace", [])
    confidence = float(root.get("confidence") or 0)
    duration_ms = sum(float(item.get("duration_ms") or 0) for item in traces)
    risk = audit.get("session_risk") or ("medium" if confidence >= 0.75 else "low")
    status = audit.get("status", "completed")
    session_type = audit.get("session_type", "诊断")
    return {
        "id": audit.get("audit_id", ""),
        "time": _format_time(audit.get("created_at", "")),
        "user": "管理员",
        "target": audit.get("session_target") or plan.get("goal") or audit.get("query") or "系统诊断",
        "type": session_type,
        "risk": risk,
        "status": "已完成" if status == "completed" else "已阻断",
        "duration": _format_duration(duration_ms),
        "description": source.get("label") or audit.get("query") or root.get("summary") or "受控诊断会话",
        "riskScore": max(32, min(92, round(confidence * 100) if confidence else 45)),
        "verifiedCount": evidence.get("verified_count", 0),
        "toolCalls": evidence.get("tool_calls", len(traces)),
    }


def _build_replay(replay_id: str, record: dict) -> dict:
    events = [
        {"type": "plan_created", "title": "生成 PlanSpec", "payload": record["plan"]},
        {"type": "knowledge_initialized", "title": "初始化 Knowledge State", "payload": record["knowledge_state"]},
    ]
    for item in record["tool_trace"]:
        events.append({"type": "tool_called", "title": f"调用 {item.get('tool')}", "payload": item})
    events.extend(
        [
            {"type": "hypothesis_updated", "title": "候选根因评分更新", "payload": record["hypotheses"]},
            {"type": "graph_built", "title": "构建反事实证据图", "payload": record["evidence_graph"]},
            {"type": "root_cause_verified", "title": "输出根因结论", "payload": record["root_cause"]},
        ]
    )
    return {
        "replay_id": replay_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "events": events,
    }


def _clip(text: str, limit: int = 220) -> str:
    single_line = " ".join(text.split())
    if len(single_line) <= limit:
        return single_line
    return single_line[:limit] + "..."


def _requirement_coverage(record: dict) -> list[dict]:
    environment = record.get("environment", {})
    plan = record.get("plan", {})
    traces = record.get("tool_trace", [])
    evidence_summary = record.get("evidence_summary", {})
    tools = environment.get("tools", {})
    trace_tools = {item.get("tool") for item in traces}
    has_network_context = bool({"ss_listen", "netstat_listen", "lsof_port"} & trace_tools)
    all_traceable = bool(evidence_summary.get("all_conclusions_traceable"))

    return [
        {
            "label": "OS 环境深度感知",
            "status": "done" if environment.get("system") else "partial",
            "evidence": f"{environment.get('system', 'unknown')} / adapter={environment.get('adapter', 'unknown')}",
        },
        {
            "label": "MCP/Tools 插件化封装",
            "status": "done" if trace_tools else "partial",
            "evidence": "、".join(sorted(tool for tool in trace_tools if tool)) or "等待工具调用",
        },
        {
            "label": "日志、网络、进程上下文",
            "status": "done" if has_network_context and "journalctl_unit" in trace_tools and "ps_process" in trace_tools else "partial",
            "evidence": "journalctl + ss/netstat/lsof + ps 已纳入诊断链路",
        },
        {
            "label": "安全意图校验",
            "status": "done" if plan.get("intent") and plan.get("steps") else "partial",
            "evidence": f"intent={plan.get('intent', 'unknown')}，steps={len(plan.get('steps', []))}",
        },
        {
            "label": "最小权限执行",
            "status": "done" if all(item.get("mode") in {"demo", "readonly"} for item in traces) else "partial",
            "evidence": "当前诊断链路仅调用只读/演示工具，高影响动作需人工确认",
        },
        {
            "label": "推理链路溯源",
            "status": "done" if all_traceable else "partial",
            "evidence": f"工具调用 {len(traces)} 次，已验证证据 {evidence_summary.get('verified_count', 0)} 条",
        },
        {
            "label": "确定性交互与根因分析",
            "status": "done" if record.get("root_cause") and record.get("evidence_graph") else "partial",
            "evidence": "PlanSpec -> Tool Trace -> Evidence Graph -> Root Cause",
        },
        {
            "label": "Kylin/openKylin 实机证明",
            "status": "done" if environment.get("is_kylin_like") else "pending",
            "evidence": "已识别麒麟环境" if environment.get("is_kylin_like") else "最后阶段补真实环境截图和录屏",
        },
        {
            "label": "系统工具可用性",
            "status": "done" if environment.get("real_mode_ready") else "partial",
            "evidence": _tool_status_summary(tools),
        },
    ]


def _coverage_score(items: list[dict]) -> int:
    score = 0.0
    for item in items:
        status = item.get("status")
        if status == "done":
            score += 1
        elif status == "partial":
            score += 0.5
    if not items:
        return 0
    return round(score / len(items) * 100)


def _coverage_status_label(status: str) -> str:
    if status == "done":
        return "已完成"
    if status == "partial":
        return "可演示"
    return "待验证"


def _display_mode(value: str) -> str:
    if value == "demo":
        return "演示模式"
    if value == "real":
        return "真实模式"
    if value == "auto":
        return "自动模式"
    return value or "未知"


def _tool_status_summary(tools: dict) -> str:
    if not tools:
        return "等待环境探针"
    ready = [name for name, ok in tools.items() if ok]
    missing = [name for name, ok in tools.items() if not ok]
    return f"已就绪：{', '.join(ready) or '无'}；待验证：{', '.join(missing) or '无'}"


def _format_time(value: str) -> str:
    if not value:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value[:19].replace("T", " ")


def _format_duration(duration_ms: float) -> str:
    seconds = max(1, int(round(duration_ms / 1000)))
    minutes, rest = divmod(seconds, 60)
    return f"{minutes}:{rest:02d} 秒"
