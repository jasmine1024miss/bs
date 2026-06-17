from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.execution.environment import probe_environment
from backend.app.runtime.models import RuntimeAlert, RuntimeEvidence
from backend.app.tools.runner import run_tool

_EVENT_STATE: dict[str, dict[str, Any]] = {}
_EVENT_CACHE: list[dict[str, Any]] = []
_LAST_SCAN_AT: str | None = None
_NEXT_SCAN_AT: str | None = None
_SCAN_COUNT = 0
_SCAN_TRIGGER = "bootstrap"
_SCHEDULER_TASK: asyncio.Task | None = None
_SCHEDULER_STARTED_AT: str | None = None
_SCHEDULER_LAST_ERROR: str | None = None
_SCHEDULER_INTERVAL_SECONDS = 15


def list_runtime_alerts() -> dict:
    if _LAST_SCAN_AT is None:
        run_runtime_scan(trigger="lazy_bootstrap")
    events = list(_EVENT_CACHE)
    return {
        "runtime": runtime_status(events),
        "items": events,
        "total": len(events),
    }


def run_runtime_scan(trigger: str = "manual") -> list[dict]:
    global _EVENT_CACHE, _LAST_SCAN_AT, _NEXT_SCAN_AT, _SCAN_COUNT, _SCAN_TRIGGER

    env = probe_environment()
    now = _now()
    _LAST_SCAN_AT = now
    _NEXT_SCAN_AT = _iso_after(_SCHEDULER_INTERVAL_SECONDS)
    _SCAN_COUNT += 1
    _SCAN_TRIGGER = trigger

    if env.get("effective_mode") == "real" and env.get("real_mode_ready"):
        observations = _real_events(now, env)
    else:
        observations = _demo_events(now, env)

    _EVENT_CACHE = _merge_event_state(observations, now)
    return list(_EVENT_CACHE)


def runtime_status(events: list[dict] | None = None) -> dict:
    env = probe_environment()
    active_events = events if events is not None else list(_EVENT_CACHE)
    pending_events = [item for item in active_events if item.get("status") not in {"resolved", "deferred"}]
    return {
        "agent_state": "online",
        "scan_state": "running" if scheduler_is_running() else "standby",
        "scheduler_state": "running" if scheduler_is_running() else "standby",
        "scheduler_started_at": _SCHEDULER_STARTED_AT,
        "scheduler_last_error": _SCHEDULER_LAST_ERROR,
        "scan_strategy": "background_scheduler",
        "event_model_version": "A1-runtime-alert-v1",
        "effective_mode": env.get("effective_mode", "demo"),
        "adapter": env.get("adapter", "demo"),
        "last_scan_at": _LAST_SCAN_AT or _now(),
        "next_scan_at": _NEXT_SCAN_AT,
        "last_scan_trigger": _SCAN_TRIGGER,
        "scan_interval_seconds": _SCHEDULER_INTERVAL_SECONDS,
        "scan_count": _SCAN_COUNT,
        "new_count": sum(1 for item in active_events if item.get("status") == "new"),
        "medium_or_high_count": sum(1 for item in pending_events if item.get("risk_level") in {"medium", "high"}),
        "message": "后台自动巡检已启用：读取类检测自动执行，高影响处置需人工确认。",
    }


def update_alert_status(event_id: str, status: str, linked_audit_id: str | None = None) -> dict:
    state = _EVENT_STATE.setdefault(event_id, {})
    state["status"] = status
    state["handled_at"] = _now()
    if linked_audit_id:
        state["linked_audit_id"] = linked_audit_id

    event = None
    for item in _EVENT_CACHE:
        if item.get("event_id") == event_id:
            item["status"] = status
            item["handled_at"] = state["handled_at"]
            if linked_audit_id:
                item["linked_audit_id"] = linked_audit_id
            event = item
            break

    return {
        "ok": event is not None,
        "event": event,
        "runtime": runtime_status(list(_EVENT_CACHE)),
    }


def source_from_alert(event: dict) -> dict:
    return {
        "kind": "runtime_alert",
        "event_id": event.get("event_id"),
        "label": f"自动巡检事件：{event.get('title')}",
        "target": event.get("target") or event.get("title") or "自动巡检诊断",
        "port": event.get("port") or 80,
        "service": event.get("service") or "nginx",
        "process": event.get("process") or event.get("service") or "nginx",
        "bind": event.get("bind") or "0.0.0.0",
        "risk": event.get("risk_level") or "medium",
        "reason": event.get("summary") or "由自动巡检事件触发受控诊断",
        "alert_source": event.get("source"),
        "detected_at": event.get("detected_at"),
    }


def scheduler_is_running() -> bool:
    return _SCHEDULER_TASK is not None and not _SCHEDULER_TASK.done()


def start_runtime_scheduler(interval_seconds: int = 15) -> dict:
    global _SCHEDULER_TASK, _SCHEDULER_STARTED_AT, _SCHEDULER_INTERVAL_SECONDS

    _SCHEDULER_INTERVAL_SECONDS = max(5, int(interval_seconds))
    if scheduler_is_running():
        return runtime_status()

    _SCHEDULER_STARTED_AT = _now()
    _SCHEDULER_TASK = asyncio.create_task(_scheduler_loop(), name="safeops-runtime-scheduler")
    return runtime_status()


async def stop_runtime_scheduler() -> None:
    global _SCHEDULER_TASK

    task = _SCHEDULER_TASK
    _SCHEDULER_TASK = None
    if task is None or task.done():
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def _scheduler_loop() -> None:
    global _SCHEDULER_LAST_ERROR

    while True:
        try:
            run_runtime_scan(trigger="scheduler")
            _SCHEDULER_LAST_ERROR = None
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            _SCHEDULER_LAST_ERROR = str(exc)
        await asyncio.sleep(_SCHEDULER_INTERVAL_SECONDS)


def _merge_event_state(events: list[RuntimeAlert], now: str) -> list[dict]:
    merged: list[dict] = []
    seen_ids: set[str] = set()

    for event in events:
        data = event.to_dict()
        event_id = data["event_id"]
        seen_ids.add(event_id)
        state = _EVENT_STATE.setdefault(event_id, {
            "status": data["status"],
            "first_seen_at": data["detected_at"],
            "occurrence_count": 0,
        })
        state["occurrence_count"] = int(state.get("occurrence_count", 0)) + 1
        state["last_seen_at"] = now
        data["status"] = state.get("status", data["status"])
        data["first_seen_at"] = state.get("first_seen_at") or data["detected_at"]
        data["last_seen_at"] = now
        data["occurrence_count"] = state["occurrence_count"]
        data["linked_audit_id"] = state.get("linked_audit_id")
        data["handled_at"] = state.get("handled_at")
        merged.append(data)

    for event_id, state in _EVENT_STATE.items():
        if event_id in seen_ids or state.get("status") not in {"diagnosing", "diagnosed", "deferred"}:
            continue
        merged.append({
            "event_id": event_id,
            "source": "event_memory",
            "title": "历史巡检事件",
            "service": "unknown",
            "port": None,
            "process": "unknown",
            "bind": "unknown",
            "risk_level": "low",
            "status": state.get("status", "resolved"),
            "detected_at": state.get("first_seen_at") or now,
            "first_seen_at": state.get("first_seen_at") or now,
            "last_seen_at": state.get("last_seen_at") or now,
            "occurrence_count": state.get("occurrence_count", 1),
            "summary": "该事件已不在当前巡检结果中，仅保留审计追踪状态。",
            "evidence_hint": "event memory",
            "target": "历史事件追踪",
            "mode": "memory",
            "adapter": "safeops-runtime",
            "category": "memory",
            "suggested_action": "打开审计记录复核历史处理过程。",
            "linked_audit_id": state.get("linked_audit_id"),
            "handled_at": state.get("handled_at"),
            "evidence": [],
            "plan_hint": "查看历史审计会话",
        })

    return merged


def _demo_events(now: str, env: dict) -> list[RuntimeAlert]:
    return [
        _event(
            event_id="evt_nginx_service_failed",
            source="service_scan",
            title="nginx 服务状态异常",
            risk_level="medium",
            service="nginx",
            port=80,
            process="httpd",
            bind="0.0.0.0",
            summary="后台巡检自动发现 nginx.service 处于失败状态，建议进入受控诊断。",
            evidence_hint="systemctl: failed；journalctl: Address already in use",
            detected_at=now,
            target="nginx.service 自动巡检诊断",
            env=env,
            category="service_health",
            evidence=[
                RuntimeEvidence("systemctl_status", "service_state", "nginx.service failed", 0.92),
                RuntimeEvidence("journalctl_unit", "log_signal", "Address already in use", 0.88),
            ],
        ),
        _event(
            event_id="evt_port_80_occupied",
            source="port_scan",
            title="80/TCP 监听归属需核验",
            risk_level="medium",
            service="nginx",
            port=80,
            process="httpd",
            bind="0.0.0.0",
            summary="后台巡检自动发现 80/TCP 当前由 httpd 占用，可能影响 nginx 启动。",
            evidence_hint="ss/netstat/lsof: 80/TCP -> PID 1234/httpd",
            detected_at=now,
            target="nginx 80/TCP 端口归属诊断",
            env=env,
            category="port_ownership",
            evidence=[
                RuntimeEvidence("ss_listen", "port_owner", "80/TCP -> PID 1234", 0.9),
                RuntimeEvidence("ps_process", "process_owner", "PID 1234 -> httpd", 0.87),
            ],
        ),
        _event(
            event_id="evt_admin_port_review",
            source="port_scan",
            title="管理端口暴露需复核",
            risk_level="high",
            service="docker-api",
            port=2375,
            process="dockerd",
            bind="0.0.0.0",
            summary="后台巡检发现管理类端口处于监听状态，建议复核访问控制策略。",
            evidence_hint="端口快照：2375/TCP 监听；处置动作需人工确认",
            detected_at=now,
            target="管理端口暴露复核",
            env=env,
            category="exposure_review",
            evidence=[
                RuntimeEvidence("ss_listen", "exposed_port", "2375/TCP LISTEN", 0.84),
            ],
        ),
    ]


def _real_events(now: str, env: dict) -> list[RuntimeAlert]:
    events: list[RuntimeAlert] = []

    service = run_tool("systemctl_status", {"service": "nginx"})
    if service.get("facts", {}).get("service_state") in {"failed", "inactive"} or not service.get("ok"):
        events.append(_event(
            event_id="evt_nginx_service_failed",
            source="service_scan",
            title="nginx 服务状态异常",
            risk_level="medium",
            service="nginx",
            port=80,
            process="nginx",
            bind="0.0.0.0",
            summary=service.get("summary") or "自动巡检发现 nginx 服务状态异常。",
            evidence_hint=_clip(service.get("raw") or service.get("summary") or ""),
            detected_at=now,
            target="nginx.service 自动巡检诊断",
            env=env,
            category="service_health",
            evidence=[
                RuntimeEvidence("systemctl_status", "service_state", str(service.get("summary") or "nginx state abnormal"), 0.86),
            ],
        ))

    port = run_tool("ss_listen", {"port": 80})
    facts = port.get("facts", {})
    if facts.get("pid") or facts.get("process"):
        events.append(_event(
            event_id="evt_port_80_occupied",
            source="port_scan",
            title="80/TCP 监听归属需核验",
            risk_level="medium",
            service="nginx",
            port=80,
            process=facts.get("process") or "unknown",
            bind=facts.get("bind") or "0.0.0.0",
            summary=port.get("summary") or "自动巡检发现 80/TCP 存在监听进程。",
            evidence_hint=_clip(port.get("raw") or port.get("summary") or ""),
            detected_at=now,
            target="nginx 80/TCP 端口归属诊断",
            env=env,
            category="port_ownership",
            evidence=[
                RuntimeEvidence("ss_listen", "port_owner", _clip(port.get("summary") or "80/TCP has listener"), 0.86),
            ],
        ))

    if not events:
        events.append(_event(
            event_id="evt_runtime_healthy",
            source="runtime_scan",
            title="核心巡检未发现中高风险异常",
            risk_level="low",
            service="system",
            port=None,
            process="safeops-agent",
            bind="localhost",
            summary="自动巡检完成，当前核心服务和端口未出现需要立即诊断的事件。",
            evidence_hint="systemctl/ss 读取类巡检完成",
            detected_at=now,
            target="系统巡检摘要",
            env=env,
            status="resolved",
            category="health_summary",
            evidence=[
                RuntimeEvidence("runtime_scan", "summary", "core checks completed", 0.8),
            ],
        ))

    return events


def _event(
    *,
    event_id: str,
    source: str,
    title: str,
    risk_level: str,
    service: str,
    port: int | None,
    process: str,
    bind: str,
    summary: str,
    evidence_hint: str,
    detected_at: str,
    target: str,
    env: dict,
    status: str = "new",
    category: str = "runtime",
    evidence: list[RuntimeEvidence] | None = None,
) -> RuntimeAlert:
    return RuntimeAlert(
        event_id=event_id,
        source=source,
        title=title,
        service=service,
        port=port,
        process=process,
        bind=bind,
        risk_level=risk_level,
        status=status,
        detected_at=detected_at,
        summary=summary,
        evidence_hint=evidence_hint,
        target=target,
        mode=env.get("effective_mode", "demo"),
        adapter=env.get("adapter", "demo"),
        category=category,
        suggested_action=_suggested_action(risk_level),
        evidence=evidence or [],
        first_seen_at=detected_at,
        last_seen_at=detected_at,
    )


def _suggested_action(risk_level: str) -> str:
    if risk_level == "high":
        return "打开详情并生成处置计划，高影响动作需人工确认。"
    if risk_level == "medium":
        return "建议进入受控诊断，生成证据链和审计记录。"
    return "记录事件并等待下一轮巡检。"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _iso_after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _clip(text: str, limit: int = 160) -> str:
    single_line = " ".join(str(text).split())
    if len(single_line) <= limit:
        return single_line
    return single_line[:limit] + "..."
